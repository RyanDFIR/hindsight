# -*- coding: utf-8 -*-
import copy
import datetime
import json
import logging
import os
import re
import sqlite3
import struct
import urllib.parse

from pyhindsight import utils
from pyhindsight.browsers.webbrowser import WebBrowser

log = logging.getLogger(__name__)


# moz_historyvisits.visit_type values from PlacesUtils:
# https://searchfox.org/mozilla-central/source/toolkit/components/places/nsINavHistoryService.idl
FIREFOX_VISIT_TYPES = {
    1: 'Link',
    2: 'Typed',
    3: 'Bookmark',
    4: 'Embed',
    5: 'Redirect (permanent)',
    6: 'Redirect (temporary)',
    7: 'Download',
    8: 'Framed Link',
    9: 'Reload',
}

# moz_bookmarks.type values
BOOKMARK_TYPE_URL = 1
BOOKMARK_TYPE_FOLDER = 2
BOOKMARK_TYPE_SEPARATOR = 3

# cache2 entry layout (see CacheFileMetadata.h in mozilla-central). Body is
# divided into 256 KiB chunks with a uint16 hash per chunk written between
# the body and the metadata block; the file ends with a uint32 offset to the
# start of the metadata block.
CACHE2_CHUNK_SIZE = 256 * 1024
CACHE2_HASH_SIZE = 2
CACHE2_MIN_ENTRY_SIZE = 41  # 4 hash + 32 header + 1 key + null + 4 offset

# Firefox cache keys look like `O^partitionKey=%28...%29,:https://www.example.com/...`;
# the URL is the trailing scheme://... segment.
_CACHE2_URL_RE = re.compile(rb'(https?://[^\x00]+)$')

# Matches `user_pref("key", value);` lines in prefs.js.
_PREFS_LINE_RE = re.compile(
    r'^user_pref\(\s*"([^"]+)"\s*,\s*(.*?)\s*\)\s*;\s*$'
)

# Forensically interesting Firefox preferences, grouped for the XLSX sheet.
INTERESTING_PREFS = [
    ('Identity & Account', [
        ('services.sync.username', 'Firefox Account email (logged-in user)'),
        ('services.sync.lastSync', 'Last Firefox Sync time (unix seconds)'),
        ('services.sync.numClients', 'Number of devices linked to this account'),
        ('identity.fxaccounts.lastSignedInUserHash', 'Hashed identity of last FxA user'),
    ]),
    ('Startup & Homepage', [
        ('browser.startup.homepage', 'Configured homepage URL(s)'),
        ('browser.startup.page', 'What to show on startup (1=homepage, 3=last session)'),
        ('browser.newtabpage.enabled', 'New tab page enabled'),
        ('browser.startup.lastColdStartupCheck', 'Last cold-start check (unix seconds)'),
        ('app.installation.timestamp', 'Firefox installation timestamp (PRTime)'),
    ]),
    ('Downloads', [
        ('browser.download.lastDir', 'Last directory used to save a download'),
        ('browser.download.dir', 'Configured default download directory'),
        ('browser.download.folderList',
         'Default download folder type (0=Desktop, 1=Downloads, 2=custom)'),
        ('browser.download.useDownloadDir', 'Skip the Save As prompt'),
        ('browser.download.alwaysOpenPanel', 'Always open the downloads panel'),
    ]),
    ('Network & Proxy', [
        ('network.proxy.type',
         'Proxy mode (0=none, 1=manual, 2=PAC, 4=auto-detect, 5=system)'),
        ('network.proxy.http', 'Manual HTTP proxy host'),
        ('network.proxy.http_port', 'Manual HTTP proxy port'),
        ('network.proxy.ssl', 'Manual HTTPS proxy host'),
        ('network.proxy.socks', 'Manual SOCKS proxy host'),
        ('network.proxy.no_proxies_on', 'Domains bypassing the proxy'),
        ('network.proxy.autoconfig_url', 'PAC file URL'),
        ('network.trr.mode', 'DNS-over-HTTPS mode'),
        ('network.trr.uri', 'DNS-over-HTTPS resolver URL'),
    ]),
    ('Privacy & Tracking Protection', [
        ('privacy.donottrackheader.enabled', 'Send Do-Not-Track header'),
        ('privacy.globalprivacycontrol.enabled', 'Send Global Privacy Control'),
        ('privacy.trackingprotection.enabled', 'Enhanced Tracking Protection'),
        ('privacy.history.custom', 'Using custom history settings'),
        ('privacy.sanitize.sanitizeOnShutdown', 'Clear history on shutdown'),
        ('privacy.clearOnShutdown.history', 'Clear browsing history on shutdown'),
        ('privacy.clearOnShutdown.cookies', 'Clear cookies on shutdown'),
        ('privacy.clearOnShutdown.downloads', 'Clear download list on shutdown'),
        ('privacy.clearOnShutdown.formdata', 'Clear form data on shutdown'),
    ]),
    ('Search & Region', [
        ('browser.search.region', 'Country code used to pick default engines'),
        ('browser.search.suggest.enabled', 'Show search suggestions'),
        ('browser.urlbar.placeholderName', 'Active default search engine name'),
        ('browser.search.defaultenginename', 'Configured default search engine'),
        ('browser.search.lastModifiedTopic', 'Last search-config modification (PRTime)'),
        ('intl.accept_languages', 'Languages sent in HTTP Accept-Language'),
    ]),
    ('Passwords & Autofill', [
        ('signon.rememberSignons', 'Save logins and passwords for websites'),
        ('signon.management.page.breach-alerts.enabled', 'Show login breach alerts'),
        ('signon.autofillForms', 'Autofill saved usernames/passwords'),
        ('browser.formfill.enable', 'Save form entries'),
        ('extensions.formautofill.addresses.enabled', 'Save and fill addresses'),
        ('extensions.formautofill.creditCards.enabled', 'Save and fill credit cards'),
    ]),
    ('Telemetry & Updates', [
        ('app.update.auto', 'Apply updates automatically'),
        ('app.update.background.lastInstalledTaskVersion', 'Last background-update task version'),
        ('toolkit.telemetry.enabled', 'Send telemetry to Mozilla'),
        ('datareporting.healthreport.uploadEnabled', 'Send Health Report data'),
        ('toolkit.telemetry.lastUpdate', 'Last telemetry upload (unix seconds)'),
    ]),
    ('Containers & Profiles', [
        ('privacy.userContext.enabled', 'Container tabs enabled'),
        ('extensions.installedFromFXA', 'Add-ons installed via FxA'),
        ('browser.engagement.profileCount', 'Number of profiles on this install'),
    ]),
]


class Firefox(WebBrowser):
    def __init__(self, profile_path, browser_name=None, cache_path=None, version=None, timezone=None,
                 no_copy=None, temp_dir=None):
        WebBrowser.__init__(
            self, profile_path, browser_name=browser_name, cache_path=cache_path, version=version,
            timezone=timezone, no_copy=no_copy, temp_dir=temp_dir)
        self.profile_path = profile_path
        # Honor a variant passed by the caller (e.g. "Tor"); Tor Browser is
        # Firefox-based and currently shares this parser, differing only in variant.
        self.browser_name = browser_name or "Firefox"
        self.cache_path = cache_path
        self.timezone = timezone
        self.no_copy = no_copy
        self.temp_dir = temp_dir

        if self.version is None:
            self.version = []
        if self.structure is None:
            self.structure = {}

    def _open(self, path, database):
        conn = utils.open_sqlite_db(self, path, database)
        if not conn:
            self.artifacts_counts[database] = 'Failed'
            return None
        return conn

    @staticmethod
    def _visit_type_friendly(visit_type):
        if visit_type is None:
            return None
        return FIREFOX_VISIT_TYPES.get(visit_type, f'Unknown ({visit_type})')

    def determine_version(self, path, database='places.sqlite'):
        # places.sqlite tracks schema with PRAGMA user_version; Firefox 62+ is >= 52.
        conn = self._open(path, database)
        if not conn:
            return
        try:
            cursor = conn.cursor()
            cursor.execute('PRAGMA user_version')
            row = cursor.fetchone()
            if row:
                user_version = list(row.values())[0]
                if user_version:
                    self.version.append(user_version)
                    self.display_version = f'places schema v{user_version}'
                    log.info(f' - places.sqlite user_version: {user_version}')
        except Exception as e:
            log.warning(f' - Could not read places.sqlite user_version: {e}')
        finally:
            conn.close()

    def _execute_versioned_query(self, cursor, queries, artifact_name):
        """Execute the schema-appropriate query from a {min_schema_version: sql} dict.

        Mirrors the Chrome parser's approach: pick the query for the detected
        places schema version (``self.version``, from PRAGMA user_version), then
        fall back to lower-schema queries if the chosen one references a column
        the profile doesn't have yet (sqlite3.OperationalError). Returns True if
        a query executed (the cursor then holds the rows), False otherwise.
        """
        schema_version = self.version[0] if self.version else max(queries)
        candidates = sorted((v for v in queries if v <= schema_version), reverse=True) or [min(queries)]
        for candidate in candidates:
            try:
                cursor.execute(queries[candidate])
                log.info(f' - Using {artifact_name} query for places schema v{candidate}')
                return True
            except sqlite3.OperationalError as e:
                log.warning(f' - {artifact_name} query for places schema v{candidate} '
                            f'failed ({e}); trying an older schema')
        return False

    def get_history(self, path, database='places.sqlite', row_type='url'):
        results = []
        log.info(f'History items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        # `description` and `preview_image_url` were added to moz_places in
        # MigrateV38Up (places schema v38 / Firefox 57). Profiles below that — e.g.
        # older Tor Browser builds, which sit at places schema v30 — lack both
        # columns, so a single query referencing them fails the whole history read.
        # Keep one readable query per schema era (keyed by the minimum places
        # user_version it applies to); `hidden` rows are framed/redirect-only
        # entries the user didn't navigate to — keep them so examiners can filter
        # in the output rather than us deciding.
        queries = {
            # places schema v38+ (Firefox 57+): has description / preview_image_url.
            38: (
                "SELECT p.id AS place_id, p.url, p.title, p.visit_count, "
                "       p.typed, p.hidden, p.last_visit_date, p.frecency, "
                "       p.description, p.preview_image_url, "
                "       v.id AS visit_id, v.visit_date, v.visit_type, "
                "       v.from_visit, v.session, "
                "       (SELECT url FROM moz_places "
                "         WHERE id = (SELECT place_id FROM moz_historyvisits "
                "                      WHERE id = v.from_visit)) AS from_url "
                "FROM moz_places p "
                "JOIN moz_historyvisits v ON p.id = v.place_id"
            ),
            # Pre-v38 schema (e.g. Tor Browser's places schema v30): no
            # description / preview_image_url columns.
            1: (
                "SELECT p.id AS place_id, p.url, p.title, p.visit_count, "
                "       p.typed, p.hidden, p.last_visit_date, p.frecency, "
                "       v.id AS visit_id, v.visit_date, v.visit_type, "
                "       v.from_visit, v.session, "
                "       (SELECT url FROM moz_places "
                "         WHERE id = (SELECT place_id FROM moz_historyvisits "
                "                      WHERE id = v.from_visit)) AS from_url "
                "FROM moz_places p "
                "JOIN moz_historyvisits v ON p.id = v.place_id"
            ),
        }

        try:
            cursor = conn.cursor()
            if not self._execute_versioned_query(cursor, queries, 'history'):
                log.error(' - Could not query history with any known schema')
                self.artifacts_counts[database] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            for row in cursor:
                visit_time = utils.to_datetime(row.get('visit_date'), self.timezone)
                last_visit_time = utils.to_datetime(row.get('last_visit_date'), self.timezone) \
                    if row.get('last_visit_date') else visit_time

                new_row = Firefox.URLItem(
                    profile=self.profile_path,
                    visit_id=row.get('visit_id'),
                    url=row.get('url'),
                    title=row.get('title'),
                    visit_time=visit_time,
                    last_visit_time=last_visit_time,
                    visit_count=row.get('visit_count'),
                    typed_count=row.get('typed'),  # 0/1 flag in Firefox, not a count
                    from_visit=row.get('from_visit'),
                    transition=row.get('visit_type'),
                    hidden=row.get('hidden'),
                    favicon_id=None,
                )
                new_row.row_type = row_type
                new_row.transition_friendly = Firefox._visit_type_friendly(row.get('visit_type'))
                new_row.source_item = source_item
                from_url = row.get('from_url')
                if from_url:
                    new_row.interpretation = f'Referrer: {from_url}'
                results.append(new_row)

            self.artifacts_counts[database] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    def get_bookmarks(self, path, database='places.sqlite'):
        # moz_bookmarks stores folders and bookmarks in the same table; split by `type`.
        results = []
        log.info(f'Bookmark items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT b.id, b.type, b.fk, b.parent, b.title, b.dateAdded, "
                "       b.lastModified, b.guid, p.url "
                "FROM moz_bookmarks b "
                "LEFT JOIN moz_places p ON b.fk = p.id"
            )
            rows = cursor.fetchall()
            folder_titles = {r['id']: (r['title'] or '') for r in rows if r['type'] == BOOKMARK_TYPE_FOLDER}

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            for row in rows:
                bm_type = row.get('type')
                parent_folder = folder_titles.get(row.get('parent'), '')
                date_added = utils.to_datetime(row.get('dateAdded'), self.timezone)
                date_modified = utils.to_datetime(row.get('lastModified'), self.timezone) \
                    if row.get('lastModified') else date_added

                if bm_type == BOOKMARK_TYPE_URL:
                    item = Firefox.BookmarkItem(
                        profile=self.profile_path,
                        date_added=date_added,
                        name=row.get('title') or '',
                        url=row.get('url'),
                        parent_folder=parent_folder,
                    )
                    item.source_item = source_item
                    results.append(item)
                elif bm_type == BOOKMARK_TYPE_FOLDER:
                    # Skip the synthetic top-level roots (menu/toolbar/tags/unfiled/mobile).
                    if row.get('parent') in (None, 0):
                        continue
                    item = Firefox.BookmarkFolderItem(
                        profile=self.profile_path,
                        date_added=date_added,
                        date_modified=date_modified,
                        name=row.get('title') or '',
                        parent_folder=parent_folder,
                    )
                    item.source_item = source_item
                    results.append(item)

            self.artifacts_counts['Bookmarks'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    def get_cookies(self, path, database='cookies.sqlite'):
        # Firefox cookies are unencrypted at rest. Emit separate (created)
        # and (accessed) rows like the Chrome parser does.
        results = []
        log.info(f'Cookie items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT name, value, host, path, expiry, lastAccessed, creationTime, "
                    "       isSecure, isHttpOnly, sameSite "
                    "FROM moz_cookies"
                )
            except Exception as e:
                log.error(f' - Could not query cookies: {e}')
                self.artifacts_counts[database] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            zero_ts = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
            for row in cursor:
                creation = utils.to_datetime(row.get('creationTime'), self.timezone)
                accessed = utils.to_datetime(row.get('lastAccessed'), self.timezone)
                # `expiry` is unix seconds (not PRTime). 0 means session cookie.
                expiry_raw = row.get('expiry')
                if expiry_raw:
                    try:
                        expires = datetime.datetime.fromtimestamp(int(expiry_raw), datetime.timezone.utc)
                        if self.timezone:
                            expires = expires.astimezone(self.timezone)
                    except (OverflowError, OSError, ValueError):
                        expires = None
                else:
                    expires = None

                base = Firefox.CookieItem(
                    profile=self.profile_path,
                    host_key=row.get('host'),
                    path=row.get('path'),
                    name=row.get('name'),
                    value=row.get('value'),
                    creation_utc=creation,
                    last_access_utc=accessed,
                    secure=bool(row.get('isSecure')),
                    http_only=bool(row.get('isHttpOnly')),
                    persistent=bool(expiry_raw),
                    has_expires=bool(expiry_raw),
                    expires_utc=expires,
                )
                host = row.get('host') or ''
                base.url = host.lstrip('.')
                base.source_item = source_item

                created = copy.copy(base)
                created.row_type = 'cookie (created)'
                created.timestamp = creation
                results.append(created)

                if accessed and accessed not in (creation, zero_ts):
                    accessed_row = copy.copy(base)
                    accessed_row.row_type = 'cookie (accessed)'
                    accessed_row.timestamp = accessed
                    results.append(accessed_row)

            self.artifacts_counts['Cookies'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    def get_downloads(self, path, database='places.sqlite'):
        # Firefox 24+ stores downloads as moz_annos rows (`downloads/destinationFileURI`)
        # rather than the legacy downloads.sqlite.
        results = []
        log.info(f'Download items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT p.url, a.content AS target, a.dateAdded AS start_time, "
                    "       a.lastModified AS end_time, p.id AS place_id "
                    "FROM moz_places p "
                    "JOIN moz_annos a ON p.id = a.place_id "
                    "JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id "
                    "WHERE aa.name = 'downloads/destinationFileURI'"
                )
            except Exception as e:
                log.error(f' - Could not query downloads: {e}')
                self.artifacts_counts[database + '_downloads'] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            for row in cursor:
                start = utils.to_datetime(row.get('start_time'), self.timezone)
                end = utils.to_datetime(row.get('end_time'), self.timezone) if row.get('end_time') else start
                target = row.get('target') or ''
                if target.startswith('file:///'):
                    try:
                        target = urllib.parse.unquote(target[len('file:///'):])
                    except Exception:
                        pass

                item = Firefox.DownloadItem(
                    profile=self.profile_path,
                    download_id=row.get('place_id'),
                    url=row.get('url'),
                    received_bytes=None,
                    total_bytes=None,
                    state=None,
                    full_path=target,
                    start_time=start,
                    end_time=end,
                    target_path=target,
                    current_path=target,
                )
                item.row_type = 'download'
                item.timestamp = start
                item.value = target or 'Error retrieving download location'
                item.status_friendly = ''
                item.interrupt_reason_friendly = ''
                item.danger_type_friendly = ''
                item.state_friendly = ''
                item.source_item = source_item
                results.append(item)

            self.artifacts_counts[database + '_downloads'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    def get_form_history(self, path, database='formhistory.sqlite'):
        # moz_formhistory rows are values typed into named form fields.
        # Firefox 64+ also tracks timesUsed/firstUsed/lastUsed.
        results = []
        log.info(f'Form history items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            has_usage = False
            try:
                cursor.execute("PRAGMA table_info(moz_formhistory)")
                cols = {r['name'] for r in cursor.fetchall()}
                has_usage = {'timesUsed', 'firstUsed', 'lastUsed'}.issubset(cols)
            except Exception:
                pass

            try:
                if has_usage:
                    cursor.execute(
                        "SELECT fieldname, value, timesUsed, firstUsed, lastUsed "
                        "FROM moz_formhistory"
                    )
                else:
                    cursor.execute("SELECT fieldname, value FROM moz_formhistory")
            except Exception as e:
                log.error(f' - Could not query form history: {e}')
                self.artifacts_counts[database] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            for row in cursor:
                # 'it'/'ts' are internal timestamp-ish fields excluded by the autopsy parser.
                field = (row.get('fieldname') or '').strip()
                if field.lower() in ('it', 'ts'):
                    continue

                if has_usage:
                    first_used = utils.to_datetime(row.get('firstUsed'), self.timezone)
                    item = Firefox.AutofillItem(
                        profile=self.profile_path,
                        date_created=first_used,
                        name=field,
                        value=row.get('value'),
                        count=row.get('timesUsed'),
                    )
                    item.timestamp = first_used
                else:
                    item = Firefox.AutofillItem(
                        profile=self.profile_path,
                        date_created=None,
                        name=field,
                        value=row.get('value'),
                        count=None,
                    )
                    item.timestamp = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
                item.row_type = 'autofill'
                item.source_item = source_item
                results.append(item)

            self.artifacts_counts[database] = len(results)
            self.artifacts_display['Autofill'] = 'Form history records'
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    # moz_perms.permission integer; sourced from nsIPermissionManager.idl.
    _PERMISSION_VALUES = {
        0: 'Unknown',
        1: 'Allow',
        2: 'Deny',
        3: 'Prompt',
        8: 'Allow for session',
    }

    _EXPIRE_TYPES = {
        0: 'Never',
        1: 'At session end',
        2: 'At a specific time',
        3: 'Policy-controlled',
    }

    def get_permissions(self, path, database='permissions.sqlite'):
        # moz_perms timestamps are unix milliseconds (not PRTime).
        results = []
        log.info(f'Permissions items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT origin, type, permission, expireType, expireTime, "
                    "       modificationTime "
                    "FROM moz_perms"
                )
            except Exception as e:
                log.error(f' - Could not query permissions: {e}')
                self.artifacts_counts[database] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            for row in cursor:
                # ms -> PRTime us so to_datetime hits its 16-digit branch.
                mod_ms = row.get('modificationTime') or 0
                mod_time = utils.to_datetime(mod_ms * 1000, self.timezone) if mod_ms else \
                    datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

                perm_value = row.get('permission')
                perm_label = self._PERMISSION_VALUES.get(perm_value, f'Unknown ({perm_value})')
                expire_type = row.get('expireType')
                expire_label = self._EXPIRE_TYPES.get(expire_type, f'Unknown ({expire_type})')

                exp_ms = row.get('expireTime') or 0
                if expire_type == 2 and exp_ms:
                    expires = utils.to_datetime(exp_ms * 1000, self.timezone)
                    interpretation = f'{expire_label}: {expires.isoformat()}'
                else:
                    interpretation = expire_label

                item = Firefox.SiteSetting(
                    profile=self.profile_path,
                    url=row.get('origin'),
                    timestamp=mod_time,
                    key=row.get('type'),
                    value=perm_label,
                    interpretation=interpretation,
                )
                item.row_type = 'site setting'
                item.source_item = source_item
                item.name = row.get('type')
                item.value = perm_label
                results.append(item)

            self.artifacts_counts['Permissions'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    # SiteSecurityServiceState.bin record layout (DataStorage format):
    # 286-byte fixed slot: hash[0:2], flags[2:4], key[4:260] (ASCII, null-padded,
    # 2-char persistence prefix + hostname), value[260:] as `<expiry_ms>,<state>,<sub>`.
    _HSTS_RECORD_SIZE = 286
    _HSTS_KEY_OFFSET = 4
    _HSTS_KEY_MAX = 256
    _HSTS_VALUE_OFFSET = 260
    _HSTS_VALUE_RE = re.compile(rb'(\d+),(\d+),(\d+)')

    def get_hsts(self, path, filename='SiteSecurityServiceState.bin'):
        results = []
        full_path = os.path.join(path, filename)
        log.info(f'HSTS items from {filename}:')
        if not os.path.isfile(full_path):
            log.info(f' - {full_path} not present')
            return

        try:
            with open(full_path, 'rb') as fh:
                blob = fh.read()
        except OSError as e:
            log.error(f' - Could not read {full_path}: {e}')
            self.artifacts_counts['HSTS'] = 'Failed'
            return

        source_item = os.path.relpath(full_path, self.profile_path)
        n_records = len(blob) // self._HSTS_RECORD_SIZE
        for i in range(n_records):
            rec = blob[i * self._HSTS_RECORD_SIZE:(i + 1) * self._HSTS_RECORD_SIZE]

            key_bytes = rec[self._HSTS_KEY_OFFSET:self._HSTS_KEY_OFFSET + self._HSTS_KEY_MAX]
            key_bytes = key_bytes.split(b'\x00', 1)[0]
            if len(key_bytes) < 3:
                continue
            try:
                key_str = key_bytes.decode('ascii')
            except UnicodeDecodeError:
                continue
            # 'P' prefix = persistent-storage bucket holding HSTS pins; skip others.
            if not key_str or key_str[0] != 'P':
                continue
            hostname = key_str[2:] if len(key_str) > 2 else key_str

            value_bytes = rec[self._HSTS_VALUE_OFFSET:]
            m = self._HSTS_VALUE_RE.search(value_bytes)
            if not m:
                continue
            expiry_ms = int(m.group(1))
            state = int(m.group(2))
            include_subdomains = int(m.group(3))

            # state 0 = unset/deleted; skip.
            if state == 0:
                continue

            try:
                expiry_dt = datetime.datetime.fromtimestamp(expiry_ms / 1000.0,
                                                             datetime.timezone.utc)
                if self.timezone:
                    expiry_dt = expiry_dt.astimezone(self.timezone)
                expiry_str = expiry_dt.isoformat()
            except (OSError, OverflowError, ValueError):
                expiry_str = str(expiry_ms)

            interpretation_parts = [f'expires {expiry_str}']
            if include_subdomains:
                interpretation_parts.append('includeSubdomains=true')
            else:
                interpretation_parts.append('includeSubdomains=false')
            if state == 2:
                interpretation_parts.append('state=2 (HSTS via header + includeSubdomains)')
            else:
                interpretation_parts.append(f'state={state}')

            # No creation ts in HSTS records; use file mtime as a soft observed-at.
            try:
                observed = datetime.datetime.fromtimestamp(
                    os.path.getmtime(full_path), datetime.timezone.utc)
                if self.timezone:
                    observed = observed.astimezone(self.timezone)
            except OSError:
                observed = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

            item = Firefox.SiteSetting(
                profile=self.profile_path,
                url=hostname,
                timestamp=observed,
                key='HSTS',
                value='Enforced',
                interpretation='; '.join(interpretation_parts),
            )
            item.row_type = 'site setting (HSTS)'
            item.name = 'HSTS'
            item.value = 'Enforced'
            item.source_item = source_item
            results.append(item)

        self.artifacts_counts['HSTS'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    @staticmethod
    def _parse_prefs_value(raw):
        if raw == 'true':
            return True
        if raw == 'false':
            return False
        if raw == 'null':
            return None
        try:
            return json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
                return raw[1:-1].replace('\\\\', '\\').replace('\\"', '"')
            return raw

    def get_preferences(self, path, prefs_file='prefs.js'):
        full_path = os.path.join(path, prefs_file)
        log.info(f'Preferences from {prefs_file}:')
        if not os.path.isfile(full_path):
            log.info(f' - {full_path} not present')
            return

        all_prefs = {}
        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('//'):
                        continue
                    m = _PREFS_LINE_RE.match(line)
                    if not m:
                        continue
                    name = m.group(1)
                    value = self._parse_prefs_value(m.group(2))
                    all_prefs[name] = value
        except OSError as e:
            log.error(f' - Could not read {full_path}: {e}')
            self.artifacts_counts['prefs.js'] = 'Failed'
            return

        results = []
        seen = set()

        for group_name, entries in INTERESTING_PREFS:
            results.append({'group': group_name, 'name': None, 'value': None, 'description': None})
            for key, description in entries:
                if key in all_prefs:
                    value = all_prefs[key]
                    seen.add(key)
                else:
                    value = '<not set>'
                results.append({
                    'group': None,
                    'name': key,
                    'value': value if not isinstance(value, (dict, list)) else json.dumps(value),
                    'description': description,
                })

        # Long tail: every other set pref, grouped by dotted prefix.
        remaining = sorted(k for k in all_prefs if k not in seen)
        if remaining:
            results.append({'group': 'All Other Preferences', 'name': None, 'value': None, 'description': None})
            current_prefix = None
            for key in remaining:
                prefix = key.split('.', 1)[0]
                if prefix != current_prefix:
                    results.append({
                        'group': f'{prefix}.*', 'name': None, 'value': None, 'description': None,
                    })
                    current_prefix = prefix
                value = all_prefs[key]
                results.append({
                    'group': None,
                    'name': key,
                    'value': value if not isinstance(value, (dict, list)) else json.dumps(value),
                    'description': None,
                })

        pref_count = sum(1 for r in results if r['name'] is not None)
        self.artifacts_counts['Preferences'] = pref_count

        profile_folder = os.path.basename(path.rstrip(os.sep)) or 'profile'
        presentation = {
            'title': f'Preferences ({profile_folder})',
            'columns': [
                {'display_name': 'Group', 'data_name': 'group', 'display_width': 24},
                {'display_name': 'Setting Name', 'data_name': 'name', 'display_width': 50},
                {'display_name': 'Value', 'data_name': 'value', 'display_width': 50},
                {'display_name': 'Description', 'data_name': 'description', 'display_width': 60},
            ],
        }
        self.preferences.append({'data': results, 'presentation': presentation})
        log.info(f' - Parsed {pref_count} preferences')

    def get_logins(self, path, filename='logins.json'):
        # Username and password values are NSS/3DES-CBC encrypted (key wrapped in key4.db).
        # We do NOT decrypt; we surface unencrypted metadata + three timestamp rows per login.
        results = []
        full_path = os.path.join(path, filename)
        log.info(f'Saved logins from {filename}:')
        if not os.path.isfile(full_path):
            log.info(f' - {full_path} not present')
            return

        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            log.error(f' - Could not read {full_path}: {e}')
            self.artifacts_counts['Logins'] = 'Failed'
            return

        source_item = os.path.relpath(full_path, self.profile_path)
        zero_ts = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

        for login in data.get('logins', []):
            hostname = login.get('hostname') or login.get('formSubmitURL') or ''
            form_url = login.get('formSubmitURL') or ''
            http_realm = login.get('httpRealm') or ''
            user_field = login.get('usernameField') or ''
            pass_field = login.get('passwordField') or ''
            guid = login.get('guid') or ''
            times_used = login.get('timesUsed', 0)
            ever_synced = login.get('everSynced')

            created_ms = login.get('timeCreated') or 0
            last_used_ms = login.get('timeLastUsed') or 0
            pw_changed_ms = login.get('timePasswordChanged') or 0

            def _to_dt(ms):
                if not ms:
                    return zero_ts
                return utils.to_datetime(ms * 1000, self.timezone)

            interp_parts = [
                f'GUID: {guid}',
                f'usernameField: {user_field!r}',
                f'passwordField: {pass_field!r}',
                f'timesUsed: {times_used}',
            ]
            if form_url and form_url != hostname:
                interp_parts.append(f'formSubmitURL: {form_url}')
            if http_realm:
                interp_parts.append(f'httpRealm: {http_realm}')
            if ever_synced is not None:
                interp_parts.append(f'everSynced: {ever_synced}')
            interpretation = '; '.join(interp_parts)

            for ts_ms, row_label, ts_name in [
                (created_ms, 'login (created)', 'timeCreated'),
                (last_used_ms, 'login (last used)', 'timeLastUsed'),
                (pw_changed_ms, 'login (password changed)', 'timePasswordChanged'),
            ]:
                if not ts_ms:
                    continue
                # Drop the duplicate row when the timestamp matches creation.
                if row_label.endswith('changed)') and ts_ms == created_ms:
                    continue
                if row_label.endswith('last used)') and ts_ms == created_ms:
                    continue

                item = Firefox.LoginItem(
                    profile=self.profile_path,
                    date_created=_to_dt(ts_ms),
                    url=hostname,
                    name=user_field or '(username field)',
                    value='<encrypted>',
                    count=times_used,
                    interpretation=f'{ts_name}; {interpretation}',
                )
                item.row_type = row_label
                item.timestamp = _to_dt(ts_ms)
                item.source_item = source_item
                results.append(item)

        for guid in data.get('potentiallyVulnerablePasswords', []) or []:
            item = Firefox.LoginItem(
                profile=self.profile_path,
                date_created=zero_ts,
                url='<aggregate>',
                name='potentiallyVulnerablePassword',
                value=guid if isinstance(guid, str) else json.dumps(guid),
                count=None,
                interpretation='Firefox flagged this saved login GUID as potentially exposed in a known breach',
            )
            item.row_type = 'login (vulnerable)'
            item.timestamp = zero_ts
            item.source_item = source_item
            results.append(item)

        self.artifacts_counts['Logins'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    @staticmethod
    def _snappy_decompress(src):
        # Snappy "raw" block: varint(decompressed_len) + tag-prefixed literal/copy records.
        # Pure-Python so we don't take a C-extension dep on python-snappy.
        n = len(src)
        i = 0
        decompressed_len = 0
        shift = 0
        while i < n:
            b = src[i]
            i += 1
            decompressed_len |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift >= 32:
                raise ValueError('snappy: decompressed length varint too long')

        out = bytearray()
        while i < n and len(out) < decompressed_len:
            tag = src[i]
            i += 1
            tag_type = tag & 0x03
            if tag_type == 0:
                # Literal; top 6 bits = length-1 when < 60, else 60..63 = N-59 extra length bytes.
                length = (tag >> 2) + 1
                if length > 60:
                    extra = length - 60
                    length = 0
                    for j in range(extra):
                        length |= src[i + j] << (8 * j)
                    length += 1
                    i += extra
                out += src[i:i + length]
                i += length
            elif tag_type == 1:
                length = ((tag >> 2) & 0x07) + 4
                offset = ((tag & 0xE0) << 3) | src[i]
                i += 1
                for _ in range(length):
                    out.append(out[-offset])
            elif tag_type == 2:
                length = (tag >> 2) + 1
                offset = src[i] | (src[i + 1] << 8)
                i += 2
                for _ in range(length):
                    out.append(out[-offset])
            else:
                length = (tag >> 2) + 1
                offset = (src[i] | (src[i + 1] << 8) |
                          (src[i + 2] << 16) | (src[i + 3] << 24))
                i += 4
                for _ in range(length):
                    out.append(out[-offset])

        return bytes(out)

    # 8-byte magic for Mozilla's mozLz40 wrapper: magic + uint32 LE decompressed size + LZ4 block.
    _MOZLZ4_MAGIC = b'mozLz40\x00'

    @staticmethod
    def _lz4_block_decompress(src, dest_size):
        # LZ4 block format: token byte (hi=literal_len, lo=match_len), optional 0xff
        # overflow chains for both lengths, literal bytes, 2-byte LE match offset.
        out = bytearray()
        i = 0
        n = len(src)
        while i < n:
            token = src[i]
            i += 1
            literal_len = token >> 4
            if literal_len == 15:
                while i < n:
                    b = src[i]
                    i += 1
                    literal_len += b
                    if b != 0xFF:
                        break
            out.extend(src[i:i + literal_len])
            i += literal_len
            if i >= n:
                break
            if i + 2 > n:
                break
            offset = src[i] | (src[i + 1] << 8)
            i += 2
            if offset == 0:
                break
            match_len = (token & 0x0F) + 4
            if (token & 0x0F) == 15:
                while i < n:
                    b = src[i]
                    i += 1
                    match_len += b
                    if b != 0xFF:
                        break
            # Byte-by-byte copy so overlapping windows (RLE-style runs) work.
            for _ in range(match_len):
                out.append(out[-offset])
            if len(out) >= dest_size:
                break
        return bytes(out)

    @classmethod
    def _decompress_jsonlz4(cls, path):
        try:
            with open(path, 'rb') as fh:
                magic = fh.read(8)
                if magic != cls._MOZLZ4_MAGIC:
                    log.warning(f' - {path}: not a mozLz40 file (magic={magic!r})')
                    return None
                size_bytes = fh.read(4)
                if len(size_bytes) != 4:
                    return None
                dest_size = struct.unpack('<I', size_bytes)[0]
                payload = fh.read()
        except OSError as e:
            log.warning(f' - Could not read {path}: {e}')
            return None
        try:
            return cls._lz4_block_decompress(payload, dest_size)
        except Exception as e:
            log.warning(f' - LZ4 decompress failed for {path}: {e}')
            return None

    # signedState integers from mozapps/extensions/AddonManager.sys.mjs.
    _ADDON_SIGNED_STATES = {
        -2: 'Broken',
        -1: 'Unknown',
        0: 'Missing',
        1: 'Preliminary',
        2: 'Signed',
        3: 'System',
        4: 'Privileged',
    }

    def get_extensions(self, path, filename='extensions.json'):
        full_path = os.path.join(path, filename)
        log.info(f'Installed extensions from {filename}:')
        if not os.path.isfile(full_path):
            log.info(f' - {full_path} not present')
            return

        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            log.error(f' - Could not read {full_path}: {e}')
            self.artifacts_counts['Extensions'] = 'Failed'
            return

        results = []
        for addon in data.get('addons', []):
            ext_id = addon.get('id') or ''
            version = addon.get('version') or ''
            addon_type = addon.get('type') or ''
            active = addon.get('active')
            user_disabled = addon.get('userDisabled')
            app_disabled = addon.get('appDisabled')
            signed_state_raw = addon.get('signedState')
            signed_state = self._ADDON_SIGNED_STATES.get(
                signed_state_raw, f'Unknown ({signed_state_raw})')
            source_uri = addon.get('sourceURI') or ''
            location = addon.get('location') or ''
            on_disk_path = addon.get('path') or ''
            root_uri = addon.get('rootURI') or ''
            install_ms = addon.get('installDate') or 0
            update_ms = addon.get('updateDate') or 0

            default_locale = addon.get('defaultLocale') or {}
            name = default_locale.get('name') or ext_id
            description = default_locale.get('description') or ''

            user_perms = addon.get('userPermissions') or {}
            perms_list = list(user_perms.get('permissions', []))
            origins_list = list(user_perms.get('origins', []))
            permissions_str = json.dumps({
                'permissions': perms_list, 'origins': origins_list
            }) if (perms_list or origins_list) else ''

            # Compact manifest summary; full extension manifests can be 500KB.
            manifest_summary = {
                'id': ext_id,
                'version': version,
                'type': addon_type,
                'active': active,
                'userDisabled': user_disabled,
                'appDisabled': app_disabled,
                'signedState': signed_state,
                'sourceURI': source_uri,
                'installLocation': location,
                'path': on_disk_path,
                'rootURI': root_uri,
                'installDate': install_ms,
                'updateDate': update_ms,
            }

            results.append(Firefox.BrowserExtension(
                profile=self.profile_path,
                ext_id=ext_id,
                name=name,
                description=description,
                version=version,
                permissions=permissions_str,
                manifest=json.dumps(manifest_summary),
            ))

        self.artifacts_counts['Extensions'] = len(results)
        log.info(f' - Parsed {len(results)} items')

        presentation = {
            'title': 'Installed Extensions',
            'columns': [
                {'display_name': 'Extension Name', 'data_name': 'name', 'display_width': 26},
                {'display_name': 'Description', 'data_name': 'description', 'display_width': 60},
                {'display_name': 'Version', 'data_name': 'version', 'display_width': 10},
                {'display_name': 'App ID', 'data_name': 'ext_id', 'display_width': 40},
                {'display_name': 'Profile Folder', 'data_name': 'profile', 'display_width': 30},
                {'display_name': 'Permissions', 'data_name': 'permissions', 'display_width': 45},
                {'display_name': 'Manifest', 'data_name': 'manifest', 'display_width': 80},
            ],
        }
        self.installed_extensions = {'data': results, 'presentation': presentation}

    def _walk_sessionstore(self, doc, source_label, source_item, results):
        # Emit one SessionItem per navigation entry so the timeline shows tab
        # history rather than just the currently selected URL.
        zero_ts = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

        def _emit_entries(entries, window_idx, tab_idx, selected_index,
                           tab_last_accessed_ms, row_label):
            for nav_idx, entry in enumerate(entries or []):
                url = entry.get('url')
                if not url:
                    continue
                title = entry.get('title') or ''
                referrer = entry.get('referrer') or entry.get('originalURI') or ''
                # Only the selected nav-entry gets a real timestamp; others sort to epoch 0.
                if nav_idx + 1 == selected_index and tab_last_accessed_ms:
                    ts = utils.to_datetime(tab_last_accessed_ms * 1000, self.timezone)
                else:
                    ts = zero_ts

                item = Firefox.SessionItem(
                    profile=self.profile_path,
                    url=url,
                    title=title,
                    timestamp=ts,
                    session_id=f'win{window_idx}.tab{tab_idx}',
                    nav_index=nav_idx,
                    referrer_url=referrer,
                    original_request_url=entry.get('originalURI'),
                    source_path=source_item,
                )
                item.row_type = row_label
                item.value = ''
                item.source_item = source_item
                item.transition_type = (
                    'selected' if nav_idx + 1 == selected_index else 'history'
                )
                results.append(item)

        for w_idx, window in enumerate(doc.get('windows', []) or []):
            for t_idx, tab in enumerate(window.get('tabs', []) or []):
                _emit_entries(
                    tab.get('entries', []), w_idx, t_idx,
                    tab.get('index'), tab.get('lastAccessed'),
                    f'session (open tab, {source_label})')

            for c_idx, closed in enumerate(window.get('_closedTabs', []) or []):
                state = closed.get('state') or {}
                ts_ms = closed.get('closedAt')
                ts = utils.to_datetime(ts_ms * 1000, self.timezone) \
                    if ts_ms else zero_ts
                for nav_idx, entry in enumerate(state.get('entries', []) or []):
                    url = entry.get('url')
                    if not url:
                        continue
                    item = Firefox.SessionItem(
                        profile=self.profile_path,
                        url=url,
                        title=entry.get('title') or '',
                        timestamp=ts,
                        session_id=f'win{w_idx}.closed{c_idx}',
                        nav_index=nav_idx,
                        referrer_url=entry.get('referrer') or '',
                        original_request_url=entry.get('originalURI'),
                        source_path=source_item,
                    )
                    item.row_type = f'session (closed tab, {source_label})'
                    item.value = ''
                    item.source_item = source_item
                    item.transition_type = 'closed'
                    results.append(item)

        for cw_idx, cwin in enumerate(doc.get('_closedWindows', []) or []):
            for t_idx, tab in enumerate(cwin.get('tabs', []) or []):
                ts_ms = tab.get('lastAccessed')
                ts = utils.to_datetime(ts_ms * 1000, self.timezone) \
                    if ts_ms else zero_ts
                for nav_idx, entry in enumerate(tab.get('entries', []) or []):
                    url = entry.get('url')
                    if not url:
                        continue
                    item = Firefox.SessionItem(
                        profile=self.profile_path,
                        url=url,
                        title=entry.get('title') or '',
                        timestamp=ts,
                        session_id=f'closedwin{cw_idx}.tab{t_idx}',
                        nav_index=nav_idx,
                        referrer_url=entry.get('referrer') or '',
                        original_request_url=entry.get('originalURI'),
                        source_path=source_item,
                    )
                    item.row_type = f'session (closed window, {source_label})'
                    item.value = ''
                    item.source_item = source_item
                    item.transition_type = 'closed'
                    results.append(item)

    def get_sessionstore(self, path):
        # sessionstore-backups/ rotates: recovery.jsonlz4 (live), recovery.baklz4
        # (previous live), previous.jsonlz4 (last clean close), upgrade.jsonlz4-<ts>
        # (per-upgrade snapshot, often preserves state from older Firefox versions).
        results = []
        log.info('Sessionstore items:')

        candidates = []
        primary = os.path.join(path, 'sessionstore.jsonlz4')
        if os.path.isfile(primary):
            candidates.append((primary, 'current'))

        backups_dir = os.path.join(path, 'sessionstore-backups')
        if os.path.isdir(backups_dir):
            for name in sorted(os.listdir(backups_dir)):
                full = os.path.join(backups_dir, name)
                if not os.path.isfile(full):
                    continue
                if not (name.endswith('.jsonlz4') or name.endswith('.baklz4')
                        or '.jsonlz4-' in name):
                    continue
                candidates.append((full, name))

        if not candidates:
            log.info(' - No sessionstore files found')
            return

        for full_path, label in candidates:
            try:
                raw = self._decompress_jsonlz4(full_path)
                if raw is None:
                    continue
                doc = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                log.warning(f' - Could not parse {full_path}: {e}')
                continue
            source_item = os.path.relpath(full_path, self.profile_path)
            before = len(results)
            self._walk_sessionstore(doc, label, source_item, results)
            log.info(f' - {label}: parsed {len(results) - before} entries')

        self.artifacts_counts['Sessions'] = len(results)
        log.info(f' - Parsed {len(results)} items total')
        self.parsed_artifacts.extend(results)

    def get_bookmark_backups(self, path):
        # Firefox writes a fresh jsonlz4 snapshot of the bookmark tree daily and
        # keeps ~10 rolling backups; deleted bookmarks survive in older snapshots.
        backups_dir = os.path.join(path, 'bookmarkbackups')
        log.info('Bookmark backups:')
        if not os.path.isdir(backups_dir):
            log.info(f' - {backups_dir} not present')
            return

        zero_ts = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
        results = []

        def _walk(node, parent_title, snapshot_label, source_item):
            type_code = node.get('typeCode')
            title = node.get('title') or ''
            date_added = node.get('dateAdded') or 0
            last_modified = node.get('lastModified') or date_added
            ts = utils.to_datetime(date_added, self.timezone) if date_added else zero_ts
            mod_ts = utils.to_datetime(last_modified, self.timezone) if last_modified else ts

            if type_code == 1:
                url = node.get('uri') or node.get('url') or ''
                item = Firefox.BookmarkItem(
                    profile=self.profile_path,
                    date_added=ts,
                    name=title,
                    url=url,
                    parent_folder=parent_title,
                )
                item.row_type = f'bookmark (backup, {snapshot_label})'
                item.source_item = source_item
                results.append(item)
            elif type_code == 2:
                # Skip the synthetic top-level roots (parent_title empty for menu/toolbar/etc).
                if parent_title:
                    item = Firefox.BookmarkFolderItem(
                        profile=self.profile_path,
                        date_added=ts,
                        date_modified=mod_ts,
                        name=title,
                        parent_folder=parent_title,
                    )
                    item.row_type = f'bookmark folder (backup, {snapshot_label})'
                    item.source_item = source_item
                    results.append(item)
                next_parent = title or parent_title
                for child in node.get('children', []) or []:
                    _walk(child, next_parent, snapshot_label, source_item)

        for name in sorted(os.listdir(backups_dir)):
            full = os.path.join(backups_dir, name)
            if not (name.endswith('.jsonlz4') or name.endswith('.json')):
                continue
            if not os.path.isfile(full):
                continue
            try:
                if name.endswith('.jsonlz4'):
                    raw = self._decompress_jsonlz4(full)
                    if raw is None:
                        continue
                    doc = json.loads(raw)
                else:
                    with open(full, 'r', encoding='utf-8', errors='replace') as fh:
                        doc = json.load(fh)
            except (json.JSONDecodeError, OSError) as e:
                log.warning(f' - Could not parse {full}: {e}')
                continue
            source_item = os.path.relpath(full, self.profile_path)
            before = len(results)
            for child in doc.get('children', []) or []:
                _walk(child, '', name, source_item)
            log.info(f' - {name}: {len(results) - before} entries')

        self.artifacts_counts['Bookmark Backups'] = len(results)
        log.info(f' - Parsed {len(results)} items total')
        self.parsed_artifacts.extend(results)

    def get_favicons(self, path, database='favicons.sqlite'):
        # favicons.sqlite survives 'Clear History' on places.sqlite, so pages
        # appear here even after the user wiped them from history.
        results = []
        log.info(f'Favicon items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT p.page_url, i.icon_url, i.width, i.expire_ms "
                    "FROM moz_pages_w_icons p "
                    "JOIN moz_icons_to_pages m ON p.id = m.page_id "
                    "JOIN moz_icons i ON i.id = m.icon_id"
                )
            except Exception as e:
                log.error(f' - Could not query favicons: {e}')
                self.artifacts_counts[database] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            zero_ts = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

            for row in cursor:
                expire_ms = row.get('expire_ms') or 0
                if expire_ms:
                    expire_dt = utils.to_datetime(expire_ms * 1000, self.timezone)
                else:
                    expire_dt = zero_ts

                icon_url = row.get('icon_url') or ''
                width = row.get('width') or 0
                # 'fake-favicon-uri:' is Firefox-synthetic; no forensic value.
                if icon_url.startswith('fake-favicon-uri:'):
                    continue

                item = Firefox.URLItem(
                    profile=self.profile_path,
                    visit_id=None,
                    url=row.get('page_url'),
                    title=None,
                    visit_time=expire_dt,
                    last_visit_time=expire_dt,
                    visit_count=None,
                    typed_count=None,
                    from_visit=None,
                    transition=None,
                    hidden=None,
                    favicon_id=None,
                )
                item.row_type = 'url (from favicons)'
                item.transition_friendly = 'Recovered from favicons cache'
                item.interpretation = (
                    f'Icon: {icon_url} ({width}px); page survived in '
                    f'favicons.sqlite (history may have been cleared)'
                )
                item.source_item = source_item
                results.append(item)

            self.artifacts_counts['Favicons'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    # bounce-tracking-protection.sqlite.sites.entryType from BounceTrackingProtectionStorage.sys.mjs.
    _BOUNCE_ENTRY_TYPES = {
        0: 'User activation',
        1: 'Bounce tracker',
    }

    # protections.sqlite.events.type from the content-blocking telemetry categories.
    _PROTECTION_EVENT_TYPES = {
        1: 'Tracking content',
        2: 'Tracking cookie',
        3: 'Fingerprinter',
        4: 'Cryptominer',
        5: 'Social tracker',
    }

    def get_bounce_tracking(self, path, database='bounce-tracking-protection.sqlite'):
        results = []
        log.info(f'Bounce tracking items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT originAttributeSuffix, siteHost, entryType, timeStamp "
                    "FROM sites"
                )
            except Exception as e:
                log.error(f' - Could not query bounce-tracking state: {e}')
                self.artifacts_counts[database] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            for row in cursor:
                ts = utils.to_datetime(row.get('timeStamp'), self.timezone)
                entry_type = row.get('entryType')
                entry_label = self._BOUNCE_ENTRY_TYPES.get(
                    entry_type, f'Unknown ({entry_type})')
                origin_suffix = row.get('originAttributeSuffix') or ''
                interp_parts = [f'entryType={entry_label}']
                if origin_suffix:
                    interp_parts.append(f'originAttributeSuffix={origin_suffix}')

                item = Firefox.SiteSetting(
                    profile=self.profile_path,
                    url=row.get('siteHost'),
                    timestamp=ts,
                    key='bounce-tracking',
                    value=entry_label,
                    interpretation='; '.join(interp_parts),
                )
                item.row_type = 'site setting (bounce tracking)'
                item.name = 'bounce-tracking'
                item.value = entry_label
                item.source_item = source_item
                results.append(item)

            self.artifacts_counts['Bounce Tracking'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    def get_content_blocking(self, path, database='protections.sqlite'):
        # Aggregate daily counters: (date, category, count).
        results = []
        log.info(f'Content-blocking items from {database}:')

        conn = self._open(path, database)
        if not conn:
            return

        try:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT type, count, timestamp FROM events")
            except Exception as e:
                log.error(f' - Could not query content-blocking events: {e}')
                self.artifacts_counts[database] = 'Failed'
                return

            source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
            for row in cursor:
                # `timestamp` is a TEXT date like '2025-09-15'.
                ts_raw = row.get('timestamp') or ''
                try:
                    ts = datetime.datetime.strptime(ts_raw, '%Y-%m-%d').replace(
                        tzinfo=datetime.timezone.utc)
                    if self.timezone:
                        ts = ts.astimezone(self.timezone)
                except (ValueError, TypeError):
                    ts = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

                type_int = row.get('type')
                type_label = self._PROTECTION_EVENT_TYPES.get(
                    type_int, f'Unknown ({type_int})')
                count = row.get('count') or 0

                item = Firefox.SiteSetting(
                    profile=self.profile_path,
                    url='<aggregate daily counter>',
                    timestamp=ts,
                    key='content-blocking',
                    value=f'{type_label} blocked: {count}',
                    interpretation=f'On {ts_raw}, Firefox blocked {count} {type_label.lower()}(s) sitewide',
                )
                item.row_type = 'site setting (content blocking)'
                item.name = 'content-blocking'
                item.value = f'{type_label} blocked: {count}'
                item.source_item = source_item
                results.append(item)

            self.artifacts_counts['Content Blocking'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)
        finally:
            conn.close()

    @staticmethod
    def _parse_cache2_meta_at(hdr):
        # Parse a metadata header tuple starting at the byte immediately after
        # the u32 CRC. Returns (fields_dict, header_size) or None.
        if len(hdr) < 28:
            return None
        try:
            version, fetch_count, last_fetched, last_modified, frecency, expiration, key_size = \
                struct.unpack('>IIIIIII', hdr[:28])
        except struct.error:
            return None
        if version >= 2:
            if len(hdr) < 32:
                return None
            flags = struct.unpack('>I', hdr[28:32])[0]
            header_size = 32
        else:
            flags = None
            header_size = 28
        if key_size == 0 or key_size > 64 * 1024:
            return None
        if header_size + key_size + 1 > len(hdr):
            return None
        return ({
            'version': version,
            'fetch_count': fetch_count,
            'last_fetched': last_fetched,
            'last_modified': last_modified,
            'frecency': frecency,
            'expiration': expiration if expiration else None,
            'flags': flags,
            'key_size': key_size,
        }, header_size)

    @staticmethod
    def _parse_cache2_elements(blob):
        # response-head is itself a CRLF-joined HTTP block stored under the
        # name 'response-head'. Other names (last-accessed, frecency, etc.)
        # are short scalars.
        elements = {}
        parts = blob.split(b'\x00')
        i = 0
        while i + 1 < len(parts):
            name = parts[i].decode('utf-8', errors='replace')
            value = parts[i + 1].decode('utf-8', errors='replace')
            if name:
                elements[name] = value
            i += 2
        return elements

    @staticmethod
    def _split_response_head(response_head):
        status_line = None
        headers = {}
        if response_head:
            lines = response_head.replace('\r\n', '\n').split('\n')
            status_line = lines[0].strip() if lines else None
            for line in lines[1:]:
                if ':' not in line:
                    continue
                name, _, value = line.partition(':')
                if name.strip():
                    headers[name.strip().lower()] = value.strip()
        return status_line, headers

    # Best-effort regex-based recovery for entries whose metadata block has
    # been zeroed or corrupted by forensic acquisition. We try to pull a URL,
    # partition key, HTTP response headers, and net-response-time telemetry
    # straight out of the file's bytes.
    _CACHE2_KEY_URL_RE = re.compile(rb'(?:[\t:])(https?://[\x21-\x7e]{3,2000})')
    _CACHE2_PART_KEY_RE = re.compile(rb'\^partitionKey=%28([^%]+)%2C([^%]+)%29')
    _CACHE2_HEADER_RE = re.compile(
        rb'(content-type|content-length|content-encoding|cache-control|'
        rb'date|etag|last-modified|server|location|set-cookie|vary|age|expires|'
        rb'strict-transport-security|x-content-type-options|x-frame-options):'
        rb'\s*([^\r\n\x00]{1,500})', re.IGNORECASE)
    _CACHE2_TIMING_RE = re.compile(rb'net-response-time-on(start|stop)\x00(\d{1,8})')
    _CACHE2_STATUSLINE_RE = re.compile(rb'HTTP/1\.[01] (\d{3})')

    @classmethod
    def _cache2_regex_recover(cls, buf):
        out = {}
        m = cls._CACHE2_KEY_URL_RE.search(buf)
        if m:
            out['url'] = m.group(1).rstrip(b'\x00').decode(
                'utf-8', errors='replace')
        pk = cls._CACHE2_PART_KEY_RE.search(buf)
        if pk:
            out['partition_scheme'] = pk.group(1).decode(
                'utf-8', errors='replace')
            out['partition_host'] = pk.group(2).decode(
                'utf-8', errors='replace')
        headers = {}
        for name, value in cls._CACHE2_HEADER_RE.findall(buf):
            k = name.lower().decode('ascii')
            v = value.decode('utf-8', errors='replace').strip()
            if k not in headers and v:
                headers[k] = v
        if headers:
            out['headers'] = headers
        timing = {}
        for phase, ms in cls._CACHE2_TIMING_RE.findall(buf):
            timing[phase.decode('ascii')] = int(ms)
        if timing:
            out['timing'] = timing
        sl = cls._CACHE2_STATUSLINE_RE.search(buf)
        if sl:
            out['status'] = int(sl.group(1))
        return out

    @classmethod
    def _cache2_backscan_meta(cls, buf):
        # When the trailer u32 is corrupt or key_size is garbage, the real
        # metadata block may still be intact inside the file. The block starts
        # with u32 CRC | u32 version (small int: 1, 2, or 3). Look for those
        # version bytes in the back half and validate the candidate header.
        size = len(buf)
        if size < 64:
            return None
        start = size // 2
        # 2010-01-01 to 2100-01-01 in Unix seconds: timestamps outside this
        # range almost always indicate we landed on a random byte, not real
        # metadata.
        TS_LO, TS_HI = 1262304000, 4102444800
        for ver in (3, 2, 1):
            needle = b'\x00\x00\x00' + bytes([ver])
            pos = buf.find(needle, start)
            while pos != -1:
                ms = pos - 4
                if ms < 0:
                    pos = buf.find(needle, pos + 1)
                    continue
                meta = cls._parse_cache2_meta_at(buf[ms + 4:])
                if meta is None:
                    pos = buf.find(needle, pos + 1)
                    continue
                fields, header_size = meta
                if fields['version'] != ver:
                    pos = buf.find(needle, pos + 1)
                    continue
                lf = fields['last_fetched']
                lm = fields['last_modified']
                if not (lf == 0 or TS_LO <= lf <= TS_HI):
                    pos = buf.find(needle, pos + 1)
                    continue
                if not (lm == 0 or TS_LO <= lm <= TS_HI):
                    pos = buf.find(needle, pos + 1)
                    continue
                key_off = ms + 4 + header_size
                key_size = fields['key_size']
                key_bytes = buf[key_off:key_off + key_size]
                # Require a URL marker so we don't latch onto a coincidental
                # version-tag run.
                if b'http' not in key_bytes:
                    pos = buf.find(needle, pos + 1)
                    continue
                elements_blob = buf[key_off + key_size + 1:-4]
                return fields, key_bytes, elements_blob, ms
            # else: keep searching for older versions
        return None

    @classmethod
    def _parse_cache2_entry(cls, path):
        # Layout (big-endian throughout):
        #   [body, length=meta_offset] [chunk_hashes, 2B per CHUNK_SIZE chunk]
        #   [metadata block] [uint32 meta_offset trailer]
        # Metadata block: u32 crc | u32 version | u32 fetch_count | u32 last_fetched
        #   | u32 last_modified | u32 frecency | u32 expiration | u32 key_size
        #   | u32 flags (v2+) | key[key_size] | 0x00 | (name\0value\0)* elements
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        if size < CACHE2_MIN_ENTRY_SIZE:
            return None

        try:
            with open(path, 'rb') as fh:
                # Multi-MB entries: seek to the metadata block instead of slurping
                # gigabytes of cached video into memory. The strict-parse path
                # avoids reading the whole file; the recovery path needs it.
                if size <= 4 * 1024 * 1024:
                    buf = fh.read()
                    meta_offset = struct.unpack('>I', buf[-4:])[0]
                    if meta_offset < size - 4:
                        n_chunks = (meta_offset + CACHE2_CHUNK_SIZE - 1) // CACHE2_CHUNK_SIZE if meta_offset else 0
                        meta_start = meta_offset + n_chunks * CACHE2_HASH_SIZE
                        meta_block = buf[meta_start:-4]
                    else:
                        meta_block = b''
                else:
                    buf = None
                    fh.seek(-4, os.SEEK_END)
                    meta_offset = struct.unpack('>I', fh.read(4))[0]
                    if meta_offset >= size - 4:
                        return None
                    n_chunks = (meta_offset + CACHE2_CHUNK_SIZE - 1) // CACHE2_CHUNK_SIZE if meta_offset else 0
                    meta_start = meta_offset + n_chunks * CACHE2_HASH_SIZE
                    meta_len = size - meta_start - 4
                    if meta_len <= 0 or meta_len > 64 * 1024 * 1024:
                        return None
                    fh.seek(meta_start)
                    meta_block = fh.read(meta_len)
        except (OSError, struct.error):
            return None

        # ---- Tier A: strict parse ----
        if len(meta_block) >= 32:
            hdr = meta_block[4:]
            meta = cls._parse_cache2_meta_at(hdr)
            if meta is not None:
                fields, header_size = meta
                key_size = fields['key_size']
                key_bytes = hdr[header_size:header_size + key_size]
                elements_blob = hdr[header_size + key_size + 1:]
                elements = cls._parse_cache2_elements(elements_blob)
                response_head = (elements.get('response-head')
                                 or elements.get('original-response-headers') or '')
                status_line, headers = cls._split_response_head(response_head)
                m = _CACHE2_URL_RE.search(key_bytes)
                url = m.group(1).decode('utf-8', errors='replace') if m else \
                    key_bytes.decode('utf-8', errors='replace')
                return {
                    'data_size': meta_offset,
                    'version': fields['version'],
                    'fetch_count': fields['fetch_count'],
                    'last_fetched': fields['last_fetched'],
                    'last_modified': fields['last_modified'],
                    'frecency': fields['frecency'],
                    'expiration': fields['expiration'],
                    'flags': fields['flags'],
                    'key': key_bytes.decode('utf-8', errors='replace'),
                    'url': url,
                    'elements': elements,
                    'status_line': status_line,
                    'headers': headers,
                    'recovery_state': 'live',
                }

        # ---- Tier B/C: recovery (only attempted on fully-read small files) ----
        if buf is None:
            return None

        back = cls._cache2_backscan_meta(buf)
        if back is not None:
            fields, key_bytes, elements_blob, _ms = back
            elements = cls._parse_cache2_elements(elements_blob)
            response_head = (elements.get('response-head')
                             or elements.get('original-response-headers') or '')
            status_line, headers = cls._split_response_head(response_head)
            # Augment with regex-mined headers if the elements blob was wrecked.
            if not headers:
                regex = cls._cache2_regex_recover(buf)
                headers = regex.get('headers', {})
            m = _CACHE2_URL_RE.search(key_bytes)
            url = m.group(1).decode('utf-8', errors='replace') if m else \
                key_bytes.decode('utf-8', errors='replace')
            return {
                'data_size': 0,
                'version': fields['version'],
                'fetch_count': fields['fetch_count'],
                'last_fetched': fields['last_fetched'],
                'last_modified': fields['last_modified'],
                'frecency': fields['frecency'],
                'expiration': fields['expiration'],
                'flags': fields['flags'],
                'key': key_bytes.decode('utf-8', errors='replace'),
                'url': url,
                'elements': elements,
                'status_line': status_line,
                'headers': headers,
                'recovery_state': 'recovered (relocated metadata)',
            }

        # ---- Tier D: regex-only recovery ----
        regex = cls._cache2_regex_recover(buf)
        url = regex.get('url')
        headers = regex.get('headers', {})
        timing = regex.get('timing', {})
        if not url and not headers and not timing:
            return None

        part_host = regex.get('partition_host')
        if url:
            if headers:
                rs = 'recovered (url + headers, no metadata)'
            else:
                rs = 'recovered (url only, no metadata)'
        elif headers and timing:
            rs = 'recovered (headers + telemetry, no url)'
        elif headers:
            rs = 'recovered (headers only)'
        else:
            rs = 'recovered (telemetry only)'

        return {
            'data_size': 0,
            'version': None,
            'fetch_count': None,
            'last_fetched': 0,
            'last_modified': 0,
            'frecency': None,
            'expiration': None,
            'flags': None,
            'key': url or '',
            'url': url or '',
            'elements': {},
            'status_line': (f'HTTP/1.1 {regex["status"]}'
                            if 'status' in regex else None),
            'headers': headers,
            'recovery_state': rs,
            'partition_host': part_host,
            'timing': timing,
        }

    def _resolve_cache_dir(self):
        # Resolution order: user-supplied --cache, profile-adjacent cache2/entries,
        # then OS-specific fallbacks since Firefox splits cache out of the profile
        # on Windows (%LOCALAPPDATA%) and macOS (~/Library/Caches).
        def _entries_under(p):
            if not p or not os.path.isdir(p):
                return None
            base = os.path.basename(p.rstrip(os.sep)).lower()
            if base == 'entries':
                return p
            if base == 'cache2':
                cand = os.path.join(p, 'entries')
                return cand if os.path.isdir(cand) else None
            cand = os.path.join(p, 'cache2', 'entries')
            return cand if os.path.isdir(cand) else None

        cand = _entries_under(self.cache_path)
        if cand:
            return cand

        cand = _entries_under(self.profile_path)
        if cand:
            return cand

        # Windows: %APPDATA%\Mozilla\Firefox -> %LOCALAPPDATA%\Mozilla\Firefox
        norm = self.profile_path.replace('/', os.sep)
        lower = norm.lower()
        if '\\roaming\\mozilla\\firefox\\' in lower:
            local = re.sub(r'\\Roaming\\Mozilla\\Firefox\\',
                           r'\\Local\\Mozilla\\Firefox\\', norm, count=1, flags=re.IGNORECASE)
            cand = _entries_under(local)
            if cand:
                log.info(f' - Auto-detected Firefox cache at {cand}')
                return cand

        # macOS: ~/Library/Application Support/Firefox -> ~/Library/Caches/Firefox
        if '/Library/Application Support/Firefox/' in self.profile_path:
            mac = self.profile_path.replace(
                '/Library/Application Support/Firefox/',
                '/Library/Caches/Firefox/', 1)
            cand = _entries_under(mac)
            if cand:
                log.info(f' - Auto-detected Firefox cache at {cand}')
                return cand

        return None

    def get_cache(self, cache_entries_dir):
        results = []
        log.info(f'Cache items from {cache_entries_dir}:')

        try:
            names = os.listdir(cache_entries_dir)
        except OSError as e:
            log.error(f' - Could not read cache directory: {e}')
            self.artifacts_counts['Cache'] = 'Failed'
            return

        source_item = os.path.relpath(cache_entries_dir, self.profile_path) \
            if cache_entries_dir.startswith(self.profile_path) else cache_entries_dir
        skipped = 0
        recovery_counts = {}
        for name in names:
            path = os.path.join(cache_entries_dir, name)
            if not os.path.isfile(path):
                continue
            parsed = self._parse_cache2_entry(path)
            if parsed is None:
                skipped += 1
                continue

            try:
                request_time = datetime.datetime.fromtimestamp(
                    parsed['last_fetched'], datetime.timezone.utc)
                if self.timezone:
                    request_time = request_time.astimezone(self.timezone)
            except (OSError, OverflowError, ValueError):
                request_time = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

            content_type = parsed['headers'].get('content-type')
            data_size = parsed['data_size']
            if content_type and data_size:
                data_summary = f'{content_type} ({data_size} bytes)'
            elif content_type:
                data_summary = f'{content_type}'
            elif data_size:
                data_summary = f'{data_size} bytes'
            else:
                data_summary = '<no data>'

            recovery_state = parsed.get('recovery_state', 'live')
            recovery_counts[recovery_state] = recovery_counts.get(recovery_state, 0) + 1

            item = Firefox.CacheItem(
                profile=self.profile_path,
                url=parsed['url'],
                title=None,
                request_time=request_time,
                locations=name,
                key=parsed['key'],
                metadata=None,
                data=None,
            )
            if recovery_state == 'live':
                item.row_type = 'cache'
            else:
                item.row_type = f'cache ({recovery_state})'
            item.data_summary = data_summary
            item.http_headers_str = str(parsed['headers']) if parsed['headers'] else ''
            item.etag = parsed['headers'].get('etag', '') or ''
            item.last_modified = parsed['headers'].get('last-modified', '') or ''
            item.source_item = source_item

            # For regex-only recoveries, the partition host (top-frame site
            # that triggered the request) and net-response telemetry are the
            # primary forensic value. Surface them in the interpretation.
            interp_bits = []
            ph = parsed.get('partition_host')
            if ph:
                interp_bits.append(f'partitionKey host: {ph}')
            timing = parsed.get('timing') or {}
            if timing:
                t_parts = [f'{k}={v}ms' for k, v in sorted(timing.items())]
                interp_bits.append('net-response-time ' + ', '.join(t_parts))
            if interp_bits:
                item.interpretation = '; '.join(interp_bits)

            results.append(item)

        if skipped:
            log.info(f' - Skipped {skipped} unparseable files in cache directory')

        if recovery_counts:
            live_n = recovery_counts.pop('live', 0)
            recovered_total = sum(recovery_counts.values())
            log.info(f' - Parsed {len(results)} items '
                     f'({live_n} live, {recovered_total} recovered)')
            if recovered_total:
                breakdown = ', '.join(
                    f'{n} {state}' for state, n in
                    sorted(recovery_counts.items(), key=lambda kv: -kv[1]))
                log.info(f'   - Recovery breakdown: {breakdown}')
        else:
            log.info(f' - Parsed {len(results)} items')

        self.artifacts_counts['Cache'] = len(results)
        self.parsed_artifacts.extend(results)

    @staticmethod
    def _decode_origin_folder(name):
        # Firefox encodes origins as `https+++host`, `http+++host+port`, etc.
        # We only need a readable approximation; the canonical origin is
        # available from the `database` table inside the SQLite file.
        if '+++' in name:
            scheme, rest = name.split('+++', 1)
            rest = rest.replace('+', ':')
            return f'{scheme}://{rest}'
        return name

    def _decode_ls_value(self, raw, conversion_type, compression_type, source_path):
        # compression_type=1: snappy-compressed value blob.
        # conversion_type=0: real UTF-16-LE; =1: narrow (Latin-1, 1 byte per UTF-16 code unit).
        data = bytes(raw) if raw is not None else b''

        if compression_type == 1:
            try:
                data = self._snappy_decompress(data)
            except Exception as e:
                log.debug(f'localStorage snappy decompress failed for {source_path}: {e}')
                return f'<snappy decompression failed: {len(data)} bytes>'

        try:
            if conversion_type == 0:
                return data.decode('utf-16-le')
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode('utf-8', errors='replace')

    def get_local_storage(self, path):
        storage_root = os.path.join(path, 'storage', 'default')
        log.info(f'localStorage from {storage_root}:')
        if not os.path.isdir(storage_root):
            log.info(' - storage/default not present')
            return

        results = []
        origins_seen = 0
        origins_with_data = 0
        decode_failures = 0

        for origin_folder in sorted(os.listdir(storage_root)):
            ls_dir = os.path.join(storage_root, origin_folder, 'ls')
            ls_db = os.path.join(ls_dir, 'data.sqlite')
            if not os.path.isfile(ls_db):
                continue
            origins_seen += 1

            conn = utils.open_sqlite_db(self, ls_dir, 'data.sqlite')
            if not conn:
                continue

            try:
                cursor = conn.cursor()
                origin = self._decode_origin_folder(origin_folder)
                try:
                    cursor.execute('SELECT origin FROM database LIMIT 1')
                    row = cursor.fetchone()
                    if row and row.get('origin'):
                        origin = row['origin']
                except Exception:
                    pass

                try:
                    cursor.execute(
                        "SELECT key, utf16_length, conversion_type, "
                        "       compression_type, last_access_time, value "
                        "FROM data"
                    )
                except Exception as e:
                    log.debug(f' - {origin_folder}: data table unreadable ({e})')
                    continue

                source_path = os.path.relpath(ls_db, self.profile_path)
                got_any = False
                row_iter = enumerate(cursor)
                while True:
                    try:
                        seq, row = next(row_iter)
                    except StopIteration:
                        break
                    except Exception as e:
                        log.warning(
                            f' - {origin_folder}: localStorage db unreadable, '
                            f'skipping remaining rows ({e})')
                        break
                    key = row.get('key') or ''
                    conv = row.get('conversion_type') or 0
                    comp = row.get('compression_type') or 0
                    raw_value = row.get('value')
                    try:
                        value = self._decode_ls_value(
                            raw_value, conv, comp, source_path)
                    except Exception as e:
                        log.debug(f' - decode failed in {origin_folder}/{key}: {e}')
                        decode_failures += 1
                        continue

                    last_access_raw = row.get('last_access_time') or 0
                    if last_access_raw:
                        last_modified = utils.to_datetime(
                            last_access_raw, self.timezone)
                    else:
                        # last_access_time=0 is common; fall back to file mtime.
                        try:
                            last_modified = datetime.datetime.fromtimestamp(
                                os.path.getmtime(ls_db), datetime.timezone.utc)
                            if self.timezone:
                                last_modified = last_modified.astimezone(
                                    self.timezone)
                        except OSError:
                            last_modified = None

                    item = Firefox.LocalStorageItem(
                        profile=self.profile_path,
                        origin=origin,
                        key=key,
                        value=value,
                        seq=seq,
                        state='Live',
                        source_path=source_path,
                        last_modified=last_modified,
                    )
                    results.append(item)
                    got_any = True

                if got_any:
                    origins_with_data += 1
            finally:
                conn.close()

        self.artifacts_counts['Local Storage'] = len(results)
        if decode_failures:
            log.info(
                f' - Parsed {len(results)} records from {origins_with_data} '
                f'origins ({origins_seen} scanned, {decode_failures} decode '
                f'failures)'
            )
        else:
            log.info(
                f' - Parsed {len(results)} records from {origins_with_data} '
                f'origins ({origins_seen} scanned)'
            )
        self.parsed_storage.extend(results)

    # SCTAG values from mozilla-central/js/src/vm/StructuredClone.cpp StructuredDataType.
    # Tags below SCTAG_HEADER (0xFFF10000) are doubles encoded as their 64-bit IEEE bits.
    _SC_HEADER = 0xFFF10000
    _SC_NULL = 0xFFFF0000
    _SC_UNDEFINED = 0xFFFF0001
    _SC_BOOLEAN = 0xFFFF0002
    _SC_INT32 = 0xFFFF0003
    _SC_STRING = 0xFFFF0004
    _SC_DATE_OBJECT = 0xFFFF0005
    _SC_REGEXP_OBJECT = 0xFFFF0006
    _SC_ARRAY_OBJECT = 0xFFFF0007
    _SC_OBJECT_OBJECT = 0xFFFF0008
    _SC_ARRAY_BUFFER_V2 = 0xFFFF0009
    _SC_BOOLEAN_OBJECT = 0xFFFF000A
    _SC_STRING_OBJECT = 0xFFFF000B
    _SC_NUMBER_OBJECT = 0xFFFF000C
    _SC_BACK_REFERENCE = 0xFFFF000D
    _SC_TYPED_ARRAY_V2 = 0xFFFF0010
    _SC_MAP_OBJECT = 0xFFFF0011
    _SC_SET_OBJECT = 0xFFFF0012
    _SC_END_OF_KEYS = 0xFFFF0013
    _SC_DATA_VIEW_V2 = 0xFFFF0015
    _SC_BIGINT = 0xFFFF001D
    _SC_BIGINT_OBJECT = 0xFFFF001E
    _SC_ARRAY_BUFFER = 0xFFFF001F
    _SC_TYPED_ARRAY = 0xFFFF0020
    _SC_DATA_VIEW = 0xFFFF0021
    _SC_ERROR_OBJECT = 0xFFFF0022
    _SC_TYPED_ARRAY_V1_MIN = 0xFFFF0100
    _SC_TYPED_ARRAY_V1_MAX = 0xFFFF010A

    class _StructuredCloneReader(object):
        # Decode a SpiderMonkey JS_StructuredClone byte stream: sequence of
        # 64-bit LE (tag, data) pairs where the high 32 bits are SCTAG and
        # the low 32 bits are a type-specific payload. Bodies are read inline
        # and padded to an 8-byte boundary between pairs.

        def __init__(self, outer, buf):
            self._sc = outer
            self.buf = buf
            self.pos = 0
            self.objects = []  # back-reference table for SCTAG_BACK_REFERENCE

        def _pair(self):
            if self.pos + 8 > len(self.buf):
                raise ValueError(f'EOF at {self.pos}')
            pair = struct.unpack_from('<Q', self.buf, self.pos)[0]
            self.pos += 8
            return (pair >> 32) & 0xFFFFFFFF, pair & 0xFFFFFFFF, pair

        def _align8(self):
            rem = self.pos % 8
            if rem:
                self.pos += 8 - rem

        def _bytes(self, n):
            if self.pos + n > len(self.buf):
                raise ValueError(f'EOF reading {n} at {self.pos}')
            b = self.buf[self.pos:self.pos + n]
            self.pos += n
            return b

        def _string(self, data):
            # High bit of data = Latin-1 flag; low 31 bits = code-unit count.
            latin1 = (data & 0x80000000) != 0
            length = data & 0x7FFFFFFF
            if latin1:
                s = self._bytes(length).decode('latin-1', errors='replace')
            else:
                s = self._bytes(length * 2).decode('utf-16-le', errors='replace')
            self._align8()
            return s

        def read(self):
            tag, data, pair = self._pair()
            if tag == self._sc._SC_HEADER:
                tag, data, pair = self._pair()
            return self._value(tag, data, pair)

        def _value(self, tag, data, pair):
            sc = self._sc
            if tag < sc._SC_HEADER:
                return struct.unpack('<d', struct.pack('<Q', pair))[0]
            if tag == sc._SC_NULL:
                return None
            if tag == sc._SC_UNDEFINED:
                return '<undefined>'
            if tag == sc._SC_BOOLEAN:
                return bool(data)
            if tag == sc._SC_INT32:
                return struct.unpack('<i', struct.pack('<I', data))[0]
            if tag == sc._SC_STRING:
                return self._string(data)
            if tag == sc._SC_DATE_OBJECT:
                ms = struct.unpack('<d', self._bytes(8))[0]
                return f'<Date: {ms} ms>'
            if tag == sc._SC_ARRAY_OBJECT:
                arr = []
                self.objects.append(arr)
                while True:
                    t2, d2, _ = self._pair()
                    if t2 == sc._SC_END_OF_KEYS:
                        break
                    if t2 == sc._SC_INT32:
                        idx = struct.unpack('<i', struct.pack('<I', d2))[0]
                    elif t2 == sc._SC_STRING:
                        idx = self._string(d2)
                    else:
                        idx = f'<idx tag 0x{t2:x}>'
                    t3, d3, p3 = self._pair()
                    val = self._value(t3, d3, p3)
                    if isinstance(idx, int):
                        while len(arr) <= idx:
                            arr.append(None)
                        arr[idx] = val
                    else:
                        arr.append((idx, val))
                return arr
            if tag == sc._SC_OBJECT_OBJECT:
                obj = {}
                self.objects.append(obj)
                while True:
                    t2, d2, _ = self._pair()
                    if t2 == sc._SC_END_OF_KEYS:
                        break
                    if t2 == sc._SC_STRING:
                        key = self._string(d2)
                    elif t2 == sc._SC_INT32:
                        key = struct.unpack('<i', struct.pack('<I', d2))[0]
                    else:
                        key = f'<key tag 0x{t2:x}>'
                    t3, d3, p3 = self._pair()
                    obj[key] = self._value(t3, d3, p3)
                return obj
            if tag == sc._SC_BACK_REFERENCE:
                return self.objects[data] if data < len(self.objects) \
                    else f'<backref {data}>'
            if tag == sc._SC_MAP_OBJECT:
                m = {}
                self.objects.append(m)
                while True:
                    t2, d2, p2 = self._pair()
                    if t2 == sc._SC_END_OF_KEYS:
                        break
                    k = self._value(t2, d2, p2)
                    t3, d3, p3 = self._pair()
                    m[str(k)] = self._value(t3, d3, p3)
                return m
            if tag == sc._SC_SET_OBJECT:
                s = []
                self.objects.append(s)
                while True:
                    t2, d2, p2 = self._pair()
                    if t2 == sc._SC_END_OF_KEYS:
                        break
                    s.append(self._value(t2, d2, p2))
                return s
            if tag == sc._SC_STRING_OBJECT:
                return self._string(data)
            if tag == sc._SC_BOOLEAN_OBJECT:
                return bool(data)
            if tag == sc._SC_NUMBER_OBJECT:
                return struct.unpack('<d', self._bytes(8))[0]
            if tag in (sc._SC_BIGINT, sc._SC_BIGINT_OBJECT):
                sign = (data & 0x80000000) != 0
                n_digits = data & 0x7FFFFFFF
                raw = self._bytes(n_digits * 8)
                v = 0
                for i in range(n_digits):
                    v |= struct.unpack_from('<Q', raw, i * 8)[0] << (64 * i)
                return -v if sign else v
            if tag == sc._SC_ARRAY_BUFFER:
                n = data
                self._bytes(n)
                self._align8()
                return f'<ArrayBuffer: {n} bytes>'
            if tag == sc._SC_ARRAY_BUFFER_V2:
                n = struct.unpack('<Q', self._bytes(8))[0]
                self._bytes(n)
                self._align8()
                return f'<ArrayBuffer (v2): {n} bytes>'
            if tag == sc._SC_TYPED_ARRAY:
                scalar = data
                t2, d2, _ = self._pair()
                length = struct.unpack('<i', struct.pack('<I', d2))[0] \
                    if t2 == sc._SC_INT32 else d2
                self._pair()
                t4, d4, p4 = self._pair()
                self._value(t4, d4, p4)
                return f'<TypedArray[scalar={scalar}]: {length} elements>'
            if tag == sc._SC_TYPED_ARRAY_V2:
                scalar = data
                n = struct.unpack('<Q', self._bytes(8))[0]
                self._bytes(n)
                self._align8()
                return f'<TypedArray (v2)[scalar={scalar}]: {n} bytes>'
            if tag == sc._SC_DATA_VIEW:
                self._pair()
                self._pair()
                t4, d4, p4 = self._pair()
                self._value(t4, d4, p4)
                return '<DataView>'
            if tag == sc._SC_DATA_VIEW_V2:
                n = struct.unpack('<Q', self._bytes(8))[0]
                self._bytes(n)
                self._align8()
                return '<DataView (v2)>'
            if sc._SC_TYPED_ARRAY_V1_MIN <= tag <= sc._SC_TYPED_ARRAY_V1_MAX:
                length = data
                t2, d2, p2 = self._pair()
                self._value(t2, d2, p2)
                return f'<TypedArray (v1): {length} elements>'
            if tag == sc._SC_REGEXP_OBJECT:
                flags = data
                t2, d2, _ = self._pair()
                src = self._string(d2) if t2 == sc._SC_STRING else '<not string>'
                return f'/{src}/<flags={flags}>'
            if tag == sc._SC_ERROR_OBJECT:
                return '<Error>'
            return f'<unknown SCTAG 0x{tag:08x}>'

    # IDB key type prefixes from mozilla-central/dom/indexedDB/Key.cpp.
    _IDB_KEY_FLOAT = 0x10
    _IDB_KEY_DATE = 0x20
    _IDB_KEY_STRING = 0x30
    _IDB_KEY_BINARY = 0x40
    _IDB_KEY_ARRAY = 0x50
    _IDB_KEY_TERMINATOR = 0x00

    @classmethod
    def _decode_idb_key(cls, raw):
        # IDB key encoding: one-byte type prefix + sortable encoding.
        # We aim for a recognizable string, not perfect round-tripping.
        if not raw:
            return ''
        raw = bytes(raw)

        def _decode_one(buf, pos):
            if pos >= len(buf):
                return '', pos
            t = buf[pos]
            pos += 1
            if t == cls._IDB_KEY_STRING:
                chars = []
                while pos < len(buf):
                    b = buf[pos]
                    if b == 0:
                        pos += 1
                        break
                    if b <= 0x7F:
                        chars.append(chr(b - 1))
                        pos += 1
                    elif b <= 0xBF and pos + 1 < len(buf):
                        c = ((b & 0x3F) << 8) | buf[pos + 1]
                        chars.append(chr(c + 0x7F))
                        pos += 2
                    elif pos + 2 < len(buf):
                        c = ((b & 0x3F) << 10) | (buf[pos + 1] << 2) | (buf[pos + 2] >> 6)
                        chars.append(chr(c + 0x3FFF + 0x80))
                        pos += 3
                    else:
                        pos += 1
                return ''.join(chars), pos
            if t == cls._IDB_KEY_FLOAT or t == cls._IDB_KEY_DATE:
                if pos + 8 > len(buf):
                    return f'<truncated {t:02x}>', len(buf)
                # Big-endian with sign-bit flipped so negatives sort before positives; undo.
                raw8 = bytearray(buf[pos:pos + 8])
                pos += 8
                if raw8[0] & 0x80:
                    raw8[0] &= 0x7F
                else:
                    for i in range(8):
                        raw8[i] ^= 0xFF
                d = struct.unpack('>d', bytes(raw8))[0]
                if t == cls._IDB_KEY_DATE:
                    return f'<Date: {d} ms>', pos
                return repr(d), pos
            if t == cls._IDB_KEY_BINARY:
                end = buf.find(b'\x00', pos)
                if end == -1:
                    end = len(buf)
                chunk = buf[pos:end]
                return f'<binary: {chunk.hex()}>', end + 1
            if t == cls._IDB_KEY_ARRAY:
                items = []
                while pos < len(buf) and buf[pos] != cls._IDB_KEY_TERMINATOR:
                    item, pos = _decode_one(buf, pos)
                    items.append(item)
                if pos < len(buf):
                    pos += 1
                return '[' + ', '.join(items) + ']', pos
            return f'<unknown idb key type 0x{t:02x}: {buf[pos:].hex()}>', len(buf)

        try:
            value, _ = _decode_one(raw, 0)
            return value
        except Exception:
            return raw.hex()

    @staticmethod
    def _stringify_idb_value(obj, max_len=2000):
        try:
            s = json.dumps(obj, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            s = str(obj)
        if len(s) > max_len:
            s = s[:max_len] + f' ...[truncated {len(s) - max_len} chars]'
        return s

    def get_indexeddb(self, path):
        storage_root = os.path.join(path, 'storage', 'default')
        log.info(f'IndexedDB from {storage_root}:')
        if not os.path.isdir(storage_root):
            log.info(' - storage/default not present')
            return

        results = []
        idb_files_seen = 0
        idb_files_with_data = 0
        decode_failures = 0
        empty_blobs = 0

        for origin_folder in sorted(os.listdir(storage_root)):
            idb_dir = os.path.join(storage_root, origin_folder, 'idb')
            if not os.path.isdir(idb_dir):
                continue
            for db_filename in sorted(os.listdir(idb_dir)):
                if not db_filename.endswith('.sqlite'):
                    continue
                idb_files_seen += 1

                conn = utils.open_sqlite_db(self, idb_dir, db_filename)
                if not conn:
                    continue

                try:
                    cursor = conn.cursor()

                    origin = self._decode_origin_folder(origin_folder)
                    db_name = db_filename[:-len('.sqlite')]
                    try:
                        cursor.execute(
                            'SELECT origin, name FROM database LIMIT 1')
                        row = cursor.fetchone()
                        if row:
                            origin = row.get('origin') or origin
                            db_name = row.get('name') or db_name
                    except Exception:
                        pass

                    store_names = {}
                    try:
                        cursor.execute(
                            'SELECT id, name FROM object_store')
                        for r in cursor:
                            store_names[r.get('id')] = r.get('name') or ''
                    except Exception:
                        pass

                    try:
                        cursor.execute(
                            'SELECT object_store_id, key, data FROM object_data')
                    except Exception as e:
                        log.debug(f' - {db_filename}: object_data unreadable ({e})')
                        continue

                    source_path = os.path.relpath(
                        os.path.join(idb_dir, db_filename), self.profile_path)
                    seq = 0
                    got_any = False
                    for row in cursor:
                        seq += 1
                        store_id = row.get('object_store_id')
                        store_name = store_names.get(store_id, f'store_{store_id}')
                        key_blob = row.get('key')
                        data_blob = row.get('data')

                        key_str = self._decode_idb_key(key_blob) if key_blob else ''

                        value_str = ''
                        if data_blob:
                            try:
                                decompressed = self._snappy_decompress(bytes(data_blob))
                                reader = Firefox._StructuredCloneReader(self, decompressed)
                                value_obj = reader.read()
                                value_str = self._stringify_idb_value(value_obj)
                            except Exception as e:
                                decode_failures += 1
                                value_str = f'<decode failed: {e}>'
                        else:
                            empty_blobs += 1

                        item = Firefox.IndexedDBItem(
                            profile=self.profile_path,
                            origin=origin,
                            key=key_str,
                            value=value_str,
                            seq=seq,
                            state='Live',
                            database=f'{db_name}.{store_name}',
                            source_path=source_path,
                        )
                        results.append(item)
                        got_any = True
                    if got_any:
                        idb_files_with_data += 1
                finally:
                    conn.close()

        self.artifacts_counts['IndexedDB'] = len(results)
        log.info(
            f' - Parsed {len(results)} records from {idb_files_with_data} '
            f'IndexedDB files ({idb_files_seen} scanned, '
            f'{decode_failures} decode failures, {empty_blobs} empty blobs)'
        )
        self.parsed_storage.extend(results)

    def get_cache_storage(self, path):
        # Cache API (JS-visible, used by Service Workers) is distinct from cache2.
        # Each origin has cache/caches.sqlite + a morgue/<bucket>/<uuid>.final tree;
        # bucket is the last two hex chars of the body UUID parsed as decimal.
        storage_root = os.path.join(path, 'storage', 'default')
        log.info(f'Cache API storage from {storage_root}:')
        if not os.path.isdir(storage_root):
            log.info(' - storage/default not present')
            return

        results = []
        origins_seen = 0
        origins_with_data = 0
        missing_bodies = 0

        for origin_folder in sorted(os.listdir(storage_root)):
            cache_dir = os.path.join(storage_root, origin_folder, 'cache')
            db_file = os.path.join(cache_dir, 'caches.sqlite')
            if not os.path.isfile(db_file):
                continue
            origins_seen += 1
            morgue_dir = os.path.join(cache_dir, 'morgue')

            conn = utils.open_sqlite_db(self, cache_dir, 'caches.sqlite')
            if not conn:
                continue

            try:
                cursor = conn.cursor()

                origin = self._decode_origin_folder(origin_folder)

                # Cache names are UTF-16-LE BLOBs in storage.key.
                cache_names = {}
                try:
                    cursor.execute(
                        'SELECT cache_id, key FROM storage')
                    for row in cursor:
                        cid = row.get('cache_id')
                        key_bytes = row.get('key')
                        if key_bytes is None:
                            continue
                        try:
                            cache_names[cid] = bytes(key_bytes).decode(
                                'utf-16-le', errors='replace')
                        except Exception:
                            cache_names[cid] = f'<cache {cid}>'
                except Exception:
                    pass

                headers_by_entry = {}
                try:
                    cursor.execute(
                        'SELECT entry_id, name, value FROM response_headers')
                    for row in cursor:
                        eid = row.get('entry_id')
                        headers_by_entry.setdefault(eid, []).append(
                            (row.get('name'), row.get('value')))
                except Exception:
                    pass

                try:
                    cursor.execute(
                        'SELECT id, cache_id, request_method, '
                        '       request_url_no_query, request_url_query, '
                        '       request_referrer, response_status, '
                        '       response_status_text, response_body_id, '
                        '       response_body_disk_size '
                        'FROM entries'
                    )
                except Exception as e:
                    log.debug(f' - {origin_folder}: entries unreadable ({e})')
                    continue

                source_item = os.path.relpath(db_file, self.profile_path)
                got_any = False
                file_mtime = None
                try:
                    file_mtime = os.path.getmtime(db_file)
                except OSError:
                    pass

                for row in cursor:
                    eid = row.get('id')
                    cid = row.get('cache_id')
                    cache_name = cache_names.get(cid, f'cache_{cid}')

                    base_url = row.get('request_url_no_query') or ''
                    query = row.get('request_url_query') or ''
                    url = base_url + query

                    body_id = row.get('response_body_id') or ''
                    body_size = row.get('response_body_disk_size') or 0
                    body_path = ''
                    if body_id:
                        stripped = body_id.strip('{}')
                        if len(stripped) >= 2:
                            try:
                                bucket = int(stripped[-2:], 16)
                                cand = os.path.join(
                                    morgue_dir, str(bucket), f'{body_id}.final')
                                if os.path.isfile(cand):
                                    body_path = os.path.relpath(
                                        cand, self.profile_path)
                                else:
                                    missing_bodies += 1
                            except ValueError:
                                pass

                    headers = dict(headers_by_entry.get(eid, []))
                    content_type = headers.get('content-type', '')
                    etag = headers.get('etag', '') or ''
                    last_modified = headers.get('last-modified', '') or ''

                    if content_type and body_size:
                        data_summary = f'{content_type} ({body_size} bytes)'
                    elif content_type:
                        data_summary = content_type
                    elif body_size:
                        data_summary = f'{body_size} bytes'
                    else:
                        data_summary = '<no body>'

                    location_parts = [f'cache: {cache_name}']
                    if body_path:
                        location_parts.append(f'body: {body_path}')
                    elif body_id:
                        location_parts.append(f'body_id: {body_id} (file missing)')
                    locations = '; '.join(location_parts)

                    interp_parts = []
                    status = row.get('response_status')
                    status_text = row.get('response_status_text') or ''
                    method = row.get('request_method') or 'GET'
                    interp_parts.append(f'{method} -> {status} {status_text}'.strip())
                    referrer = row.get('request_referrer') or ''
                    if referrer:
                        interp_parts.append(f'Referrer: {referrer}')
                    interpretation = '; '.join(interp_parts)

                    if file_mtime:
                        request_time = datetime.datetime.fromtimestamp(
                            file_mtime, datetime.timezone.utc)
                        if self.timezone:
                            request_time = request_time.astimezone(self.timezone)
                    else:
                        request_time = datetime.datetime.fromtimestamp(
                            0, datetime.timezone.utc)

                    item = Firefox.CacheItem(
                        profile=self.profile_path,
                        url=url,
                        title=None,
                        request_time=request_time,
                        locations=locations,
                        key=body_id,
                        metadata=None,
                        data=None,
                    )
                    item.row_type = 'cache (Cache API)'
                    item.data_summary = data_summary
                    item.http_headers_str = str(headers) if headers else ''
                    item.etag = etag
                    item.last_modified = last_modified
                    item.interpretation = interpretation
                    item.source_item = source_item
                    results.append(item)
                    got_any = True

                if got_any:
                    origins_with_data += 1
            finally:
                conn.close()

        self.artifacts_counts['Cache API'] = len(results)
        log.info(
            f' - Parsed {len(results)} entries from {origins_with_data} '
            f'origins ({origins_seen} scanned, {missing_bodies} bodies '
            f'missing from morgue)'
        )
        self.parsed_artifacts.extend(results)

    def process(self):
        try:
            input_listing = os.listdir(self.profile_path)
        except OSError as e:
            log.error(f'Unable to read Firefox profile {self.profile_path}: {e}')
            return

        # Detect the schema version up front so the live display's profile panel
        # ("Detected Browser: Firefox v<schema>") is correct from the first frame.
        if 'places.sqlite' in input_listing:
            self.determine_version(self.profile_path, 'places.sqlite')

        # Firefox declares its own group labels; the shared driver (lifted to
        # WebBrowser) owns only the presentation. File-presence gating stays here.
        group_order = [
            "User Activity",
            "Website Storage",
            "Browser Extensions",
            "Configuration & Supporting Data",
        ]

        with self.processing_display(group_order) as driver:
            # User Activity
            driver.group("User Activity")
            if 'places.sqlite' in input_listing:
                driver.run(
                    'URL records', 'places.sqlite', self.get_history,
                    self.profile_path, 'places.sqlite',
                    display_key='places.sqlite', display_value='URL records')

                driver.run(
                    'Download records', 'places.sqlite_downloads', self.get_downloads,
                    self.profile_path, 'places.sqlite',
                    display_key='places.sqlite_downloads', display_value='Download records')

                driver.run(
                    'Bookmark records', 'Bookmarks', self.get_bookmarks,
                    self.profile_path, 'places.sqlite',
                    display_key='Bookmarks', display_value='Bookmark records')

            if 'formhistory.sqlite' in input_listing:
                driver.run(
                    'Form history records', 'formhistory.sqlite', self.get_form_history,
                    self.profile_path, 'formhistory.sqlite',
                    display_key='formhistory.sqlite', display_value='Form history records')

            if 'sessionstore.jsonlz4' in input_listing or 'sessionstore-backups' in input_listing:
                driver.run(
                    'Session (tab) records', 'Sessions', self.get_sessionstore,
                    self.profile_path,
                    display_key='Sessions', display_value='Session (tab) records')

            if 'bookmarkbackups' in input_listing:
                driver.run(
                    'Bookmark backup records', 'Bookmark Backups', self.get_bookmark_backups,
                    self.profile_path,
                    display_key='Bookmark Backups', display_value='Bookmark backup records')

            if 'favicons.sqlite' in input_listing:
                driver.run(
                    'Favicon-derived URL records', 'Favicons', self.get_favicons,
                    self.profile_path, 'favicons.sqlite',
                    display_key='Favicons', display_value='Favicon-derived URL records')

            # Website Storage
            driver.group("Website Storage")
            if 'cookies.sqlite' in input_listing:
                driver.run(
                    'Cookie records', 'Cookies', self.get_cookies,
                    self.profile_path, 'cookies.sqlite',
                    display_key='Cookies', display_value='Cookie records')

            if 'storage' in input_listing and os.path.isdir(
                    os.path.join(self.profile_path, 'storage', 'default')):
                driver.run(
                    'Local Storage records', 'Local Storage', self.get_local_storage,
                    self.profile_path,
                    display_key='Local Storage', display_value='Local Storage records')

                driver.run(
                    'IndexedDB records', 'IndexedDB', self.get_indexeddb,
                    self.profile_path,
                    display_key='IndexedDB', display_value='IndexedDB records')

                driver.run(
                    'Cache API records', 'Cache API', self.get_cache_storage,
                    self.profile_path,
                    display_key='Cache API', display_value='Cache API records')

            cache_dir = self._resolve_cache_dir()
            if cache_dir:
                driver.run(
                    'Cache records', 'Cache', self.get_cache,
                    cache_dir,
                    display_key='Cache', display_value='Cache records')
            else:
                log.info('No Firefox cache2 directory found; skipping cache parse.')

            # Browser Extensions
            driver.group("Browser Extensions")
            if 'extensions.json' in input_listing:
                driver.run(
                    'Installed Extensions', 'Extensions', self.get_extensions,
                    self.profile_path, 'extensions.json',
                    display_key='Extensions', display_value='Installed Extensions')

            # Configuration & Supporting Data
            driver.group("Configuration & Supporting Data")
            if 'prefs.js' in input_listing:
                driver.run(
                    'Preference items', 'Preferences', self.get_preferences,
                    self.profile_path, 'prefs.js',
                    display_key='Preferences', display_value='Preference items')

            if 'permissions.sqlite' in input_listing:
                driver.run(
                    'Permission records', 'Permissions', self.get_permissions,
                    self.profile_path, 'permissions.sqlite',
                    display_key='Permissions', display_value='Permission records')

            if 'SiteSecurityServiceState.bin' in input_listing:
                driver.run(
                    'HSTS records', 'HSTS', self.get_hsts,
                    self.profile_path, 'SiteSecurityServiceState.bin',
                    display_key='HSTS', display_value='HSTS records')

            if 'logins.json' in input_listing:
                driver.run(
                    'Saved login records', 'Logins', self.get_logins,
                    self.profile_path, 'logins.json',
                    display_key='Logins', display_value='Saved login records')

            if 'bounce-tracking-protection.sqlite' in input_listing:
                driver.run(
                    'Bounce-tracking records', 'Bounce Tracking', self.get_bounce_tracking,
                    self.profile_path, 'bounce-tracking-protection.sqlite',
                    display_key='Bounce Tracking', display_value='Bounce-tracking records')

            if 'protections.sqlite' in input_listing:
                driver.run(
                    'Content-blocking event records', 'Content Blocking', self.get_content_blocking,
                    self.profile_path, 'protections.sqlite',
                    display_key='Content Blocking', display_value='Content-blocking event records')

        self.parsed_artifacts.sort()

    class URLItem(WebBrowser.URLItem):
        pass

    class BookmarkItem(WebBrowser.BookmarkItem):
        pass

    class BookmarkFolderItem(WebBrowser.BookmarkFolderItem):
        pass

    class CookieItem(WebBrowser.CookieItem):
        pass

    class DownloadItem(WebBrowser.DownloadItem):
        pass

    class AutofillItem(WebBrowser.AutofillItem):
        pass

    class CacheItem(WebBrowser.CacheItem):
        pass

    class SiteSetting(WebBrowser.SiteSetting):
        pass

    class LoginItem(WebBrowser.LoginItem):
        pass

    class BrowserExtension(WebBrowser.BrowserExtension):
        pass

    class SessionItem(WebBrowser.SessionItem):
        pass

    class LocalStorageItem(WebBrowser.LocalStorageItem):
        pass

    class IndexedDBItem(WebBrowser.IndexedDBItem):
        pass
