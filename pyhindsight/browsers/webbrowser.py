import abc
import hashlib
import logging
import sqlite3
import sys
import urllib.parse
import rich.align
import rich.columns
import rich.console
import rich.live
import rich.panel
import rich.spinner
import rich.table
import rich.text
from pyhindsight import utils

log = logging.getLogger(__name__)


class ProcessingDisplay:
    """Live, grouped progress table shared across browsers.

    Obtained via ``WebBrowser.processing_display(group_order)`` and used as a
    context manager. Each browser's ``process()`` owns its own file-presence
    gating and group labels; this driver owns only the presentation (the
    ``rich.live`` table, spinner, and bracketed counts). It reads browser state
    (``artifacts_counts`` / ``artifacts_display`` / ``profile_path`` /
    ``browser_name`` / ``display_version``) but holds no parser-specific logic.

    Usage:
        with self.processing_display(["Group A", "Group B"]) as driver:
            driver.group("Group A")
            driver.run('URL', 'History', self.get_history, path, 'History', ...,
                       display_key='History', display_value='URL records')
    """

    count_width = 7
    table_width = 50  # Consistent width for tables and panel

    def __init__(self, browser, group_order):
        self.browser = browser
        self.group_order = list(group_order)
        self.current_group = self.group_order[0] if self.group_order else 'Artifacts'
        self.output_groups = {}
        self.console = rich.console.Console()
        self._live = None

    def __enter__(self):
        self._live = rich.live.Live(
            self._build_live_view(), console=self.console, refresh_per_second=4)
        self._live.__enter__()
        return self

    def __exit__(self, *exc_info):
        return self._live.__exit__(*exc_info)

    def group(self, name):
        """Set the group subsequent run() calls are bucketed under."""
        self.current_group = name

    def run(self, label, count_key, func, *args, display_key=None, display_value=None, **kwargs):
        """Show a spinner row, run the parser, then replace it with its count."""
        group_rows = self.output_groups.setdefault(self.current_group, [])
        display_label = display_value or self.browser.artifacts_display.get(display_key, label)
        group_rows.append((display_label, self._bracketed_spinner()))
        self._live.update(self._build_live_view())
        func(*args, **kwargs)
        if display_key and display_value:
            self.browser.artifacts_display[display_key] = display_value
        group_rows[-1] = (
            display_label, self._bracketed_count(self.browser.artifacts_counts.get(count_key, "0")))
        self._live.update(self._build_live_view())

    def _build_table(self, rows, header_label):
        # Header row as separate table with center alignment
        header = rich.table.Table(show_header=False, box=None, expand=False)
        header.add_column(justify="left", width=self.table_width - self.count_width - 8, style="bold on #333333")
        header.add_column(justify="center", width=self.count_width + 8, style="bold on #333333")
        header.add_row(rich.text.Text(header_label, style="bold"), rich.text.Text("Count", style="bold"))

        # Content table with right alignment
        table = rich.table.Table(show_header=False, box=None, expand=False)
        table.add_column(overflow="fold", justify="right", width=self.table_width - self.count_width - 8)
        table.add_column(justify="center", width=self.count_width + 8, no_wrap=True)
        for row_label, row_count in rows:
            table.add_row(row_label, row_count)
        return rich.console.Group(header, table)

    def _build_group_tables(self):
        tables = []
        for group_name in self.group_order:
            rows = self.output_groups.get(group_name, [])
            if not rows:
                continue
            inner_table = self._build_table(rows, group_name)
            tables.append(rich.align.Align.center(inner_table))
            tables.append(rich.text.Text(""))  # Padding between groups
        return rich.console.Group(*tables)

    def _build_profile_panel(self):
        # Use a table with min_width so panel can expand for long paths
        content = rich.table.Table(show_header=False, box=None, expand=False)
        content.add_column(min_width=self.table_width, overflow="fold")
        content.add_row(f"Path: {self.browser.profile_path}")
        content.add_row(f"Detected Browser: {self.browser.browser_name} v{self.browser.display_version}")
        return rich.align.Align.center(
            rich.panel.Panel(content, title="Profile", border_style="green", padding=(0, 2)))

    def _build_live_view(self):
        return rich.console.Group(self._build_profile_panel(), self._build_group_tables())

    def _bracketed_spinner(self):
        leading = " " * (self.count_width - 1)
        spinner = rich.columns.Columns(
            [rich.text.Text("  [ ", style="dim"), rich.text.Text(leading),
             rich.spinner.Spinner("dots", text="", style="green"), rich.text.Text(" ]  ", style="dim")],
            expand=False,
            equal=False,
            padding=(0, 0))
        return spinner

    def _bracketed_count(self, count):
        text = rich.text.Text()
        text.append("[ ", style="dim")
        if str(count) == "Failed":
            text.append(f"{count:>{self.count_width}}", style="red")
        elif str(count) == "0":
            text.append(f"{count:>{self.count_width}}", style="dim")
        else:
            text.append(f"{count:>{self.count_width}}")
        text.append(" ]", style="dim")
        return text


class WebBrowser(object):
    def __init__(
            self, profile_path, browser_name, cache_path=None, version=None, display_version=None,
            timezone=None, structure=None, no_copy=None, temp_dir=None):
        self.profile_path = profile_path
        self.browser_name = browser_name
        self.cache_path = cache_path
        self.version = version
        self.display_version = display_version
        self.timezone = timezone
        self.structure = structure
        self.parsed_artifacts = []
        self.parsed_storage = []
        self.parsed_extension_data = []
        self.parsed_sync_data = []
        self.artifacts_counts = {}
        self.artifacts_display = {}
        self.preferences = []
        self.no_copy = no_copy
        self.temp_dir = temp_dir
        self.origin_hashes = {}
        self.installed_extensions = {}

        if self.version is None:
            self.version = []

    @staticmethod
    def format_processing_output(name, items):
        width = 80
        left_side = width*0.55
        count = '{:>7}'.format(str(items))
        pretty_name = "{name:>{left_width}}:{count:^{right_width}}" \
            .format(name=name, left_width=int(left_side), count=' '.join(['[', count, ']']),
                    right_width=(width - int(left_side)-2))
        return pretty_name

    def processing_display(self, group_order):
        """Return a live, grouped progress display for use as a context manager.

        ``group_order`` is this browser's own ordered list of group labels. The
        browser's ``process()`` keeps full ownership of file-presence gating and
        which parsers run; this only drives the shared presentation. See
        ``ProcessingDisplay``.
        """
        return ProcessingDisplay(self, group_order)

    @staticmethod
    def format_profile_path(profile_path):
        if len(profile_path) > 68:
            profile_path = "...{}".format(profile_path[-65:])
        return "\n    Profile: {}".format(profile_path)

    def build_structure(self, path, database):

        if database not in list(self.structure.keys()):
            self.structure[database] = {}

            # Copy and connect to copy of SQLite DB
            conn = utils.open_sqlite_db(self, path, database)
            if not conn:
                self.artifacts_counts[database] = 'Failed'
                return
            try:
                cursor = conn.cursor()

                # Find the names of each table in the db
                try:
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = cursor.fetchall()
                except sqlite3.OperationalError:
                    print("\nSQLite3 error; is the Chrome profile in use?  Hindsight cannot access history files "
                          "if Chrome has them locked.  This error most often occurs when trying to analyze a local "
                          "Chrome installation while it is running.  Please close Chrome and try again.")
                    sys.exit(1)
                except:
                    log.error(f' - Could not query {database} in {path}')
                    return

                # For each table, find all the columns in it
                for table in tables:
                    # cursor.execute('PRAGMA table_info({})'.format(str(table[0])))
                    cursor.execute('PRAGMA table_info({})'.format(table['name']))
                    columns = cursor.fetchall()

                    # Create a dict of lists of the table/column names
                    # self.structure[database][str(table[0])] = []
                    self.structure[database][table['name']] = []
                    for column in columns:
                        self.structure[database][table['name']].append(column['name'])
            finally:
                conn.close()

    @staticmethod
    def dict_factory(cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def get_clean_hostnames(self):
        hostnames = set()
        for artifact in self.parsed_artifacts:
            if not isinstance(artifact, self.HistoryItem) or not artifact.url:
                continue

            # Some artifact "URLs", often parsed from Preferences, are two
            # origins combined, so split them into two.
            # Example from Preferences (3pcd_heuristics_grants):
            #   "https://[*.]lnkd.in,https://[*.]linkedin.com"
            artifact_urls = artifact.url.split(',')

            for artifact_url in artifact_urls:
                # Some artifact "URLs" will be in invalid forms, which urllib (rightly)
                # won't parse. Modify these URLs so they will parse properly.
                # Examples:
                #   Cookie: ".example.com",
                #   Preferences (cookie_controls_metadata): "https://[*.]example.com"
                prefixes = ('.', 'https://[*.]', 'http://[*.]')

                for prefix in prefixes:
                    if artifact_url.startswith(prefix):
                        artifact_url = 'https://' + artifact_url[len(prefix):]

                if artifact_url.endswith(',*'):
                    artifact_url = artifact_url[:-2]

                try:
                    hostname = urllib.parse.urlparse(artifact_url).hostname
                except ValueError as e:
                    log.warning(f'Error when parsing domain from {artifact_url}; {e}')
                    continue

                # Some URLs don't have a domain, like local PDF files
                if hostname:
                    hostnames.add(hostname)
        return hostnames

    def build_md5_hash_list_of_origins(self):
        domains = self.get_clean_hostnames()
        for domain in domains:
            self.origin_hashes[hashlib.md5(domain.encode()).hexdigest()] = domain

    def get_extension_name_from_id(self, extension_id):
        if self.installed_extensions and self.installed_extensions.get('data'):
            for extension in self.installed_extensions['data']:
                if extension.ext_id == extension_id:
                    if extension.name:
                        return extension.name
                    # Unpacked extensions cache no manifest in Secure Prefs, so the name
                    # often isn't recoverable from the profile alone — surface the source
                    # path instead (the lead an examiner needs to recover the name).
                    if getattr(extension, 'path', None):
                        return f"<unpacked - {extension.path}>"
                    return extension.name
            return "<Extension not found - may have been uninstalled>"
        return "<Unable to parse installed extensions>"

    class HistoryItem(object):
        def __init__(self, item_type, timestamp, profile, url=None, name=None, value=None, interpretation=None):
            self.row_type = item_type
            self.timestamp = timestamp
            self.profile = profile
            self.url = url
            self.name = name
            self.value = value
            self.interpretation = interpretation
            self.source_item = None

        def __lt__(self, other):
            if not self.timestamp.tzinfo and other.timestamp.tzinfo:
                log.warning(f'{self} missing tzinfo; using tzinfo from {other} during sort')
                self.timestamp = self.timestamp.replace(tzinfo=other.timestamp.tzinfo)
            elif self.timestamp.tzinfo and not other.timestamp.tzinfo:
                log.warning(f'{other} missing tzinfo; using tzinfo from {self} during sort')
                other.timestamp = other.timestamp.replace(tzinfo=self.timestamp.tzinfo)

            return self.timestamp < other.timestamp

        def __iter__(self):
            return iter(self.__dict__)

    class URLItem(HistoryItem):
        def __init__(
                self, profile, visit_id, url, title, visit_time, last_visit_time, visit_count, typed_count, from_visit,
                transition, hidden, favicon_id, indexed=None, visit_duration=None, visit_source=None,
                transition_friendly=None, is_known_to_sync=None, originator_cache_guid=None, opener_visit=None,
                category_ids=None, entity_ids=None, cluster_id=None, cluster_label=None,
                response_code=None, tab_id=None, window_id=None):
            super(WebBrowser.URLItem, self).__init__('url', timestamp=visit_time, profile=profile, url=url, name=title)
            self.profile = profile
            self.url = url
            self.title = title
            self.visit_time = visit_time
            self.last_visit_time = last_visit_time
            self.visit_count = visit_count
            self.typed_count = typed_count
            self.transition = transition
            self.hidden = hidden
            self.favicon_id = favicon_id
            self.indexed = indexed
            self.visit_id = visit_id
            self.from_visit = from_visit
            self.visit_duration = visit_duration
            self.visit_source = visit_source
            self.transition_friendly = transition_friendly
            self.is_known_to_sync = is_known_to_sync
            self.originator_cache_guid = originator_cache_guid
            self.opener_visit = opener_visit
            self.category_ids = category_ids
            self.entity_ids = entity_ids
            self.category_names = None
            self.entity_names = None
            self.categories_str = None
            self.entities_str = None
            self.cluster_str = None
            self.cluster_id = cluster_id
            self.cluster_label = cluster_label
            self.response_code = response_code
            self.tab_id = tab_id
            self.window_id = window_id

    class CacheItem(HistoryItem):
        def __init__(
                self, profile, url, title, request_time, locations, key, metadata, data):
            super(WebBrowser.CacheItem, self).__init__('cache', timestamp=request_time, profile=profile, url=url, name=title)
            self.profile = profile
            self.url = url
            self.title = title
            self.locations = locations
            self.key = key
            self.metadata = metadata
            self.data = data
            self.data_summary = None
            self.http_headers_str = None
            self.etag = None
            self.last_modified = None
            self.locations_str = None

        def create_data_summary(self):
            if not self.data:
                return "<no data>"

            if not self.metadata:
                return f"{len(self.data)} bytes"

            return f"{(self.metadata.get_attribute('content-type') or ['not specified'])[0]} ({len(self.data)} bytes)"

        def stringify_http_headers(self):
            headers = {}
            for attribute, value in self.metadata.http_header_attributes:
                headers[attribute] = value

            self.http_headers_str = str(headers)

    class DownloadItem(HistoryItem):
        def __init__(
                self, profile, download_id, url, received_bytes, total_bytes, state, full_path=None, start_time=None,
                end_time=None, target_path=None, current_path=None, opened=None, danger_type=None,
                interrupt_reason=None, etag=None, last_modified=None, chain_index=None, interrupt_reason_friendly=None,
                danger_type_friendly=None, state_friendly=None, status_friendly=None,
                guid=None, hash=None, http_method=None, referrer=None, site_url=None, tab_url=None,
                tab_referrer_url=None, mime_type=None, original_mime_type=None, last_access_time=None,
                transient=None, by_ext_id=None, by_ext_name=None, by_web_app_id=None,
                embedder_download_data=None, download_source=None, url_chain=None,
                request_headers=None, fetched_via_service_worker=None, storage_partition=None):
            super(WebBrowser.DownloadItem, self).__init__('download', timestamp=start_time, profile=profile, url=url)
            self.profile = profile
            self.download_id = download_id
            self.url = url
            self.received_bytes = received_bytes
            self.total_bytes = total_bytes
            self.state = state
            self.full_path = full_path
            self.start_time = start_time
            self.end_time = end_time
            self.target_path = target_path
            self.current_path = current_path
            self.opened = opened
            self.danger_type = danger_type
            self.interrupt_reason = interrupt_reason
            self.etag = etag
            self.last_modified = last_modified
            self.chain_index = chain_index
            self.interrupt_reason_friendly = interrupt_reason_friendly
            self.danger_type_friendly = danger_type_friendly
            self.state_friendly = state_friendly
            self.status_friendly = status_friendly
            # Additional columns present in newer History `downloads` schemas (see the
            # column->version map in get_downloads).
            self.guid = guid
            self.hash = hash
            self.http_method = http_method
            self.referrer = referrer
            self.site_url = site_url
            self.tab_url = tab_url
            self.tab_referrer_url = tab_referrer_url
            self.mime_type = mime_type
            self.original_mime_type = original_mime_type
            self.last_access_time = last_access_time
            self.transient = transient
            self.by_ext_id = by_ext_id
            self.by_ext_name = by_ext_name
            self.by_web_app_id = by_web_app_id
            self.embedder_download_data = embedder_download_data
            # How the download was triggered (download_pb.DownloadSource); only available
            # from shared_proto_db's ukm_info, not the History downloads table.
            self.download_source = download_source
            # shared_proto_db-only extras (not in the History downloads table):
            self.url_chain = url_chain                          # full redirect chain (list)
            self.request_headers = request_headers              # outbound HTTP headers (dict)
            self.fetched_via_service_worker = fetched_via_service_worker
            self.storage_partition = storage_partition          # non-default partition (extension/isolated)

    class CookieItem(HistoryItem):
        def __init__(self, profile, host_key, path, name, value, creation_utc, last_access_utc, secure, http_only,
                     persistent=None, has_expires=None, expires_utc=None, priority=None, top_frame_site_key=None,
                     last_update_utc=None):
            super(WebBrowser.CookieItem, self).__init__(
                'cookie', timestamp=creation_utc, profile=profile, url=host_key, name=name, value=value)
            self.profile = profile
            self.host_key = host_key
            self.path = path
            self.name = name
            self.value = value
            self.creation_utc = creation_utc
            self.last_access_utc = last_access_utc
            self.last_update_utc = last_update_utc
            self.secure = secure
            self.httponly = http_only
            self.persistent = persistent
            self.has_expires = has_expires
            self.expires_utc = expires_utc
            self.priority = priority
            self.top_frame_site_key = top_frame_site_key

    class AutofillItem(HistoryItem):
        def __init__(self, profile, date_created, name, value, count):
            super(WebBrowser.AutofillItem, self).__init__(
                'autofill', timestamp=date_created, profile=profile, name=name, value=value)
            self.profile = profile
            self.date_created = date_created
            self.name = name
            self.value = value
            self.count = count

    class BookmarkItem(HistoryItem):
        def __init__(self, profile, date_added, name, url, parent_folder, sync_transaction_version=None):
            super(WebBrowser.BookmarkItem, self).__init__(
                'bookmark', timestamp=date_added, profile=profile, name=name, value=parent_folder)
            self.profile = profile
            self.date_added = date_added
            self.name = name
            self.url = url
            self.parent_folder = parent_folder
            self.sync_transaction_version = sync_transaction_version

    class BookmarkFolderItem(HistoryItem):
        def __init__(self, profile, date_added, date_modified, name, parent_folder, sync_transaction_version=None):
            super(WebBrowser.BookmarkFolderItem, self).__init__(
                'bookmark folder', timestamp=date_added, profile=profile, name=name, value=parent_folder)
            self.profile = profile
            self.date_added = date_added
            self.date_modified = date_modified
            self.name = name
            self.parent_folder = parent_folder
            self.sync_transaction_version = sync_transaction_version

    class BrowserExtension(object):
        def __init__(self, profile, ext_id, name, description, version, permissions, manifest,
                     on_disk=False, in_secure_prefs=False, install_time=None, update_time=None,
                     location=None, state=None, from_webstore=None, was_installed_by_default=None,
                     granted_scriptable_host=None, withholding_scriptable_host=None,
                     runtime_granted_scriptable_host=None, content_scripts=None):
            self.profile = profile
            self.ext_id = ext_id
            self.name = name
            self.description = description
            self.version = version
            # Manifest-declared permissions. Chrome stores the parsed manifest list
            # (or None); Firefox stores a compact JSON-string summary. Serialized to
            # a string only at the SQLite output boundary.
            self.permissions = permissions
            self.manifest = manifest
            # Presence: whether the extension was found unpacked on disk (Extensions/<id>/),
            # registered in Secure Preferences (extensions.settings.<id>), or both.
            self.on_disk = on_disk
            self.in_secure_prefs = in_secure_prefs
            # Fields sourced from Secure Preferences (extensions.settings.<id>)
            self.install_time = install_time
            self.update_time = update_time
            self.location = location
            self.state = state
            # Source folder for unpacked (developer-mode) extensions. Such extensions
            # cache no manifest in Secure Preferences — only this path to the live
            # source dir — so name/version often can't be resolved from the profile alone.
            self.path = None
            self.from_webstore = from_webstore
            self.was_installed_by_default = was_installed_by_default
            # Host scope the extension can actually inject content scripts into
            self.granted_scriptable_host = granted_scriptable_host or []
            self.withholding_scriptable_host = withholding_scriptable_host or []
            self.runtime_granted_scriptable_host = runtime_granted_scriptable_host or []
            # API permissions actually granted / withheld / granted at runtime
            # (Secure Preferences granted_permissions.api etc.), which can differ
            # from the manifest-declared set above.
            self.granted_api = []
            self.withholding_api = []
            self.runtime_granted_api = []
            # Host scope for cross-origin API access (fetch/XHR from extension
            # contexts) — 'explicit_host', distinct from scriptable_host (injection).
            self.granted_explicit_host = []
            self.withholding_explicit_host = []
            self.runtime_granted_explicit_host = []
            # List of declared content script blocks (from the manifest)
            self.content_scripts = content_scripts or []
            # Dynamically registered scripts from the 'Extension Scripts' StateStore
            # (chrome.scripting.registerContentScripts / chrome.userScripts), normalized
            # to the same shape as content_scripts with an added 'kind' tag.
            self.dynamic_scripts = []
            # Dynamic scripts carved from superseded / deleted LevelDB records that are no
            # longer in the current live set (registered at some point, then removed). May
            # be partial if recovered from a truncated record.
            self.historical_dynamic_scripts = []

        @property
        def source(self):
            """Human-readable presence indicator used in reporting."""
            if self.on_disk and self.in_secure_prefs:
                return 'Disk + Secure Prefs'
            if self.in_secure_prefs:
                return 'Secure Prefs only'
            if self.on_disk:
                return 'Disk only'
            return 'Unknown'

    class LoginItem(HistoryItem):
        def __init__(self, profile, date_created, url, name, value, count, interpretation):
            super(WebBrowser.LoginItem, self).__init__(
                'login', timestamp=date_created, profile=profile, url=url, name=name, value=value)
            self.profile = profile
            self.date_created = date_created
            self.url = url
            self.name = name
            self.value = value
            self.count = count
            self.interpretation = interpretation

    class PreferenceItem(HistoryItem):
        def __init__(self, profile, url, timestamp, key, value, interpretation):
            super(WebBrowser.PreferenceItem, self).__init__(
                'preference', timestamp=timestamp, profile=profile, name=key, value=value)
            self.profile = profile
            self.url = url
            self.timestamp = timestamp
            self.key = key
            self.value = value
            self.interpretation = interpretation

    class SiteSetting(HistoryItem):
        def __init__(self, profile, url, timestamp, key, value, interpretation):
            super(WebBrowser.SiteSetting, self).__init__(
                'site setting', timestamp=timestamp, profile=profile, name=key, value=value)
            self.profile = profile
            self.url = url
            self.timestamp = timestamp
            self.key = key
            self.value = value
            self.interpretation = interpretation

    class MediaItem(HistoryItem):
        def __init__(
                self, profile, url, title, last_updated, position=None, media_duration=None,
                source_title=None, watch_time=None, has_video=None, has_audio=None):
            super(WebBrowser.MediaItem, self).__init__(
                'media', timestamp=last_updated, profile=profile, url=url, name=title)
            self.profile = profile
            self.url = url
            self.title = title
            self.last_updated = last_updated
            self.position = position
            self.media_duration = media_duration
            self.source_title = source_title
            self.watch_time = watch_time
            self.has_video = has_video
            self.has_audio = has_audio

    class SessionItem(HistoryItem):
        def __init__(
                self, profile, url, title, timestamp, session_id=None, nav_index=None,
                transition_type=None, transition_type_raw=None, referrer_url=None,
                original_request_url=None, http_status=None, has_post_data=None,
                source_path=None, page_state=None):
            super(WebBrowser.SessionItem, self).__init__(
                'session (navigation)', timestamp=timestamp, profile=profile, url=url,
                name=title, value=transition_type)
            self.profile = profile
            self.url = url
            self.title = title
            self.session_id = session_id
            self.nav_index = nav_index
            self.transition_type = transition_type
            self.transition_type_raw = transition_type_raw
            self.referrer_url = referrer_url
            self.original_request_url = original_request_url
            self.http_status = http_status
            self.has_post_data = has_post_data
            self.source_path = source_path
            self.page_state = page_state

        def decode_transition(self):
            self.transition_type = utils.decode_page_transition(self.transition_type_raw)

    class StorageItem(object):
        def __init__(self, item_type, profile, origin, key, value=None, seq=None, state=None, source_path=None,
                     last_modified=None, interpretation=None, file_exists=None, file_size=None, magic_results=None):
            self.row_type = item_type
            self.profile = profile
            self.origin = origin
            self.key = key
            self.value = value
            self.seq = seq
            self.state = state
            self.source_path = source_path
            self.last_modified = last_modified
            self.interpretation = interpretation
            self.file_exists = file_exists
            self.file_size = file_size
            self.magic_results = magic_results

        def __lt__(self, other):
            return self.origin < other.origin

        def __iter__(self):
            return iter(self.__dict__)

    class ExtensionStorageItem(StorageItem):
        def __init__(self, profile, extension_id, key, value, extension_name=None, seq=None, state=None, source_path=None, offset=None, was_compressed=None):
            super(WebBrowser.ExtensionStorageItem, self).__init__(
                item_type='extension storage', profile=profile, origin=extension_id, key=key, value=value, seq=seq, state=state, source_path=source_path
            )
            self.profile = profile
            self.extension_id = extension_id
            self.extension_name = extension_name
            self.key = key
            self.value = value
            self.seq = seq
            self.state = state
            self.source_path = source_path
            self.offset = offset
            self.was_compressed = was_compressed

    class SyncDataItem(object):
        def __init__(
                self, profile, key, value, row_type='sync data', interpretation=None, source_path=None,
                offset=None, seq=None, state=None, file_type=None):
            self.row_type = row_type
            self.profile = profile
            self.key = key
            self.value = value
            self.interpretation = interpretation
            self.source_path = source_path
            self.offset = offset
            self.seq = seq
            self.state = state
            self.file_type = file_type

    class LocalStorageItem(StorageItem):
        def __init__(self, profile, origin, key, value, seq, state, source_path, last_modified=None):
            """

            :param profile: The path to the browser profile this item is part of.
            :param origin: The web origin this LocalStorage item belongs to.
            :param key: The key of the LocalStorage item.
            :param value: The value of the LocalStorage item. It will be rendered in UTF-16 if possible; if not, it
            will be shown as a string repr of bytes.
            :param seq: The sequence number of the key.
            :param state: The state of the record (live or deleted).
            :param source_path: The path to the source of the record.
            :param last_modified: Approximation of time content under this origin was last modified.
            If the LocalStorage items were stored in SQLite, this timestamp is when that SQLite file was last modified.
            This means copying the file or otherwise altering the LocalStorage SQLite file's metadata will change this
            value.
            If the LocalStorage items were stored in LevelDB, this will be blank.
            """
            super(WebBrowser.LocalStorageItem, self).__init__(
                'local storage', profile=profile, origin=origin, key=key, value=value, seq=seq, state=state,
                source_path=source_path, last_modified=last_modified)
            self.profile = profile
            self.origin = origin
            self.key = key
            self.value = value
            self.seq = seq
            self.state = state
            self.source_path = source_path
            self.last_modified = last_modified

    class SessionStorageItem(StorageItem):
        def __init__(self, profile, origin, key, value, seq, state, source_path):
            """

            :param profile: The path to the browser profile this item is part of.
            :param origin: The web origin this SessionStorage item belongs to.
            :param key: The key of the SessionStorage item.
            :param value: The value of the SessionStorage item (rendered in UTF-16).
            :param seq: The sequence number of the key.
            :param state: The state of the record (live or deleted).
            :param source_path: The path to the source of the record.
            """
            super(WebBrowser.SessionStorageItem, self).__init__(
                'session storage', profile=profile, origin=origin, key=key, value=value, seq=seq, state=state,
                source_path=source_path)
            self.profile = profile
            self.origin = origin
            self.key = key
            self.value = value
            self.seq = seq
            self.state = state
            self.source_path = source_path

    class IndexedDBItem(StorageItem):
        def __init__(self, profile, origin, key, value, seq, state, database, source_path):
            """

            :param profile: The path to the browser profile this item is part of.
            :param origin: The web origin this IndexedDBItem item belongs to.
            :param key: The key of the IndexedDBItem item.
            :param value: The value of the IndexedDBItem item.
            :param seq: The sequence number.
            :param database: The database within the IndexedDB file the record is part of.
            :param source_path: The path to the source of the record.
            """
            super(WebBrowser.IndexedDBItem, self).__init__(
                'indexeddb', profile=profile, origin=origin, key=key, value=value, seq=seq, state=state,
                source_path=source_path)
            self.profile = profile
            self.origin = origin
            self.key = key
            self.value = value
            self.seq = seq
            self.state = state
            self.database = database
            self.source_path = source_path

    class FileSystemItem(StorageItem):
        def __init__(self, profile, origin, key, value, seq, state, source_path, last_modified=None,
                     file_exists=None, file_size=None, magic_results=None):
            super(WebBrowser.FileSystemItem, self).__init__(
                'file system', profile=profile, origin=origin, key=key, value=value, seq=seq, state=state,
                source_path=source_path, last_modified=last_modified, file_exists=file_exists,
                file_size=file_size, magic_results=magic_results)
            self.profile = profile
            self.origin = origin
            self.key = key
            self.value = value
            self.seq = seq
            self.state = state
            self.source_path = source_path
            self.last_modified = last_modified
            self.file_exists = file_exists
            self.file_size = file_size
            self.magic_results = magic_results

    class ServiceWorkerUserDataItem(StorageItem):
        def __init__(self, profile, scope_url, registration_id, user_data_key,
                     subsystem, decoded_value, raw_value_size, seq, state, source_path,
                     event_time=None):
            super(WebBrowser.ServiceWorkerUserDataItem, self).__init__(
                'service worker (user data)', profile=profile, origin=scope_url or '',
                key=user_data_key, value=decoded_value, seq=seq, state=state,
                source_path=source_path, interpretation=subsystem,
                last_modified=event_time)
            self.scope_url = scope_url
            self.registration_id = registration_id
            self.user_data_key = user_data_key
            self.subsystem = subsystem
            self.raw_value_size = raw_value_size
            self.event_time = event_time

    class ServiceWorkerCacheStorageItem(StorageItem):
        def __init__(self, profile, storage_key, origin_hash, cache_name, cache_uuid,
                     request_url, request_method, response_status, response_status_text,
                     response_type, response_mime_type, final_url, body_size, body_sha256,
                     entry_time, response_time, source_file, source_path):
            value_parts = []
            if request_method:
                value_parts.append(f'method={request_method}')
            if response_status is not None:
                value_parts.append(f'status={response_status} {response_status_text}'.strip())
            if response_type:
                value_parts.append(f'response_type={response_type}')
            if response_mime_type:
                value_parts.append(f'mime_type={response_mime_type}')
            if body_size is not None:
                value_parts.append(f'body_size={body_size}')
            if body_sha256:
                value_parts.append(f'sha256={body_sha256}')
            if cache_name:
                value_parts.append(f'cache_name={cache_name!r}')
            if final_url:
                value_parts.append(f'final_url={final_url}')
            super(WebBrowser.ServiceWorkerCacheStorageItem, self).__init__(
                'service worker (cache storage)', profile=profile,
                origin=storage_key or origin_hash or '', key=request_url,
                value='; '.join(value_parts), state='Live', source_path=source_path,
                last_modified=entry_time)
            self.storage_key = storage_key
            self.origin_hash = origin_hash
            self.cache_name = cache_name
            self.cache_uuid = cache_uuid
            self.request_url = request_url
            self.request_method = request_method
            self.response_status = response_status
            self.response_status_text = response_status_text
            self.response_type = response_type
            self.response_mime_type = response_mime_type
            self.final_url = final_url
            self.body_size = body_size
            self.body_sha256 = body_sha256
            self.entry_time = entry_time
            self.response_time = response_time
            self.source_file = source_file

    class ServiceWorkerScriptItem(StorageItem):
        def __init__(self, profile, scope_url, version_id, resource_id, url,
                     http_status, content_type, body_size, body_sha256,
                     body_sha256_match, response_time, request_time,
                     source_file, source_path):
            value_parts = [f'resource_id={resource_id}']
            if version_id is not None:
                value_parts.append(f'version_id={version_id}')
            if http_status:
                value_parts.append(f'http_status={http_status}')
            if content_type:
                value_parts.append(f'content_type={content_type}')
            if body_size is not None:
                value_parts.append(f'body_size={body_size}')
            if body_sha256:
                value_parts.append(f'sha256={body_sha256}')
            if body_sha256_match is True:
                value_parts.append('sha256_match=ldb')
            elif body_sha256_match is False:
                value_parts.append('sha256_match=MISMATCH')
            super(WebBrowser.ServiceWorkerScriptItem, self).__init__(
                'service worker (script body)', profile=profile, origin=scope_url or '',
                key=url or f'resource_id={resource_id}', value='; '.join(value_parts),
                state='Live', source_path=source_path, last_modified=response_time)
            self.scope_url = scope_url
            self.version_id = version_id
            self.resource_id = resource_id
            self.url = url
            self.http_status = http_status
            self.content_type = content_type
            self.body_size = body_size
            self.body_sha256 = body_sha256
            self.body_sha256_match = body_sha256_match
            self.response_time = response_time
            self.request_time = request_time
            self.source_file = source_file

    class ServiceWorkerResourceItem(StorageItem):
        def __init__(self, profile, scope_url, version_id, resource_id, url, size_bytes,
                     sha256_checksum, resource_state, seq, state, source_path):
            value_parts = [f'resource_state={resource_state}', f'resource_id={resource_id}']
            if version_id is not None:
                value_parts.append(f'version_id={version_id}')
            if size_bytes is not None:
                value_parts.append(f'size_bytes={size_bytes}')
            if sha256_checksum:
                value_parts.append(f'sha256={sha256_checksum}')
            display_key = url if url else f'resource_id={resource_id}'
            super(WebBrowser.ServiceWorkerResourceItem, self).__init__(
                'service worker (resource)', profile=profile, origin=scope_url or '',
                key=display_key, value='; '.join(value_parts), seq=seq, state=state,
                source_path=source_path)
            self.scope_url = scope_url
            self.version_id = version_id
            self.resource_id = resource_id
            self.url = url
            self.size_bytes = size_bytes
            self.sha256_checksum = sha256_checksum
            self.resource_state = resource_state

    class ServiceWorkerItem(StorageItem):
        def __init__(self, profile, origin, scope_url, script_url, registration_id, version_id,
                     is_active, has_fetch_handler, last_update_check_time, resources_total_size_bytes,
                     navigation_preload_enabled, navigation_preload_header, update_via_cache,
                     script_type, script_response_time, seq, state, source_path):
            value_parts = [f'registration_id={registration_id}', f'version_id={version_id}']
            if is_active is not None:
                value_parts.append(f'is_active={is_active}')
            if has_fetch_handler is not None:
                value_parts.append(f'has_fetch_handler={has_fetch_handler}')
            if resources_total_size_bytes is not None:
                value_parts.append(f'resources_total_size_bytes={resources_total_size_bytes}')
            if navigation_preload_enabled is not None:
                value_parts.append(f'navigation_preload_enabled={navigation_preload_enabled}')
            if navigation_preload_header:
                value_parts.append(f'navigation_preload_header={navigation_preload_header}')
            if update_via_cache is not None:
                value_parts.append(f'update_via_cache={update_via_cache}')
            if script_type is not None:
                value_parts.append(f'script_type={script_type}')
            if script_response_time is not None:
                value_parts.append(f'script_response_time={script_response_time}')
            super(WebBrowser.ServiceWorkerItem, self).__init__(
                'service worker (registration)', profile=profile, origin=origin, key=script_url,
                value='; '.join(value_parts), seq=seq, state=state, source_path=source_path,
                last_modified=last_update_check_time)
            self.scope_url = scope_url
            self.script_url = script_url
            self.registration_id = registration_id
            self.version_id = version_id
            self.is_active = is_active
            self.has_fetch_handler = has_fetch_handler
            self.resources_total_size_bytes = resources_total_size_bytes
            self.navigation_preload_enabled = navigation_preload_enabled
            self.navigation_preload_header = navigation_preload_header
            self.update_via_cache = update_via_cache
            self.script_type = script_type
            self.script_response_time = script_response_time
