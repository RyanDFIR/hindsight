# -*- coding: utf-8 -*-
import copy
import hashlib
from contextlib import contextmanager
import math
import os
import pathlib
import sqlite3
import struct
import sys
import datetime
import re
import json
import logging
import shutil
import puremagic
import base64
import ccl_chromium_reader

from pyhindsight.browsers.webbrowser import WebBrowser
from pyhindsight import utils

# Try to import optional modules - do nothing on failure, as status is tracked elsewhere
try:
    import win32crypt
except ImportError:
    pass

try:
    import keyring
except ImportError:
    pass

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
except ImportError:
    pass

log = logging.getLogger(__name__)


class Chrome(WebBrowser):
    def __init__(self, profile_path, browser_name=None, cache_path=None, version=None, timezone=None,
                 storage=None, available_decrypts=None, no_copy=None, temp_dir=None,
                 originator_guids=None):
        WebBrowser.__init__(
            self, profile_path, browser_name=browser_name, cache_path=cache_path, version=version, timezone=timezone,
            no_copy=no_copy, temp_dir=temp_dir)
        self.profile_path = profile_path
        # Honor a variant passed by the caller (e.g. "Edge", "Brave", "Vivaldi");
        # all Chromium variants currently share this parser and differ only in variant.
        self.browser_name = browser_name or "Chrome"
        self.cache_path = cache_path
        self.timezone = timezone
        self.installed_extensions = {}
        # Per-extension records keyed by ext_id, merged from the on-disk Extensions/
        # directory (get_extensions) and Secure Preferences (get_extension_settings).
        # Merge is order-independent; installed_extensions['data'] is rebuilt from this.
        self._extensions_by_id = {}
        self.cached_key = None
        self.available_decrypts = available_decrypts
        self.storage = storage
        self.no_copy = no_copy
        self.temp_dir = temp_dir
        self.hsts_hashes = {}
        self.kg_entities = {}
        self.originator_guids = originator_guids

        if self.originator_guids is None:
            self.originator_guids = {}

        if self.preferences is None:
            self.preferences = []

        if self.storage is None:
            self.storage = {}

        if self.structure is None:
            self.structure = {}

        if self.version is None:
            self.version = []

        if self.available_decrypts is None:
            self.available_decrypts = {'windows': 0, 'mac': 0, 'linux': 0}

        if self.available_decrypts['windows'] == 1:
            import win32crypt

        if self.available_decrypts['mac'] == 1:
            import keyring
            from Cryptodome.Cipher import AES
            from Cryptodome.Protocol.KDF import PBKDF2

        if self.available_decrypts['linux'] == 1:
            from Cryptodome.Cipher import AES
            from Cryptodome.Protocol.KDF import PBKDF2

    def determine_version(self):
        """Determine the version of Chrome databases files by looking for combinations of columns in certain tables.
        Based on research I did to create "Chrome Evolution" tool - dfir.blog/chrome-evolution
        """

        possible_versions = list(range(1, 148))
        previous_possible_versions = possible_versions[:]

        def update_and_rollback_if_empty(version_list, prev_version_list):
            if len(version_list) == 0:
                version_list = prev_version_list[:]
                log.warning('Last version structure check eliminated all possible versions; skipping that file.')
            else:
                prev_version_list = version_list[:]
            return version_list, prev_version_list

        def trim_lesser_versions_if(column, table, version):
            """Remove version numbers < 'version' from 'possible_versions' if 'column' isn't in 'table', and keep
            versions >= 'version' if 'column' is in 'table'.
            """
            if table:
                if column in table:
                    possible_versions[:] = [x for x in possible_versions if x >= version]
                else:
                    possible_versions[:] = [x for x in possible_versions if x < version]

        def trim_greater_versions_if(column, table, version):
            """Remove version numbers > 'version' from 'possible_versions' if 'column' isn't in 'table', and keep
            versions =< 'version' if 'column' is in 'table'.
            """
            if table:
                if column in table:
                    possible_versions[:] = [x for x in possible_versions if x <= version]
                else:
                    possible_versions[:] = [x for x in possible_versions if x > version]

        def trim_lesser_versions(version):
            """Remove version numbers < 'version' from 'possible_versions'"""
            possible_versions[:] = [x for x in possible_versions if x >= version]

        if 'History' in list(self.structure.keys()):
            log.debug('Analyzing \'History\' structure')
            log.debug(f' - Starting possible versions:  {possible_versions}')
            if 'visits' in list(self.structure['History'].keys()):
                trim_lesser_versions_if('visit_duration', self.structure['History']['visits'], 20)
                trim_lesser_versions_if('incremented_omnibox_typed_score', self.structure['History']['visits'], 68)
                trim_lesser_versions_if('originator_from_visit', self.structure['History']['visits'], 106)
                trim_lesser_versions_if('is_known_to_sync', self.structure['History']['visits'], 107)
                trim_lesser_versions_if('consider_for_ntp_most_visited', self.structure['History']['visits'], 114)
                trim_lesser_versions_if('external_referrer_url', self.structure['History']['visits'], 117)
                trim_lesser_versions_if('visited_link_id', self.structure['History']['visits'], 119)
                trim_lesser_versions_if('app_id', self.structure['History']['visits'], 122)
            if 'visit_source' in list(self.structure['History'].keys()):
                trim_lesser_versions_if('source', self.structure['History']['visit_source'], 7)
            if 'downloads' in list(self.structure['History'].keys()):
                trim_lesser_versions_if('target_path', self.structure['History']['downloads'], 26)
                trim_lesser_versions_if('opened', self.structure['History']['downloads'], 16)
                trim_lesser_versions_if('referrer', self.structure['History']['downloads'], 29)
                trim_lesser_versions_if('etag', self.structure['History']['downloads'], 30)
                trim_lesser_versions_if('original_mime_type', self.structure['History']['downloads'], 37)
                trim_lesser_versions_if('tab_url', self.structure['History']['downloads'], 51)
                trim_lesser_versions_if('last_access_time', self.structure['History']['downloads'], 59)
                trim_lesser_versions_if('by_web_app_id', self.structure['History']['downloads'], 115)
            if 'downloads_slices' in list(self.structure['History'].keys()):
                trim_lesser_versions(58)
            if 'content_annotations' in list(self.structure['History'].keys()):
                trim_lesser_versions(91)
                trim_lesser_versions_if('related_searches', self.structure['History']['content_annotations'], 94)
                trim_lesser_versions_if('visibility_score', self.structure['History']['content_annotations'], 95)
                trim_lesser_versions_if('search_terms', self.structure['History']['content_annotations'], 100)
                trim_lesser_versions_if('alternative_title', self.structure['History']['content_annotations'], 104)
            if 'context_annotations' in list(self.structure['History'].keys()):
                trim_lesser_versions(92)
                trim_lesser_versions_if(
                    'total_foreground_duration', self.structure['History']['context_annotations'], 96)
            if 'clusters' in list(self.structure['History'].keys()):
                trim_lesser_versions(93)
                trim_lesser_versions_if('originator_cluster_id', self.structure['History']['clusters'], 111)
            log.debug(f' - Finishing possible versions: {possible_versions}')

        possible_versions, previous_possible_versions = \
            update_and_rollback_if_empty(possible_versions, previous_possible_versions)

        if 'Cookies' in list(self.structure.keys()):
            log.debug("Analyzing 'Cookies' structure")
            log.debug(f' - Starting possible versions:  {possible_versions}')
            if 'cookies' in list(self.structure['Cookies'].keys()):
                trim_lesser_versions_if('source_port', self.structure['Cookies']['cookies'], 88)
                trim_lesser_versions_if('source_scheme', self.structure['Cookies']['cookies'], 80)
                trim_lesser_versions_if('samesite', self.structure['Cookies']['cookies'], 76)
                trim_lesser_versions_if('is_persistent', self.structure['Cookies']['cookies'], 66)
                trim_lesser_versions_if('encrypted_value', self.structure['Cookies']['cookies'], 33)
                trim_lesser_versions_if('priority', self.structure['Cookies']['cookies'], 28)
                trim_lesser_versions_if('source_type', self.structure['Cookies']['cookies'], 125)
            log.debug(f' - Finishing possible versions: {possible_versions}')

        possible_versions, previous_possible_versions = \
            update_and_rollback_if_empty(possible_versions, previous_possible_versions)

        if 'DIPS' in list(self.structure.keys()):
            log.debug("Analyzing 'DIPS' structure")
            log.debug(f' - Starting possible versions:  {possible_versions}')
            if 'bounces' in list(self.structure['DIPS'].keys()):
                trim_lesser_versions_if('first_bounce_time', self.structure['DIPS']['bounces'], 114)
                trim_lesser_versions_if('first_web_authn_assertion_time', self.structure['DIPS']['bounces'], 117)
                trim_lesser_versions_if('first_user_activation_time', self.structure['DIPS']['bounces'], 134)
                trim_greater_versions_if('first_site_storage_time', self.structure['DIPS']['bounces'], 141)
            log.debug(f' - Finishing possible versions: {possible_versions}')

        possible_versions, previous_possible_versions = \
            update_and_rollback_if_empty(possible_versions, previous_possible_versions)

        if 'Web Data' in list(self.structure.keys()):
            log.debug("Analyzing 'Web Data' structure")
            log.debug(f' - Starting possible versions:  {possible_versions}')
            if 'autofill' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions_if('name', self.structure['Web Data']['autofill'], 2)
                trim_lesser_versions_if('date_created', self.structure['Web Data']['autofill'], 35)
            if 'autofill_profiles' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions_if('language_code', self.structure['Web Data']['autofill_profiles'], 36)
                trim_lesser_versions_if('validity_bitfield', self.structure['Web Data']['autofill_profiles'], 63)
                trim_lesser_versions_if(
                    'is_client_validity_states_updated', self.structure['Web Data']['autofill_profiles'], 71)
            if 'autofill_profile_addresses' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions(86)
                trim_lesser_versions_if('city', self.structure['Web Data']['autofill_profile_addresses'], 87)
            if 'autofill_sync_metadata' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions(57)
                trim_lesser_versions_if('model_type', self.structure['Web Data']['autofill_sync_metadata'], 69)
            if 'web_apps' not in list(self.structure['Web Data'].keys()):
                trim_lesser_versions(38)
            if 'credit_cards' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions_if('billing_address_id', self.structure['Web Data']['credit_cards'], 53)
                trim_lesser_versions_if('nickname', self.structure['Web Data']['credit_cards'], 85)
            if 'masked_bank_accounts' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions(123)
            if 'plus_addresses' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions(124)
            if 'addresses' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions(130)
            if 'attributes' in list(self.structure['Web Data'].keys()):
                trim_lesser_versions(134)
            log.debug(f' - Finishing possible versions: {possible_versions}')

        possible_versions, previous_possible_versions = \
            update_and_rollback_if_empty(possible_versions, previous_possible_versions)

        if 'Login Data' in list(self.structure.keys()):
            log.debug("Analyzing 'Login Data' structure")
            log.debug(f' - Starting possible versions:  {possible_versions}')
            if 'logins' in list(self.structure['Login Data'].keys()):
                trim_lesser_versions_if('display_name', self.structure['Login Data']['logins'], 39)
                trim_lesser_versions_if('generation_upload_status', self.structure['Login Data']['logins'], 42)
                trim_greater_versions_if('ssl_valid', self.structure['Login Data']['logins'], 53)
                trim_lesser_versions_if('possible_username_pairs', self.structure['Login Data']['logins'], 59)
                trim_lesser_versions_if('id', self.structure['Login Data']['logins'], 73)
                trim_lesser_versions_if('moving_blocked_for', self.structure['Login Data']['logins'], 84)
            if 'field_info' in list(self.structure['Login Data'].keys()):
                trim_lesser_versions(80)
            if 'compromised_credentials' in list(self.structure['Login Data'].keys()):
                trim_lesser_versions(83)
            if 'insecure_credentials' in list(self.structure['Login Data'].keys()):
                trim_lesser_versions(89)
            log.debug(f' - Finishing possible versions: {possible_versions}')

        possible_versions, previous_possible_versions = \
            update_and_rollback_if_empty(possible_versions, previous_possible_versions)

        if 'Network Action Predictor' in list(self.structure.keys()):
            log.debug("Analyzing 'Network Action Predictor' structure")
            log.debug(f' - Starting possible versions:  {possible_versions}')
            if 'resource_prefetch_predictor_url' in list(self.structure['Network Action Predictor'].keys()):
                trim_lesser_versions(22)
                trim_lesser_versions_if(
                    'key', self.structure['Network Action Predictor']['resource_prefetch_predictor_url'], 55)
                trim_lesser_versions_if(
                    'proto', self.structure['Network Action Predictor']['resource_prefetch_predictor_url'], 54)
            if 'lcp_critical_path_predictor' in list(self.structure['Network Action Predictor'].keys()):
                trim_lesser_versions(117)
            if 'lcp_critical_path_predictor_initiator_origin' in list(self.structure['Network Action Predictor'].keys()):
                trim_lesser_versions(129)
            log.debug(f' - Finishing possible versions: {possible_versions}')

        possible_versions, previous_possible_versions = \
            update_and_rollback_if_empty(possible_versions, previous_possible_versions)

        self.version = possible_versions

    @contextmanager
    def _execute_compatible_query(self, path, database, query, version, artifact_name, count_key=None):
        """Open *database*, find the highest compatible query version, execute it with schema fallback, yield cursor.

        Yields None (and logs) on any failure so callers can do ``if cursor is None: return``.
        The DB connection is always closed on exit.
        """
        if count_key is None:
            count_key = database

        compatible_version = version[0]
        while compatible_version not in query and compatible_version > 0:
            compatible_version -= 1

        if compatible_version == 0:
            log.warning(f' - No compatible query version found for {artifact_name}')
            yield None
            return

        log.info(f' - Using SQL query for {artifact_name} for Chrome v{compatible_version}')

        conn = utils.open_sqlite_db(self, path, database)
        if not conn:
            self.artifacts_counts[count_key] = 'Failed'
            yield None
            return

        try:
            cursor = conn.cursor()
            # Try versions from highest compatible downward to handle schema gaps (e.g. missing columns in Guest Profiles)
            sorted_versions = sorted([v for v in query if v <= compatible_version], reverse=True)
            for attempt_version in sorted_versions:
                try:
                    cursor.execute(query[attempt_version])
                    if attempt_version != compatible_version:
                        log.info(f' - Fell back to SQL query for {artifact_name} for Chrome v{attempt_version}')
                    break
                except sqlite3.OperationalError as e:
                    log.warning(f' - Query for {artifact_name} v{attempt_version} failed ({e}); trying lower version')
            else:
                log.error(f' - No compatible query found for {artifact_name}; skipping')
                self.artifacts_counts[count_key] = 'Failed'
                yield None
                return
            yield cursor
        finally:
            conn.close()

    def get_history(self, path, history_file, version, row_type):
        results = []

        log.info(f'History items from {history_file}')

        # Queries for different versions
        _cluster_subquery = (
            "(SELECT cav.visit_id, "
            "GROUP_CONCAT(CASE WHEN c.label IS NOT NULL AND c.label != '' "
            "THEN c.label || ' (' || cav.cluster_id || ')' "
            "ELSE CAST(cav.cluster_id AS TEXT) END, ', ') AS cluster_str "
            "FROM clusters_and_visits cav LEFT JOIN clusters c ON c.cluster_id = cav.cluster_id "
            "GROUP BY cav.visit_id) cav ON cav.visit_id = visits.id"
        )
        query = {107: f'''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, visits.is_known_to_sync, visits.originator_cache_guid, visits.visit_time,
                            visits.from_visit, visits.opener_visit, visits.visit_duration, visits.transition,
                            visit_source.source, visits.id as visit_id, content_annotations.categories,
                            content_annotations.entities, context_annotations.response_code, context_annotations.tab_id,
                            context_annotations.window_id, cav.cluster_str
                        FROM urls
                                 JOIN visits ON urls.id = visits.url
                                 LEFT JOIN visit_source ON visits.id = visit_source.id
                                 LEFT JOIN content_annotations ON content_annotations.visit_id = visits.id
                                 LEFT JOIN context_annotations ON context_annotations.visit_id = visits.id
                                 LEFT JOIN {_cluster_subquery}
                      ''',
                 95: f'''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, visits.visit_time, visits.from_visit, visits.opener_visit, visits.visit_duration,
                            visits.transition, visit_source.source, visits.id as visit_id, content_annotations.categories,
                            content_annotations.entities, cav.cluster_str
                        FROM urls
                                 JOIN visits ON urls.id = visits.url
                                 LEFT JOIN visit_source ON visits.id = visit_source.id
                                 LEFT JOIN content_annotations ON content_annotations.visit_id = visits.id
                                 LEFT JOIN {_cluster_subquery}
                     ''',
                 94: f'''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, visits.visit_time, visits.from_visit, visits.opener_visit, visits.visit_duration,
                            visits.transition, visit_source.source, visits.id as visit_id, content_annotations.categories,
                            content_annotations.entities, cav.cluster_str
                        FROM urls
                                 JOIN visits ON urls.id = visits.url
                                 LEFT JOIN visit_source ON visits.id = visit_source.id
                                 LEFT JOIN content_annotations ON content_annotations.visit_id = visits.id
                                 LEFT JOIN {_cluster_subquery}
                     ''',
                 59: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, visits.visit_time, visits.from_visit, visits.visit_duration,
                            visits.transition, visit_source.source, visits.id as visit_id
                        FROM urls JOIN visits
                        ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 30: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.visit_duration,
                            visits.transition, visit_source.source, visits.id as visit_id
                        FROM urls JOIN visits 
                        ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 29: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.visit_duration,
                            visits.transition, visit_source.source, visits.is_indexed, visits.id as visit_id
                        FROM urls JOIN visits 
                        ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 20: '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.visit_duration,
                            visits.transition, visit_source.source, visits.is_indexed, visits.id as visit_id
                        FROM urls JOIN visits 
                        ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 7:  '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.transition,
                            visit_source.source, visits.id as visit_id
                        FROM urls JOIN visits 
                        ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id''',
                 1:  '''SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                            urls.hidden, urls.favicon_id, visits.visit_time, visits.from_visit, visits.transition,
                            visits.id as visit_id
                        FROM urls, visits WHERE urls.id = visits.url'''}

        source_item = os.path.relpath(os.path.join(path, history_file), self.profile_path)
        with self._execute_compatible_query(path, history_file, query, version, 'History items') as cursor:
            if cursor is None:
                return

            for row in cursor:
                duration = None
                if row.get('visit_duration'):
                    duration = datetime.timedelta(microseconds=row.get('visit_duration'))

                new_row = Chrome.URLItem(
                    profile=self.profile_path,
                    visit_id=row.get('visit_id'),
                    url=row.get('url'),
                    title=row.get('title'),
                    visit_time=utils.to_datetime(row.get('visit_time'), self.timezone),
                    last_visit_time=utils.to_datetime(row.get('last_visit_time'), self.timezone),
                    visit_count=row.get('visit_count'),
                    typed_count=row.get('typed_count'),
                    from_visit=row.get('from_visit'),
                    transition=row.get('transition'),
                    hidden=row.get('hidden'),
                    favicon_id=row.get('favicon_id'),
                    indexed=row.get('is_indexed'),
                    visit_duration=str(duration),
                    visit_source=row.get('source'),
                    is_known_to_sync=row.get('is_known_to_sync'),
                    originator_cache_guid=row.get('originator_cache_guid'),
                    opener_visit=row.get('opener_visit'),
                    response_code=row.get('response_code'),
                    tab_id=row.get('tab_id'),
                    window_id=row.get('window_id'),
                )

                # Set the row type as determined earlier
                new_row.row_type = row_type

                # Parse content annotations
                categories = row.get('categories')
                new_row.category_ids = [c.strip() for c in categories.split(',') if c.strip()] if categories else None
                entities = row.get('entities')
                new_row.entity_ids = [e.strip() for e in entities.split(',') if e.strip()] if entities else None

                # Collect unique KG entity/category IDs for later resolution
                # IDs are stored as '/m/01mf0:99' (id:confidence); strip the score for API lookup
                if new_row.category_ids:
                    for cid in new_row.category_ids:
                        kg_id = cid.rsplit(':', 1)[0] if ':' in cid else cid
                        self.kg_entities.setdefault(kg_id, None)
                if new_row.entity_ids:
                    for eid in new_row.entity_ids:
                        kg_id = eid.rsplit(':', 1)[0] if ':' in eid else eid
                        self.kg_entities.setdefault(kg_id, None)

                new_row.cluster_str = row.get('cluster_str')

                # Translate the transition value to human-readable
                new_row.decode_transition()

                # Translate the numeric visit_source.source code to human-readable
                new_row.decode_source()

                new_row.source_item = source_item
                results.append(new_row)

        self.artifacts_counts[history_file] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_media_history(self, path, history_file, version, row_type):
        results = []

        log.info(f'Media History items from {history_file}')

        # Queries for different versions
        query = {86: '''SELECT playback.url, playback.last_updated_time_s, playback.watch_time_s,
                            playback.has_video, playback.has_audio, playbackSession.title, 
                            playbackSession.source_title, playbackSession.duration_ms, playbackSession.position_ms
                        FROM playback LEFT JOIN playbackSession 
                            ON playback.last_updated_time_s = playbackSession.last_updated_time_s'''}

        source_item = os.path.relpath(os.path.join(path, history_file), self.profile_path)
        with self._execute_compatible_query(path, history_file, query, version, 'Media History items') as cursor:
            if cursor is None:
                return

            for row in cursor:
                duration = None
                if row.get('duration_ms'):
                    # Check is duration value is reasonable; some have been equivalent of 300 million years
                    if row.get('duration_ms') < 2600000:
                        duration = str(datetime.timedelta(milliseconds=row.get('duration_ms')))[:-3]

                position = None
                if row.get('position_ms'):
                    position = str(datetime.timedelta(milliseconds=row.get('position_ms')))[:-3]

                watch_time = ' 0:00:00'
                if row.get('watch_time_s'):
                    watch_time = ' ' + str(datetime.timedelta(seconds=row.get('watch_time_s')))

                row_title = ''
                if row.get('title'):
                    row_title = row.get('title')

                new_row = Chrome.MediaItem(
                    self.profile_path, row.get('url'), row_title,
                    utils.to_datetime(row.get('last_updated_time_s'), self.timezone), position,
                    duration, row.get('source_title'), watch_time, row.get('has_video'), row.get('has_audio'))

                new_row.row_type = row_type
                new_row.source_item = source_item
                results.append(new_row)

        self.artifacts_counts[history_file] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    @staticmethod
    def _download_interpretation(item):
        """Build the Timeline Interpretation summary for a download from its richer fields
        (shared by the History and shared_proto_db download parsers)."""
        parts = []
        if getattr(item, 'download_source', None):
            parts.append(f'Source: {item.download_source}')
        by_ext = getattr(item, 'by_ext_name', None) or getattr(item, 'by_ext_id', None)
        if by_ext:
            parts.append(f'By extension: {by_ext}')
        if getattr(item, 'by_web_app_id', None):
            parts.append(f'By web app: {item.by_web_app_id}')
        # mime_type / referrer / tab_url / request_headers have dedicated Timeline columns,
        # so they are not repeated here.
        if getattr(item, 'site_url', None):
            parts.append(f'Site: {item.site_url}')
        if getattr(item, 'http_method', None):
            parts.append(f'Method: {item.http_method}')
        if getattr(item, 'storage_partition', None):
            parts.append(f'Storage partition: {item.storage_partition}')
        if getattr(item, 'fetched_via_service_worker', None):
            parts.append('Via service worker')
        chain = getattr(item, 'url_chain', None)
        if chain and len(chain) > 1:
            parts.append('Redirect chain: ' + ' -> '.join(chain))
        # In practice only set for shared_proto_db downloads; the History downloads
        # table has a hash column but Chrome never populates it.
        if getattr(item, 'hash', None):
            parts.append(f'SHA-256: {item.hash}')
        if getattr(item, 'transient', None):
            parts.append('Transient')
        return ' | '.join(parts)

    def get_downloads(self, path, database, version, row_type):
        # Set up empty return array
        results = []

        log.info(f'Download items from {database}:')

        # Queries for different versions. Columns are cumulative; the version key is the
        # Chrome version a column first appears (per the downloads field-availability chart).
        # embedder_download_data (v100) is intentionally omitted (opaque
        # StoragePartitionConfig -- see documentation/future_work.md).
        _chains = ('downloads_url_chains.url, downloads_url_chains.chain_index '
                   'FROM downloads, downloads_url_chains WHERE downloads_url_chains.id = downloads.id')
        query = {
            115: f'''SELECT downloads.id, downloads.received_bytes, downloads.total_bytes, downloads.state,
                        downloads.start_time, downloads.end_time, downloads.opened, downloads.current_path,
                        downloads.target_path, downloads.danger_type, downloads.interrupt_reason,
                        downloads.referrer, downloads.by_ext_id, downloads.by_ext_name, downloads.etag,
                        downloads.last_modified, downloads.mime_type, downloads.original_mime_type,
                        downloads.guid, downloads.hash, downloads.http_method, downloads.site_url,
                        downloads.tab_url, downloads.tab_referrer_url, downloads.last_access_time,
                        downloads.transient, downloads.by_web_app_id, {_chains}''',
            59:  f'''SELECT downloads.id, downloads.received_bytes, downloads.total_bytes, downloads.state,
                        downloads.start_time, downloads.end_time, downloads.opened, downloads.current_path,
                        downloads.target_path, downloads.danger_type, downloads.interrupt_reason,
                        downloads.referrer, downloads.by_ext_id, downloads.by_ext_name, downloads.etag,
                        downloads.last_modified, downloads.mime_type, downloads.original_mime_type,
                        downloads.guid, downloads.hash, downloads.http_method, downloads.site_url,
                        downloads.tab_url, downloads.tab_referrer_url, downloads.last_access_time,
                        downloads.transient, {_chains}''',
            51:  f'''SELECT downloads.id, downloads.received_bytes, downloads.total_bytes, downloads.state,
                        downloads.start_time, downloads.end_time, downloads.opened, downloads.current_path,
                        downloads.target_path, downloads.danger_type, downloads.interrupt_reason,
                        downloads.referrer, downloads.by_ext_id, downloads.by_ext_name, downloads.etag,
                        downloads.last_modified, downloads.mime_type, downloads.original_mime_type,
                        downloads.guid, downloads.hash, downloads.http_method, downloads.site_url,
                        downloads.tab_url, downloads.tab_referrer_url, {_chains}''',
            37:  f'''SELECT downloads.id, downloads.received_bytes, downloads.total_bytes, downloads.state,
                        downloads.start_time, downloads.end_time, downloads.opened, downloads.current_path,
                        downloads.target_path, downloads.danger_type, downloads.interrupt_reason,
                        downloads.referrer, downloads.by_ext_id, downloads.by_ext_name, downloads.etag,
                        downloads.last_modified, downloads.mime_type, downloads.original_mime_type, {_chains}''',
            30:  f'''SELECT downloads.id, downloads.received_bytes, downloads.total_bytes, downloads.state,
                        downloads.start_time, downloads.end_time, downloads.opened, downloads.current_path,
                        downloads.target_path, downloads.danger_type, downloads.interrupt_reason,
                        downloads.referrer, downloads.by_ext_id, downloads.by_ext_name, downloads.etag,
                        downloads.last_modified, {_chains}''',
            29:  f'''SELECT downloads.id, downloads.received_bytes, downloads.total_bytes, downloads.state,
                        downloads.start_time, downloads.end_time, downloads.opened, downloads.current_path,
                        downloads.target_path, downloads.danger_type, downloads.interrupt_reason,
                        downloads.referrer, {_chains}''',
            26:  f'''SELECT downloads.id, downloads.received_bytes, downloads.total_bytes, downloads.state,
                        downloads.start_time, downloads.end_time, downloads.opened, downloads.current_path,
                        downloads.target_path, downloads.danger_type, downloads.interrupt_reason, {_chains}''',
            16:  '''SELECT downloads.id, downloads.url, downloads.received_bytes, downloads.total_bytes,
                        downloads.state, downloads.full_path, downloads.start_time, downloads.end_time,
                        downloads.opened
                    FROM downloads''',
            1:   '''SELECT downloads.id, downloads.url, downloads.received_bytes, downloads.total_bytes,
                        downloads.state, downloads.full_path, downloads.start_time
                    FROM downloads'''}

        source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
        with self._execute_compatible_query(
                path, database, query, version, 'Download items',
                count_key=database + '_downloads') as cursor:
            if cursor is None:
                return

            # The downloads_url_chains join returns one row per redirect hop; collapse to one
            # entry per download, collecting the full URL chain (final hop = download URL).
            # Like the shared_proto_db parser, the chain is surfaced in the Interpretation
            # (via url_chain) rather than as duplicate rows.
            downloads_by_id = {}  # id -> {'row': first row, 'chain': {chain_index: url}}
            for row in cursor:
                acc = downloads_by_id.setdefault(row.get('id'), {'row': row, 'chain': {}})
                if row.get('url'):
                    idx = row.get('chain_index')
                    acc['chain'][idx if idx is not None else 0] = row.get('url')

            for download_id, acc in downloads_by_id.items():
                row = acc['row']
                ordered_chain = [acc['chain'][i] for i in sorted(acc['chain'])]
                final_url = ordered_chain[-1] if ordered_chain else row.get('url')
                try:
                    h = row.get('hash')
                    hash_hex = h.hex() if isinstance(h, (bytes, bytearray)) and any(h) else None
                    lat = row.get('last_access_time')
                    new_row = Chrome.DownloadItem(
                        self.profile_path, download_id, final_url, row.get('received_bytes'),
                        row.get('total_bytes'), row.get('state'), row.get('full_path'),
                        utils.to_datetime(row.get('start_time'), self.timezone),
                        utils.to_datetime(row.get('end_time'), self.timezone), row.get('target_path'),
                        row.get('current_path'), row.get('opened'), row.get('danger_type'),
                        row.get('interrupt_reason'), row.get('etag'), row.get('last_modified'),
                        None,  # chain collapsed into url_chain below
                        guid=row.get('guid'), hash=hash_hex, http_method=row.get('http_method'),
                        referrer=row.get('referrer'), site_url=row.get('site_url'),
                        tab_url=row.get('tab_url'), tab_referrer_url=row.get('tab_referrer_url'),
                        mime_type=row.get('mime_type'), original_mime_type=row.get('original_mime_type'),
                        last_access_time=(utils.to_datetime(lat, self.timezone, none_if_unset=True) if lat else None),
                        transient=row.get('transient'), by_ext_id=row.get('by_ext_id'),
                        by_ext_name=row.get('by_ext_name'), by_web_app_id=row.get('by_web_app_id'),
                        url_chain=ordered_chain if len(ordered_chain) > 1 else None)
                except Exception:
                    log.exception(' - Exception processing record; skipped.')
                    continue

                new_row.decode_interrupt_reason()
                new_row.decode_danger_type()
                new_row.decode_download_state()
                new_row.timestamp = new_row.start_time
                new_row.create_friendly_status()

                if new_row.full_path is not None:
                    new_row.value = new_row.full_path
                elif new_row.current_path is not None:
                    new_row.value = new_row.current_path
                elif new_row.target_path is not None:
                    new_row.value = new_row.target_path
                else:
                    new_row.value = 'Error retrieving download location'
                    log.error(f' - Error retrieving download location for download "{new_row.url}"')

                new_row.interpretation = self._download_interpretation(new_row)
                new_row.row_type = row_type
                new_row.source_item = source_item
                results.append(new_row)

                # Emit a second Timeline row for the last-access ("opened") event, dated at
                # last_access_time, so it appears separately from the download (start) time.
                if new_row.last_access_time is not None \
                        and new_row.last_access_time != new_row.start_time:
                    opened_row = copy.copy(new_row)
                    opened_row.timestamp = new_row.last_access_time
                    opened_row.row_type = f'{row_type} (opened)'
                    results.append(opened_row)

        self.artifacts_counts[database + '_downloads'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_shared_proto_db_downloads(self, path, dir_name):
        # Downloads persisted by Chrome's in-progress DownloadDB in the shared_proto_db
        # LevelDB. Records are keyed "<client_id>_<guid>"; the download client id is "21".
        # Values are serialized download_pb.DownloadDBEntry protos.
        # From https://source.chromium.org/chromium/chromium/src/+/main:components/download/database/proto/download_entry.proto
        from pyhindsight.lib.proto.components.download.database.proto.download_entry_pb2 import DownloadDBEntry
        from pyhindsight.lib.proto.content.browser.download.embedder_download_data_pb2 import EmbedderDownloadData

        # download_pb.DownloadSource (how the download was triggered) -> human-readable.
        # From https://source.chromium.org/chromium/chromium/src/+/main:components/download/database/proto/download_source.proto
        DOWNLOAD_SOURCES = {
            0: 'Unknown', 1: 'Navigation', 2: 'Drag and drop', 3: 'From renderer',
            4: 'Extension API', 5: 'Extension installer', 6: 'Internal API',
            7: 'Web contents API', 8: 'Offline page', 9: 'Context menu', 10: 'Retry',
            11: 'Retry from bubble', 12: 'Toolbar menu',
        }

        results = []
        ldb_path = os.path.join(path, dir_name)
        log.info('Downloads (shared_proto_db):')
        log.info(f' - Reading from {ldb_path}')
        source_item = os.path.relpath(ldb_path, self.profile_path)

        if not os.path.isdir(ldb_path):
            log.error(f' - {ldb_path} is not a directory')
            self.artifacts_counts['shared_proto_db downloads'] = 'Failed'
            return

        def decode_string16_pickle(raw):
            # target_path/current_path are serialized base::Pickle string16 blobs:
            # <uint32 pickle payload length><uint32 char count><UTF-16-LE chars>...
            if not raw or len(raw) < 8:
                return None
            try:
                _payload_len, char_count = struct.unpack('<II', raw[:8])
                return raw[8:8 + (char_count * 2)].decode('utf-16-le', 'replace')
            except Exception:
                return None

        try:
            ldb_records = ccl_chromium_reader.storage_formats.ccl_leveldb.RawLevelDb(pathlib.Path(ldb_path))
        except ValueError as e:
            log.warning(f' - Error reading records ({e}); possible LevelDB corruption')
            self.artifacts_counts['shared_proto_db downloads'] = 'Failed'
            return

        # Keep the latest (highest-seq) Live record per download guid; the in-progress DB
        # rewrites a download's entry as it progresses, so earlier records are partial
        # snapshots (empty target path, no end time, etc.).
        latest_by_guid = {}
        for record in ldb_records.iterate_records_raw():
            if record.state.name != 'Live':
                continue
            if not record.user_key.startswith(b'21_'):
                continue
            try:
                entry = DownloadDBEntry.FromString(record.value)
            except Exception as e:
                log.debug(f' - Could not decode a shared_proto_db download record: {e}')
                continue
            guid = entry.download_info.guid
            if guid not in latest_by_guid or record.seq > latest_by_guid[guid][0]:
                latest_by_guid[guid] = (record.seq, entry)
        ldb_records.close()

        for guid, (seq, entry) in latest_by_guid.items():
            di = entry.download_info
            ip = di.in_progress_info
            try:
                # How the download was triggered (ukm_info.download_source); History has no
                # equivalent column. Skip the UNKNOWN(0)/absent default.
                download_source = None
                if di.HasField('ukm_info') and di.ukm_info.download_source:
                    download_source = DOWNLOAD_SOURCES.get(
                        di.ukm_info.download_source, str(di.ukm_info.download_source))

                # Non-default storage partition => download from an extension / isolated
                # context. serialized_embedder_download_data is the empty default otherwise.
                storage_partition = None
                if ip.serialized_embedder_download_data:
                    try:
                        spc = EmbedderDownloadData.FromString(
                            ip.serialized_embedder_download_data).storage_partition_config
                        if spc.partition_domain or spc.partition_name:
                            storage_partition = (f'{spc.partition_domain}/{spc.partition_name}'
                                                 + (' (in-memory)' if spc.in_memory else ''))
                    except Exception:
                        pass

                request_headers = {h.key: h.value for h in ip.request_headers} or None

                new_row = Chrome.DownloadItem(
                    self.profile_path, download_id=guid,
                    url=ip.url_chain[-1] if ip.url_chain else '',
                    received_bytes=ip.received_bytes, total_bytes=ip.total_bytes, state=ip.state,
                    full_path=None,
                    start_time=utils.to_datetime(ip.start_time, self.timezone, none_if_unset=True),
                    end_time=utils.to_datetime(ip.end_time, self.timezone, none_if_unset=True),
                    target_path=decode_string16_pickle(ip.target_path),
                    current_path=decode_string16_pickle(ip.current_path),
                    danger_type=ip.danger_type, interrupt_reason=ip.interrupt_reason,
                    etag=ip.etag or None, last_modified=ip.last_modified or None,
                    # Fields overlapping the History downloads schema (parity).
                    guid=guid, hash=ip.hash.hex() if ip.hash else None,
                    referrer=ip.referrer_url or None, site_url=ip.site_url or None,
                    tab_url=ip.tab_url or None, tab_referrer_url=ip.tab_referrer_url or None,
                    mime_type=ip.mime_type or None, original_mime_type=ip.original_mime_type or None,
                    transient=ip.transient or None,
                    # shared_proto_db-only extras.
                    download_source=download_source,
                    url_chain=list(ip.url_chain) if len(ip.url_chain) > 1 else None,
                    request_headers=request_headers,
                    fetched_via_service_worker=ip.fetched_via_service_worker or None,
                    storage_partition=storage_partition)
            except Exception:
                log.exception(' - Exception processing shared_proto_db download; skipped.')
                continue

            new_row.decode_interrupt_reason()
            new_row.decode_danger_type()
            new_row.decode_download_state()
            new_row.timestamp = new_row.start_time
            new_row.create_friendly_status()

            new_row.value = new_row.target_path or new_row.current_path \
                or 'Error retrieving download location'
            new_row.interpretation = self._download_interpretation(new_row)
            new_row.row_type = 'download (shared_proto_db)'
            new_row.source_item = source_item
            results.append(new_row)

        self.artifacts_counts['shared_proto_db downloads'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def decrypt_cookie(self, encrypted_value):
        """Decryption based on work by Nathan Henrie and Jordan Wright as well as Chromium source:
         - Mac/Linux: http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
         - Windows: https://gist.github.com/jordan-wright/5770442#file-chrome_extract-py
         - Relevant Chromium source code: https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/
         """
        salt = b'saltysalt'
        iv = b' ' * 16
        length = 16

        def chrome_decrypt(encrypted, key=None):
            # Encrypted cookies should be prefixed with 'v10' according to the
            # Chromium code. Strip it off.
            encrypted = encrypted[3:]

            # Strip padding by taking off number indicated by padding
            # eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.
            def clean(x):
                return x[:-ord(x[-1])]

            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            decrypted = cipher.decrypt(encrypted)

            return clean(decrypted)

        decrypted_value = "<error>"
        if encrypted_value is not None:
            if len(encrypted_value) >= 2:
                # If running Chrome on Windows
                if sys.platform == 'win32' and self.available_decrypts['windows'] == 1:
                    try:
                        decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
                    except:
                        decrypted_value = "<encrypted>"
                # If running Chrome on OSX
                elif sys.platform == 'darwin' and self.available_decrypts['mac'] == 1:
                    try:
                        if not self.cached_key:
                            my_pass = keyring.get_password('Chrome Safe Storage', 'Chrome')
                            my_pass = my_pass.encode('utf8')
                            iterations = 1003
                            self.cached_key = PBKDF2(my_pass, salt, length, iterations)
                        decrypted_value = chrome_decrypt(encrypted_value, key=self.cached_key)
                    except:
                        pass
                else:
                    decrypted_value = "<encrypted>"

                # If running Chromium on Linux.
                # Unlike Win/Mac, we can decrypt Linux cookies without the user's pw
                if decrypted_value == "<encrypted>" and self.available_decrypts['linux'] == 1:
                    try:
                        if not self.cached_key:
                            my_pass = 'peanuts'
                            iterations = 1
                            self.cached_key = PBKDF2(my_pass, salt, length, iterations)
                        decrypted_value = chrome_decrypt(encrypted_value, key=self.cached_key)
                    except:
                        pass

        return decrypted_value

    def get_cookies(self, path, database, version):
        # Set up empty return array
        results = []

        log.info(f'Cookie items from {database}:')

        # Queries for different versions
        query = {103: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.last_update_utc, 
                            cookies.is_secure AS secure, cookies.is_httponly AS httponly, 
                            cookies.is_persistent AS persistent, cookies.has_expires, cookies.priority, 
                            cookies.encrypted_value, cookies.top_frame_site_key
                        FROM cookies''',
                 94: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.is_secure AS secure, 
                            cookies.is_httponly AS httponly, cookies.is_persistent AS persistent, 
                            cookies.has_expires, cookies.priority, cookies.encrypted_value, cookies.top_frame_site_key
                        FROM cookies''',
                 66: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.is_secure AS secure, 
                            cookies.is_httponly AS httponly, cookies.is_persistent AS persistent, 
                            cookies.has_expires, cookies.priority, cookies.encrypted_value
                        FROM cookies''',
                 33: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly,
                            cookies.persistent, cookies.has_expires, cookies.priority, cookies.encrypted_value
                        FROM cookies''',
                 28: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly,
                            cookies.persistent, cookies.has_expires, cookies.priority
                        FROM cookies''',
                 17: '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly,
                            cookies.persistent, cookies.has_expires
                        FROM cookies''',
                 1:  '''SELECT cookies.host_key, cookies.path, cookies.name, cookies.value, cookies.creation_utc,
                            cookies.last_access_utc, cookies.expires_utc, cookies.secure, cookies.httponly
                        FROM cookies'''}

        source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
        with self._execute_compatible_query(path, database, query, version, 'Cookie items') as cursor:
            if cursor is None:
                return

            for row in cursor:
                if row.get('encrypted_value') is not None:
                    if len(row.get('encrypted_value')) >= 2:
                        cookie_value = self.decrypt_cookie(row.get('encrypted_value'))
                    else:
                        cookie_value = row.get('value')
                else:
                    cookie_value = row.get('value')

                # Create a base cookie item with all shared data
                base_cookie = Chrome.CookieItem(
                    self.profile_path, row.get('host_key'), row.get('path'), row.get('name'), cookie_value,
                    utils.to_datetime(row.get('creation_utc'), self.timezone),
                    utils.to_datetime(row.get('last_access_utc'), self.timezone), row.get('secure'),
                    row.get('httponly'), row.get('persistent'), row.get('has_expires'),
                    utils.to_datetime(row.get('expires_utc'), self.timezone), row.get('priority'),
                    row.get('top_frame_site_key'))

                base_cookie.url = base_cookie.host_key + base_cookie.path
                if base_cookie.top_frame_site_key:
                    base_cookie.url += f' ({base_cookie.top_frame_site_key})'

                base_cookie.source_item = source_item
                base_cookie.last_update_utc = utils.to_datetime(row.get('last_update_utc'), self.timezone)
                zero_timestamp = utils.to_datetime(0, self.timezone)

                # Create the row for when the cookie was created
                created_row = copy.copy(base_cookie)
                created_row.row_type = 'cookie (created)'
                created_row.timestamp = created_row.creation_utc
                results.append(created_row)

                # If the cookie was created and accessed at the same time (only used once), or if the last accessed
                # time is 0 (happens on iOS), don't create an accessed row
                if base_cookie.last_access_utc not in (base_cookie.creation_utc, zero_timestamp):
                    accessed_row = copy.copy(base_cookie)
                    accessed_row.row_type = 'cookie (accessed)'
                    accessed_row.timestamp = accessed_row.last_access_utc
                    results.append(accessed_row)

                # Create row for last update time if it exists and is different from other timestamps
                if base_cookie.last_update_utc and base_cookie.last_update_utc != zero_timestamp \
                        and base_cookie.last_update_utc not in (base_cookie.creation_utc, base_cookie.last_access_utc):
                    updated_row = copy.copy(base_cookie)
                    updated_row.row_type = 'cookie (updated)'
                    updated_row.timestamp = updated_row.last_update_utc
                    results.append(updated_row)

        self.artifacts_counts[database] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_login_data(self, path, database, version):
        # Set up empty return array
        results = []

        log.info(f'Login items from {database}:')

        # Queries for "logins" table for different versions
        query = {78:  '''SELECT origin_url, action_url, username_element, username_value, password_element,
                            password_value, date_created, date_last_used, blacklisted_by_user, 
                            times_used FROM logins''',
                 29:  '''SELECT origin_url, action_url, username_element, username_value, password_element,
                            password_value, date_created, blacklisted_by_user, times_used FROM logins''',
                 6:  '''SELECT origin_url, action_url, username_element, username_value, password_element,
                            password_value, date_created, blacklisted_by_user FROM logins'''}

        source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
        with self._execute_compatible_query(path, database, query, version, 'Login items') as cursor:
            if cursor is None:
                return

            for row in cursor:
                if row.get('blacklisted_by_user') == 1:
                    never_save_row = Chrome.LoginItem(
                        self.profile_path, utils.to_datetime(row.get('date_created'), self.timezone),
                        url=row.get('origin_url'), name=row.get('username_element'),
                        value='', count=row.get('times_used'),
                        interpretation='User chose to "Never save password" for this site')
                    never_save_row.row_type = 'login (never save)'
                    never_save_row.source_item = source_item
                    results.append(never_save_row)

                elif row.get('username_value'):
                    interpretation_str = 'User chose to save the credentials entered'
                    if row.get('times_used') and row.get('times_used') > 0:
                        interpretation_str += f' (times used: {row.get("times_used")})'

                    username_row = Chrome.LoginItem(
                        self.profile_path, utils.to_datetime(row.get('date_created'), self.timezone),
                        url=row.get('origin_url'), name=row.get('username_element'),
                        value=row.get('username_value'), count=row.get('times_used'),
                        interpretation=interpretation_str)
                    username_row.row_type = 'login (saved credentials)'
                    username_row.source_item = source_item
                    results.append(username_row)

                    # 'date_last_used' was added in v78; some older records may have small, invalid values; skip them.
                    if row.get('date_last_used') and int(row.get('date_last_used')) > 13100000000000000:
                        interpretation_str = 'User tried to log in with this username (may or may not have succeeded)'
                        if row.get('times_used') and row.get('times_used') > 0:
                            interpretation_str += f'; times used: {row.get("times_used")})'

                        username_row = Chrome.LoginItem(
                            self.profile_path, utils.to_datetime(row.get('date_last_used'), self.timezone),
                            url=row.get('origin_url'), name=row.get('username_element'),
                            value=row.get('username_value'), count=row.get('times_used'),
                            interpretation=interpretation_str)
                        username_row.row_type = 'login (username)'
                        username_row.source_item = source_item
                        results.append(username_row)

                if row.get('password_value') is not None and self.available_decrypts['windows'] == 1:
                    try:
                        # Windows is all I've had time to test; Ubuntu uses built-in password manager
                        password = win32crypt.CryptUnprotectData(
                            row.get('password_value').decode(), None, None, None, 0)[1]
                    except:
                        password = self.decrypt_cookie(row.get('password_value'))

                    password_row = Chrome.LoginItem(
                        self.profile_path, utils.to_datetime(row.get('date_created'), self.timezone),
                        url=row.get('origin_url'), name=row.get('password_element'),
                        value=password, count=row.get('times_used'),
                        interpretation='User chose to save the credentials entered')
                    password_row.row_type = 'login (password)'
                    password_row.source_item = source_item
                    results.append(password_row)

        # Queries for "stats" table for different versions
        query = {48: '''SELECT origin_domain, username_value, dismissal_count, update_time FROM stats'''}

        with self._execute_compatible_query(path, database, query, version, 'Login Stat items') as cursor:
            if cursor is not None:
                for row in cursor:
                    stats_row = Chrome.LoginItem(
                        self.profile_path, utils.to_datetime(row.get('update_time'), self.timezone),
                        url=row.get('origin_domain'), name='',
                        value=row.get('username_value'), count=row.get('dismissal_count'),
                        interpretation=f'User declined to save the password for this site '
                                       f'(dismissal count: {row.get("dismissal_count")})')
                    stats_row.row_type = 'login (declined save)'
                    stats_row.source_item = source_item
                    results.append(stats_row)

        self.artifacts_counts['Login Data'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_autofill(self, path, database, version):
        # Set up empty return array
        results = []

        log.info(f'Autofill items from {database}:')

        # Queries for different versions
        query = {35: '''SELECT autofill.date_created, autofill.date_last_used, autofill.name, autofill.value,
                        autofill.count FROM autofill''',
                 2: '''SELECT autofill_dates.date_created, autofill.name, autofill.value, autofill.count
                        FROM autofill, autofill_dates WHERE autofill.pair_id = autofill_dates.pair_id'''}

        source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
        with self._execute_compatible_query(
                path, database, query, version, 'Autofill items', count_key='Autofill') as cursor:
            if cursor is None:
                return

            for row in cursor:
                autofill_value = row.get('value')
                if isinstance(autofill_value, bytes):
                    autofill_value = '<encrypted>'

                created_item = Chrome.AutofillItem(
                    self.profile_path, utils.to_datetime(row.get('date_created'), self.timezone),
                    row.get('name'), autofill_value, row.get('count'))
                created_item.source_item = source_item
                results.append(created_item)

                if row.get('date_last_used') and row.get('count') > 1:
                    last_used_item = Chrome.AutofillItem(
                        self.profile_path, utils.to_datetime(row.get('date_last_used'), self.timezone),
                        row.get('name'), autofill_value, row.get('count'))
                    last_used_item.source_item = source_item
                    results.append(last_used_item)

        self.artifacts_counts['Autofill'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_dips(self, path, database, version):
        # Set up empty return array
        results = []

        log.info(f'DIPS items from {database}:')

        # Queries for different versions
        query = {114: '''SELECT site, first_bounce_time, first_site_storage_time, first_stateful_bounce_time, 
                           first_user_interaction_time, last_bounce_time, last_site_storage_time, 
                           last_stateful_bounce_time, last_user_interaction_time
                         FROM bounces''',
                 117: '''SELECT site, first_bounce_time, first_site_storage_time, first_stateful_bounce_time, 
                           first_user_interaction_time, first_web_authn_assertion_time, last_bounce_time, 
                           last_site_storage_time, last_stateful_bounce_time, last_user_interaction_time,
                           last_web_authn_assertion_time
                        FROM bounces''',
                 134: '''SELECT site, first_bounce_time, first_site_storage_time, first_stateful_bounce_time, 
                            first_user_activation_time, first_web_authn_assertion_time, last_bounce_time, 
                            last_site_storage_time, last_stateful_bounce_time, last_user_activation_time,
                            last_web_authn_assertion_time
                        FROM bounces''',
                 142: '''SELECT site, first_bounce_time, first_user_activation_time, first_web_authn_assertion_time,
                                last_bounce_time, last_user_activation_time, last_web_authn_assertion_time
                         FROM bounces'''
                 }

        columns = ['first_bounce_time', 'first_site_storage_time', 'first_stateful_bounce_time',
                   'first_user_interaction_time', 'first_user_activation_time', 'last_bounce_time',
                   'last_site_storage_time', 'last_stateful_bounce_time', 'last_user_activation_time',
                   'last_user_interaction_time', 'first_web_authn_assertion_time',
                   'last_web_authn_assertion_time']

        source_item = os.path.relpath(os.path.join(path, database), self.profile_path)
        with self._execute_compatible_query(
                path, database, query, version, 'DIPS items', count_key='DIPS') as cursor:
            if cursor is None:
                return

            for row in cursor:
                for column in columns:
                    if not row.get(column):
                        continue

                    dips_record = Chrome.SiteSetting(
                        self.profile_path, row['site'], utils.to_datetime(row.get(column), self.timezone),
                        column, '', '')
                    dips_record.row_type = 'site setting (dips)'
                    dips_record.source_item = source_item
                    results.append(dips_record)

        self.artifacts_counts['DIPS'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_dips_popups(self, path, database, version):
        # Set up empty return array
        results = []

        log.info(f'DIPS Popups items from {database}:')

        # Queries for different versions
        query = {117: '''SELECT opener_site, popup_site, last_popup_time FROM popups''',
                 133: '''SELECT opener_site, popup_site, last_popup_time, is_authentication_interaction FROM popups'''}

        source_item = os.path.relpath(os.path.join(path, database), self.profile_path)

        with self._execute_compatible_query(
                path, database, query, version, 'DIPS Popup items', count_key='DIPS Popups') as cursor:
            if cursor is None:
                return

            for row in cursor:
                if row.get('is_authentication_interaction'):
                    name = 'Opened an authentication popup on:'
                else:
                    name = 'Opened a popup on:'

                dips_popup_record = Chrome.SiteSetting(
                    self.profile_path, row['opener_site'],
                    utils.to_datetime(row.get('last_popup_time'), self.timezone),
                    name, row['popup_site'], '')
                dips_popup_record.row_type = 'site setting (dips)'
                dips_popup_record.source_item = source_item
                results.append(dips_popup_record)

        self.artifacts_counts['DIPS Popups'] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_bookmarks(self, path, file, version):
        # Set up empty return array
        results = []
        source_item = os.path.relpath(os.path.join(path, file), self.profile_path)

        log.info(f'Bookmark items from {file}:')

        # Connect to 'Bookmarks' JSON file
        bookmarks_path = os.path.join(path, file)

        try:
            with open(bookmarks_path, encoding='utf-8', errors='replace') as f:
                decoded_json = json.loads(f.read())

            log.info(f' - Reading from file "{bookmarks_path}"')

            # TODO: sync_id
            def process_bookmark_children(parent, children):
                for child in children:
                    if child['type'] == 'url':
                        bm = Chrome.BookmarkItem(
                            self.profile_path, utils.to_datetime(child['date_added'], self.timezone),
                            child['name'], child['url'], parent)
                        bm.source_item = source_item
                        results.append(bm)

                    elif child['type'] == 'folder':
                        new_parent = parent + ' > ' + child['name']
                        bm = Chrome.BookmarkFolderItem(
                            self.profile_path, utils.to_datetime(child['date_added'], self.timezone),
                            child['date_modified'], child['name'], parent)
                        bm.source_item = source_item
                        results.append(bm)
                        process_bookmark_children(new_parent, child['children'])

            for top_level_folder in list(decoded_json['roots'].keys()):
                if top_level_folder == 'synced':
                    if decoded_json['roots'][top_level_folder]['children'] is not None:
                        process_bookmark_children(f"Synced > {decoded_json['roots'][top_level_folder]['name']}",
                                                  decoded_json['roots'][top_level_folder]['children'])
                elif top_level_folder != 'sync_transaction_version' and top_level_folder != 'meta_info':
                    if decoded_json['roots'][top_level_folder]['children'] is not None:
                        process_bookmark_children(decoded_json['roots'][top_level_folder]['name'],
                                                  decoded_json['roots'][top_level_folder]['children'])

            self.artifacts_counts['Bookmarks'] = len(results)
            log.info(f' - Parsed {len(results)} items')
            self.parsed_artifacts.extend(results)

        except:
            log.error(f' - Error parsing "{bookmarks_path}"')
            self.artifacts_counts['Bookmarks'] = 'Failed'
            return

    def get_local_storage(self, path, dir_name):
        results = []

        # Grab file list of 'Local Storage' directory
        ls_path = os.path.join(path, dir_name)
        log.info('Local Storage:')
        log.info(f' - Reading from {ls_path}')

        if not os.path.isdir(ls_path):
            log.error(f' - {ls_path} is not a directory')
            self.artifacts_counts['Local Storage'] = 'Failed'
            return

        local_storage_listing = os.listdir(ls_path)
        log.debug(f' - {len(local_storage_listing)} files in Local Storage directory')
        filtered_listing = []

        # Chrome v61+ used leveldb for LocalStorage, but kept old SQLite .localstorage files if upgraded.
        if 'leveldb' in local_storage_listing:
            log.debug(' - Found "leveldb" directory; reading Local Storage LevelDB records')
            ls_ldb_path = os.path.join(ls_path, 'leveldb')
            ls_ldb_records = utils.get_ldb_records(ls_ldb_path)
            log.debug(f' - Reading {len(ls_ldb_records)} Local Storage raw LevelDB records; beginning parsing')
            for record in ls_ldb_records:
                ls_item = self.parse_ls_ldb_record(record)
                if ls_item and ls_item.get('record_type') == 'entry':
                    results.append(Chrome.LocalStorageItem(
                        self.profile_path, ls_item['origin'], ls_item['key'], ls_item['value'],
                        ls_item['seq'], ls_item['state'], str(ls_item['origin_file'])))

        # Chrome v60 and earlier used a SQLite file (with a .localstorage file ext) for each origin
        for ls_file in local_storage_listing:
            if ls_file.startswith(('ftp', 'http', 'file', 'chrome-extension')) and ls_file.endswith('.localstorage'):
                filtered_listing.append(ls_file)
                ls_file_path = os.path.join(ls_path, ls_file)
                ls_created = os.stat(ls_file_path).st_ctime

                conn = None
                try:
                    # Copy and connect to copy of the Local Storage SQLite DB
                    conn = utils.open_sqlite_db(self, ls_path, ls_file)
                    if not conn:
                        continue
                    cursor = conn.cursor()

                    cursor.execute('SELECT key,value,rowid FROM ItemTable')
                    for row in cursor:
                        try:
                            printable_value = row.get('value', b'').decode('utf-16')
                        except:
                            printable_value = repr(row.get('value'))

                        results.append(Chrome.LocalStorageItem(
                            profile=self.profile_path, origin=ls_file[:-13], key=row.get('key', ''),
                            value=printable_value, seq=row.get('rowid', 0), state='Live',
                            last_modified=utils.to_datetime(ls_created, self.timezone),
                            source_path=os.path.join(ls_path, ls_file)))

                except Exception as e:
                    log.warning(f' - Error reading key/values from {ls_file_path}: {e}')
                finally:
                    if conn is not None:
                        conn.close()

        self.artifacts_counts['Local Storage'] = len(results)
        log.info(f' - Parsed {len(results)} items from {len(filtered_listing)} files')
        self.parsed_storage.extend(results)

    def get_sessions(self, path, dir_name):
        results = []

        from ccl_chromium_reader.ccl_chromium_snss2 import SnssFile, SnssFileType, NavigationEntry
        from ccl_chromium_reader.serialization_formats.ccl_easy_chromium_pickle import EasyPickleIterator
        from pyhindsight.lib.page_state import parse_page_state

        sessions_path = os.path.join(path, dir_name)
        log.info('Sessions (SNSS):')
        log.info(f' - Reading from {sessions_path}')

        if not os.path.isdir(sessions_path):
            log.error(f' - {sessions_path} is not a directory')
            self.artifacts_counts['Sessions'] = 'Failed'
            return

        # Session file command IDs (SessionRestoreIdType)
        SESSION_TAB_CLOSED = 16
        SESSION_WINDOW_CLOSED = 17
        SESSION_LAST_ACTIVE_TIME = 21

        # Tab restore file command IDs (TabRestoreIdType)
        TAB_SELECTED_NAV_IN_TAB = 4
        TAB_WINDOW = 9

        WINDOW_SHOW_STATES = {1: 'Normal', 2: 'Minimized', 3: 'Maximized', 5: 'Fullscreen'}
        WINDOW_TYPES = {0: 'Normal', 1: 'App', 2: 'App Popup', 3: 'DevTools'}

        # Session structure: maps built from structural commands (Session_* files only)
        # These are used to enrich NavigationEntry and timestamped event records
        session_tabs = {}      # tab_id -> {window_id, index, pinned, selected_nav_index, group_token, ...}
        session_windows = {}   # window_id -> {type, bounds, show_state, selected_tab_index, ...}
        session_tab_groups = {}  # group_token -> {title, color, collapsed}
        session_active_window = None

        # Structural pass: read raw commands from Session_* files to build tab/window metadata
        for filename in sorted(os.listdir(sessions_path)):
            if not filename.startswith('Session_'):
                continue
            file_path = os.path.join(sessions_path, filename)
            try:
                with open(file_path, 'rb') as f:
                    f.read(8)  # skip header
                    while True:
                        length_raw = f.read(2)
                        if not length_raw or len(length_raw) < 2:
                            break
                        length = struct.unpack('<H', length_raw)[0]
                        data = f.read(length)
                        if len(data) < length:
                            break
                        cmd_id = data[0]
                        p = data[1:]

                        if cmd_id == 0 and len(p) >= 8:      # SetTabWindow: window_id, tab_id
                            window_id = struct.unpack('<I', p[0:4])[0]
                            tab_id = struct.unpack('<I', p[4:8])[0]
                            session_tabs.setdefault(tab_id, {})['window_id'] = window_id
                            session_windows.setdefault(window_id, {})

                        elif cmd_id == 2 and len(p) >= 8:    # SetTabIndexInWindow: tab_id, index
                            tab_id = struct.unpack('<I', p[0:4])[0]
                            session_tabs.setdefault(tab_id, {})['index'] = struct.unpack('<i', p[4:8])[0]

                        elif cmd_id == 7 and len(p) >= 8:    # SetSelectedNavigationIndex: tab_id, index
                            tab_id = struct.unpack('<I', p[0:4])[0]
                            session_tabs.setdefault(tab_id, {})['selected_nav_index'] = struct.unpack('<i', p[4:8])[0]

                        elif cmd_id == 8 and len(p) >= 8:    # SetSelectedTabInIndex: window_id, index
                            window_id = struct.unpack('<I', p[0:4])[0]
                            session_windows.setdefault(window_id, {})['selected_tab_index'] = struct.unpack('<i', p[4:8])[0]

                        elif cmd_id == 9 and len(p) >= 8:    # SetWindowType: window_id, type
                            window_id = struct.unpack('<I', p[0:4])[0]
                            session_windows.setdefault(window_id, {})['type'] = WINDOW_TYPES.get(
                                struct.unpack('<i', p[4:8])[0], str(struct.unpack('<i', p[4:8])[0]))

                        elif cmd_id == 12 and len(p) >= 8:   # SetPinnedState: tab_id, pinned
                            tab_id = struct.unpack('<I', p[0:4])[0]
                            session_tabs.setdefault(tab_id, {})['pinned'] = struct.unpack('<I', p[4:8])[0] != 0

                        elif cmd_id == 13:                    # SetExtensionAppID (pickle): tab_id, extension_id
                            try:
                                with EasyPickleIterator(p) as pk:
                                    tab_id = pk.read_int32()
                                    ext_id = pk.read_string()
                                    session_tabs.setdefault(tab_id, {})['extension_app_id'] = ext_id
                            except Exception:
                                pass

                        elif cmd_id == 14 and len(p) >= 24:   # SetWindowBounds3: window_id, x, y, w, h, show_state
                            window_id = struct.unpack('<I', p[0:4])[0]
                            x, y, w, h, state = struct.unpack('<iiiii', p[4:24])
                            win = session_windows.setdefault(window_id, {})
                            win['bounds'] = f'{w}x{h} at ({x},{y})'
                            win['show_state'] = WINDOW_SHOW_STATES.get(state, str(state))

                        elif cmd_id == 15:                    # SetWindowAppName (pickle): window_id, app_name
                            try:
                                with EasyPickleIterator(p) as pk:
                                    window_id = pk.read_int32()
                                    session_windows.setdefault(window_id, {})['app_name'] = pk.read_string()
                            except Exception:
                                pass

                        elif cmd_id == 20 and len(p) >= 4:    # SetActiveWindow: window_id
                            session_active_window = struct.unpack('<I', p[0:4])[0]

                        elif cmd_id == 25 and len(p) >= 21:   # SetTabGroup: tab_id, group_token_hi, group_token_lo, has_group
                            tab_id = struct.unpack('<I', p[0:4])[0]
                            ghi = struct.unpack('<Q', p[4:12])[0]
                            glo = struct.unpack('<Q', p[12:20])[0]
                            has_group = p[20] != 0
                            if has_group:
                                session_tabs.setdefault(tab_id, {})['group_token'] = f'{ghi:016x}{glo:016x}'
                            else:
                                session_tabs.setdefault(tab_id, {}).pop('group_token', None)

                        elif cmd_id == 27:                    # SetTabGroupMetadata2 (pickle)
                            try:
                                with EasyPickleIterator(p) as pk:
                                    ghi = pk.read_uint64()
                                    glo = pk.read_uint64()
                                    title = pk.read_string16()
                                    color = pk.read_uint32()
                                    collapsed = pk.read_bool()
                                    token = f'{ghi:016x}{glo:016x}'
                                    session_tab_groups[token] = {'title': title, 'color': color, 'collapsed': collapsed}
                            except Exception:
                                pass

                        elif cmd_id == 29:                    # SetTabUserAgentOverride2 (pickle)
                            try:
                                with EasyPickleIterator(p) as pk:
                                    tab_id = pk.read_int32()
                                    ua = pk.read_string()
                                    if ua:
                                        session_tabs.setdefault(tab_id, {})['user_agent_override'] = ua
                            except Exception:
                                pass

            except Exception as e:
                log.debug(f' - Error reading structural commands from {filename}: {e}')

        log.info(f' - Session structure: {len(session_windows)} windows, {len(session_tabs)} tabs, '
                 f'{len(session_tab_groups)} tab groups')

        def get_tab_context(tab_id):
            """Build a list of context strings for a tab from the session structure.
            Window ID and Tab ID are excluded since they have dedicated columns."""
            parts = []
            tab = session_tabs.get(tab_id)
            if not tab:
                return parts

            if tab.get('index') is not None:
                sel = session_windows.get(tab.get('window_id'), {}).get('selected_tab_index')
                tab_desc = f'Tab Index: {tab["index"]}'
                if sel is not None and sel == tab['index']:
                    tab_desc += ' [Selected]'
                parts.append(tab_desc)

            if tab.get('pinned'):
                parts.append('Pinned')

            group_token = tab.get('group_token')
            if group_token and group_token in session_tab_groups:
                group = session_tab_groups[group_token]
                parts.append(f'Tab Group: {group["title"]}')

            if tab.get('extension_app_id'):
                parts.append(f'Extension: {tab["extension_app_id"]}')

            if tab.get('user_agent_override'):
                parts.append(f'UA Override: {tab["user_agent_override"][:50]}')

            return parts

        # Track exact duplicates across all session files; key is all meaningful content fields
        seen_nav_entries = set()

        for filename in sorted(os.listdir(sessions_path)):
            if filename.startswith('Session_'):
                file_type = SnssFileType.Session
                nav_row_type = 'session (navigation)'
            elif filename.startswith('Tabs_'):
                file_type = SnssFileType.Tab
                nav_row_type = 'session (tab navigation)'
            else:
                continue

            file_path = os.path.join(sessions_path, filename)
            source_item = os.path.relpath(file_path, self.profile_path)

            # Pass 1: Use CCL to parse NavigationEntry commands
            try:
                with open(file_path, 'rb') as f:
                    snss_file = SnssFile(file_type, f)
                    for command in snss_file.iter_session_commands():
                        if not isinstance(command, NavigationEntry):
                            continue

                        if command.timestamp:
                            timestamp = command.timestamp.replace(tzinfo=datetime.timezone.utc)
                            timestamp = utils.to_datetime(timestamp, self.timezone)
                        else:
                            timestamp = utils.to_datetime(0, self.timezone)

                        # Build value parts in order: nav index, tab context, short fields, then long URL fields
                        value_parts = []
                        url_parts = []  # long URL-based fields go last

                        # 1. Navigation index (back/forward position in tab)
                        if command.index is not None:
                            sel_nav = session_tabs.get(command.session_id, {}).get('selected_nav_index')
                            nav_desc = f'Nav Index: {command.index}'
                            if sel_nav is not None and sel_nav == command.index:
                                nav_desc += ' [Current]'
                            value_parts.append(nav_desc)

                        # 2. Tab context (tab index, pinned, group, extension, UA)
                        if command.session_id is not None:
                            value_parts.extend(get_tab_context(command.session_id))

                        # 3. Short fields
                        if command.has_post_data:
                            value_parts.append(f'Has POST Data: {command.has_post_data}')

                        # 4. Parse PageState for form data, POST bodies, iframes, etc.
                        parsed_ps = None
                        if command.page_state_raw:
                            try:
                                parsed_ps = parse_page_state(command.page_state_raw)
                                if parsed_ps and parsed_ps.top_frame:
                                    tf = parsed_ps.top_frame
                                    if tf.form_elements:
                                        form_items = []
                                        for fe in tf.form_elements[:10]:
                                            if not fe.values or not any(v.strip() for v in fe.values):
                                                continue  # skip fields with no meaningful values
                                            label = fe.name or '(unnamed)'
                                            form_items.append(f'{label} [{fe.type}]: {fe.values[0][:50]}')
                                        if form_items:
                                            value_parts.append(f'Form Data: {"; ".join(form_items)}')
                                    if tf.http_body and tf.http_body.elements:
                                        body_parts = []
                                        for el in tf.http_body.elements:
                                            if el.element_type == 0 and el.data:
                                                body_parts.append(f'POST({len(el.data)} bytes)')
                                            elif el.element_type == 1 and el.file_path:
                                                body_parts.append(f'File: {el.file_path}')
                                        if body_parts:
                                            value_parts.append(f'HTTP Body: {"; ".join(body_parts)}')
                                        if tf.http_body.contains_passwords:
                                            value_parts.append('Contains Passwords: True')
                                    if tf.children:
                                        value_parts.append(f'Iframes: {len(tf.children)}')
                                    if tf.initiator_origin:
                                        value_parts.append(f'Initiator: {tf.initiator_origin}')
                                if parsed_ps.referenced_files:
                                    ref_files = [f for f in parsed_ps.referenced_files if f]
                                    if ref_files:
                                        value_parts.append(f'Referenced Files: {"; ".join(ref_files)}')
                            except Exception as e:
                                log.debug(f' - Error parsing PageState for {command.url[:50]}: {e}')

                        # 5. Long URL fields at the end
                        if command.referrer_url:
                            url_parts.append(f'Referrer: {command.referrer_url}')
                        if command.original_request_url:
                            url_parts.append(f'Original URL: {command.original_request_url}')

                        value_parts.extend(url_parts)

                        item = Chrome.SessionItem(
                            self.profile_path,
                            url=command.url,
                            title=command.title,
                            timestamp=timestamp,
                            session_id=command.session_id,
                            nav_index=command.index,
                            transition_type_raw=command.transition_type.value,
                            referrer_url=command.referrer_url,
                            original_request_url=command.original_request_url,
                            http_status=command.http_status,
                            has_post_data=command.has_post_data,
                            source_path=file_path,
                            page_state=parsed_ps)
                        item.row_type = nav_row_type
                        item.value = ' | '.join(value_parts)
                        item.decode_transition()
                        item.source_item = source_item

                        dedup_key = (
                            command.url,
                            command.title,
                            timestamp,
                            command.session_id,
                            command.index,
                            command.transition_type.value,
                            command.referrer_url,
                            command.original_request_url,
                            command.http_status,
                            command.has_post_data,
                        )
                        if dedup_key in seen_nav_entries:
                            continue
                        seen_nav_entries.add(dedup_key)

                        results.append(item)

            except Exception as e:
                log.warning(f' - Error reading {filename} (NavigationEntry pass): {e}')

            # Pass 2: Read raw SNSS commands for timestamped events CCL doesn't parse
            try:
                with open(file_path, 'rb') as f:
                    f.read(8)  # skip SNSS header
                    while True:
                        length_raw = f.read(2)
                        if not length_raw or len(length_raw) < 2:
                            break
                        length = struct.unpack('<H', length_raw)[0]
                        data = f.read(length)
                        if len(data) < length:
                            break

                        cmd_id = data[0]
                        payload = data[1:]

                        if file_type == SnssFileType.Session:
                            # TabClosed (16): uint32 tab_id + pad(4) + int64 close_time
                            if cmd_id == SESSION_TAB_CLOSED and len(payload) >= 16:
                                tab_id = struct.unpack('<I', payload[0:4])[0]
                                close_time = struct.unpack('<q', payload[8:16])[0]
                                if close_time == 0:
                                    continue
                                item = Chrome.SessionItem(
                                    self.profile_path, url='', title='',
                                    timestamp=utils.to_datetime(close_time, self.timezone), session_id=tab_id,
                                    source_path=file_path)
                                item.row_type = 'session (tab closed)'
                                item.source_item = source_item
                                results.append(item)

                            # WindowClosed (17): uint32 window_id + pad(4) + int64 close_time
                            elif cmd_id == SESSION_WINDOW_CLOSED and len(payload) >= 16:
                                window_id = struct.unpack('<I', payload[0:4])[0]
                                close_time = struct.unpack('<q', payload[8:16])[0]
                                if close_time == 0:
                                    continue
                                item = Chrome.SessionItem(
                                    self.profile_path, url='', title='',
                                    timestamp=utils.to_datetime(close_time, self.timezone), source_path=file_path)
                                item.row_type = 'session (window closed)'
                                # For window events, session_id holds the window_id
                                item.session_id = window_id
                                item.source_item = source_item
                                results.append(item)

                            # LastActiveTime (21): uint32 tab_id + pad(4) + int64 last_active_time
                            elif cmd_id == SESSION_LAST_ACTIVE_TIME and len(payload) >= 16:
                                tab_id = struct.unpack('<I', payload[0:4])[0]
                                active_time = struct.unpack('<q', payload[8:16])[0]
                                if active_time == 0:
                                    continue
                                item = Chrome.SessionItem(
                                    self.profile_path, url='', title='',
                                    timestamp=utils.to_datetime(active_time, self.timezone), session_id=tab_id,
                                    source_path=file_path)
                                item.row_type = 'session (tab last active)'
                                item.source_item = source_item
                                results.append(item)

                        elif file_type == SnssFileType.Tab:
                            # SelectedNavigationInTab (4): uint32 tab_id + int32 index + int64 timestamp
                            if cmd_id == TAB_SELECTED_NAV_IN_TAB and len(payload) >= 16:
                                tab_id = struct.unpack('<I', payload[0:4])[0]
                                nav_index = struct.unpack('<i', payload[4:8])[0]
                                close_time = struct.unpack('<q', payload[8:16])[0]
                                if close_time == 0:
                                    continue
                                item = Chrome.SessionItem(
                                    self.profile_path, url='', title='',
                                    timestamp=utils.to_datetime(close_time, self.timezone), session_id=tab_id,
                                    nav_index=nav_index, source_path=file_path)
                                item.row_type = 'session (closed tab)'
                                item.value = f'Navigation Index: {nav_index}'
                                item.source_item = source_item
                                results.append(item)

                            # Window (9): Pickle with window metadata + close timestamp
                            elif cmd_id == TAB_WINDOW and len(payload) >= 8:
                                try:
                                    with EasyPickleIterator(payload) as p:
                                        window_id = p.read_int32()
                                        selected_tab = p.read_int32()
                                        num_tabs = p.read_int32()
                                        close_time = p.read_int64()
                                        x = p.read_int32()
                                        y = p.read_int32()
                                        w = p.read_int32()
                                        h = p.read_int32()
                                        show_state = p.read_int32()
                                        workspace = p.read_string()
                                        win_type = p.read_int32()

                                    if close_time == 0:
                                        continue

                                    show_state_str = WINDOW_SHOW_STATES.get(show_state, str(show_state))
                                    win_type_str = WINDOW_TYPES.get(win_type, str(win_type))

                                    value_parts = [
                                        f'Tabs: {num_tabs}',
                                        f'Selected Tab: {selected_tab}',
                                        f'Bounds: {w}x{h} at ({x},{y})',
                                        f'State: {show_state_str}',
                                        f'Type: {win_type_str}',
                                    ]

                                    item = Chrome.SessionItem(
                                        self.profile_path, url='', title='',
                                        timestamp=utils.to_datetime(close_time, self.timezone), source_path=file_path)
                                    # For window events, store window_id as session_id for the Window ID column
                                    item.session_id = window_id
                                    item.row_type = 'session (closed window)'
                                    item.value = ' | '.join(value_parts)
                                    item.source_item = source_item
                                    results.append(item)
                                except Exception as e:
                                    log.debug(f' - Error parsing Window command in {filename}: {e}')

            except Exception as e:
                log.warning(f' - Error reading {filename} (raw command pass): {e}')

        # Build tab navigation stacks from NavigationEntry results
        # tab_nav_stacks: tab_id -> {nav_index: (url, title, timestamp)} (latest entry per index)
        tab_nav_stacks = {}
        for item in results:
            if item.session_id is not None and item.url and item.nav_index is not None \
                    and 'navigation' in getattr(item, 'row_type', ''):
                stack = tab_nav_stacks.setdefault(item.session_id, {})
                # Keep the latest entry for each nav_index (by timestamp)
                existing = stack.get(item.nav_index)
                if existing is None or item.timestamp > existing[2]:
                    stack[item.nav_index] = (item.url, item.title or '', item.timestamp)

        # Derive current URL per tab from selected_nav_index
        tab_current_urls = {}
        for tab_id, stack in tab_nav_stacks.items():
            sel = session_tabs.get(tab_id, {}).get('selected_nav_index')
            if sel is not None and sel in stack:
                tab_current_urls[tab_id] = (stack[sel][0], stack[sel][1])
            elif stack:
                # Fallback: use the highest index
                max_idx = max(stack.keys())
                tab_current_urls[tab_id] = (stack[max_idx][0], stack[max_idx][1])

        # Store session structure for Excel output
        self.session_structure = {
            'windows': session_windows,
            'tabs': session_tabs,
            'tab_groups': session_tab_groups,
            'active_window': session_active_window,
            'tab_current_urls': tab_current_urls,
            'tab_nav_stacks': tab_nav_stacks,
        }

        log.info(f' - Parsed {len(results)} Session items')
        self.artifacts_counts['Sessions'] = len(results)
        self.parsed_artifacts.extend(results)

    def get_session_storage(self, path, dir_name):
        results = []

        # Grab file list of 'Session Storage' directory
        ss_path = os.path.join(path, dir_name)
        log.info('Session Storage:')
        log.info(f' - Reading from {ss_path}')
        log.info(f' - Using ccl_chromium_sessionstorage v{ccl_chromium_reader.ccl_chromium_sessionstorage.__version__}')

        if not os.path.isdir(ss_path):
            log.error(f' - {ss_path} is not a directory')
            self.artifacts_counts['Session Storage'] = 'Failed'
            return

        session_storage_listing = os.listdir(ss_path)
        log.debug(f' - {len(session_storage_listing)} files in Session Storage directory')

        ss_ldb_records = None

        # The bundled ccl_chromium_sessionstorage overwrites its module-level `log`
        # with None, so its own `log.warning(...)` calls (e.g. when a record fails to
        # UTF-16-LE decode) raise AttributeError and abort the whole run instead of
        # skipping the bad record. Hand it a real logger so it degrades gracefully.
        if ccl_chromium_reader.ccl_chromium_sessionstorage.log is None:
            ccl_chromium_reader.ccl_chromium_sessionstorage.log = \
                logging.getLogger('ccl_chromium_reader.ccl_chromium_sessionstorage')

        try:
            ss_ldb_records = ccl_chromium_reader.ccl_chromium_sessionstorage.SessionStoreDb(pathlib.Path(ss_path))
        except Exception as e:
            # The reader raises a range of errors on corrupt/truncated LevelDB data;
            # a single bad Session Storage shouldn't abort a multi-profile analysis.
            log.warning(f' - Error reading records ({e!r}); possible LevelDB corruption')
            self.artifacts_counts['Session Storage'] = 'Failed'

        if ss_ldb_records:
            for origin in ss_ldb_records.iter_hosts():
                origin_kvs = ss_ldb_records.get_all_for_host(origin)
                for key, values in origin_kvs.items():
                    for value in values:
                        record_state = 'Live'
                        if value.is_deleted:
                            record_state = 'Deleted'

                        results.append(Chrome.SessionStorageItem(
                            self.profile_path, origin, key, value.value,
                            value.leveldb_sequence_number, state=record_state, source_path=ss_path))

            # Some records don't have an associated host for some unknown reason; still include them.
            for key, value in ss_ldb_records.iter_orphans():
                record_state = 'Live'
                if value.is_deleted:
                    record_state = 'Deleted'

                results.append(Chrome.SessionStorageItem(
                    self.profile_path, '<orphan>', key, value.value,
                    value.leveldb_sequence_number, state=record_state, source_path=ss_path))

            ss_ldb_records.close()
            self.artifacts_counts['Session Storage'] = len(results)

        log.info(f' - Parsed {len(results)} Session Storage items')
        self.parsed_storage.extend(results)

    @staticmethod
    def resolve_indexeddb_blob_refs(record, origin):
        """Walk an IndexedDB record value and replace BlobIndex objects with descriptive strings
        that include the blob file path and metadata.
        """
        BlobIndex = ccl_chromium_reader.ccl_chromium_indexeddb.ccl_blink_value_deserializer.BlobIndex
        blob_base = f'{origin}.indexeddb.blob'

        def _resolve(obj):
            if isinstance(obj, BlobIndex):
                try:
                    info = record.resolve_blob_index(obj)
                    blob_path = os.path.join(
                        blob_base, f'{record.db_id}',
                        f'{info.blob_number >> 8:02x}', f'{info.blob_number:x}')
                    parts = [blob_path]
                    if info.mime_type:
                        parts.append(info.mime_type)
                    if info.size is not None:
                        parts.append(f'{info.size} bytes')
                    if info.file_name:
                        parts.append(info.file_name)
                    return f'[Blob: {"; ".join(parts)}]'
                except Exception:
                    return f'[Blob: unresolved index {obj.index_id}]'
            elif isinstance(obj, dict):
                return {k: _resolve(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_resolve(v) for v in obj]
            else:
                return obj

        return _resolve(record.value)

    def get_indexeddb(self, path, dir_name):
        results = []

        # Grab file list of 'IndexedDB' directory
        idb_path = os.path.join(path, dir_name)
        log.info('IndexedDB:')
        log.info(f' - Reading from {idb_path}')
        log.info(f' - Using ccl_chromium_indexeddb v{ccl_chromium_reader.ccl_chromium_indexeddb.__version__}')

        if not os.path.isdir(idb_path):
            log.error(f' - {idb_path} is not a directory')
            self.artifacts_counts['IndexedDB'] = 'Failed'
            return

        idb_storage_listing = os.listdir(idb_path)
        log.debug(f' - {len(idb_storage_listing)} files in IndexedDB directory')

        for storage_directory in idb_storage_listing:
            if not storage_directory.endswith('.leveldb'):
                continue

            # The Ghostery extension has 1M+ records in it; skip for now.
            if storage_directory == 'chrome-extension_mlomiejdfkolichcflejclcbmpeaniij_0.indexeddb.leveldb':
                continue

            origin = storage_directory.split('.indexeddb')[0]
            blob_directory = None
            blob_path = os.path.join(idb_path, f'{origin}.indexeddb.blob')
            if os.path.exists(blob_path):
                blob_directory = blob_path

            origin_idb = None
            try:
                origin_idb = ccl_chromium_reader.ccl_chromium_indexeddb.WrappedIndexDB(
                    leveldb_dir=os.path.join(idb_path, f'{origin}.indexeddb.leveldb'), leveldb_blob_dir=blob_directory)

                for database_id in origin_idb.database_ids:
                    database = origin_idb[database_id.dbid_no]
                    for obj_store_name in database.object_store_names:
                        obj_store = database.get_object_store_by_name(obj_store_name)
                        try:
                            for record in obj_store.iterate_records():
                                record_state = 'Deleted'
                                if record.is_live:
                                    record_state = 'Live'

                                # Store the absolute path (consistent with the other
                                # storage types); the XLSX render makes it relative to
                                # the Profile, e.g. IndexedDB\<origin>.indexeddb.leveldb.
                                record_source_path = os.path.join(idb_path, storage_directory)
                                if record.external_value_path:
                                    record_source_path = os.path.join(
                                        idb_path, f'{origin}.indexeddb.blob', record.external_value_path)

                                record_value = self.resolve_indexeddb_blob_refs(record, origin)

                                results.append(Chrome.IndexedDBItem(
                                    self.profile_path, origin, str(record.key.value), str(record_value),
                                    int(record.ldb_seq_no), database=f"{record.database_name}.{obj_store_name}",
                                    state=record_state, source_path=record_source_path))
                        except FileNotFoundError as e:
                            log.error(f' - File ({e}) not found while processing {database}')

                        except ValueError as e:
                            log.error(f' - ValueError ({e}) when processing {database}')

                        except Exception as e:
                            log.error(f' - Unexpected Exception: {e}')
            except ValueError as e:
                log.error(f' - {e} when processing {storage_directory}')
                continue

            except Exception as e:
                log.error(f' - Unexpected Exception ({e}) when processing {storage_directory}')
                continue

            finally:
                if origin_idb is not None:
                    origin_idb.close()

        self.artifacts_counts['IndexedDB'] = len(results)
        log.info(f' - Parsed {len(results)} items from {len(idb_storage_listing)} files')
        self.parsed_storage.extend(results)

    @staticmethod
    def load_extension_manifest(extension_path):
        # Get listing of the contents of extension_id directory;
        # this should contain subdirectories for each version of the extension.
        # Glob should filter out extraneous files (like $I30 from FTK).
        ext_version_listing = list(pathlib.Path(extension_path).glob("*.*_*"))

        # Connect to manifest.json in the latest version directory
        # The version could be missing leading zeros in the string, so this sort accounts for that.
        for version in sorted(ext_version_listing, reverse=True, key=lambda x: [int(part) for part in x.name.split('.')]):
            manifest_path = version / 'manifest.json'
            try:
                with open(manifest_path, encoding='utf-8', errors='replace') as f:
                    return json.loads(f.read()), version.name

            except (IOError, json.JSONDecodeError) as e:
                log.error(f' - Error opening {manifest_path} for extension {extension_path}; {e}')
                continue

        log.error(f' - Error opening manifest info for extension {extension_path}')
        return None, None

    @staticmethod
    def get_localized_messages(locale_messages, key):
        """ Helper function to extract localized messages with multiple fallbacks. """
        if key.startswith('__'):
            message_key = key[6:-2]  # Extract actual message key
            return (
                    locale_messages.get(message_key, {}).get('message') or
                    locale_messages.get(message_key, {}).get('lower', {}).get('message') or
                    # Google Wallet / Chrome Payments is weird/hidden - name is saved differently
                    # than other extensions
                    locale_messages.get('app_name', {}).get('message') or
                    '<error>'
            )
        return key

    def get_extensions(self, profile, dir_name):
        log.info('Extensions:')

        # Grab listing of 'Extensions' directory
        extension_directory_path = pathlib.Path(profile, dir_name)
        log.info(f' - Reading from {extension_directory_path}')
        if not extension_directory_path.is_dir():
            log.error(f' - {extension_directory_path} is not a directory')
            self.artifacts_counts['Extensions'] = 'Failed'
            return

        ext_listing = os.listdir(extension_directory_path)
        log.debug(f' - {len(ext_listing)} files in Extensions directory: {str(ext_listing)}')

        # Only process directories with the expected naming convention
        ext_id_re = re.compile(r'^([a-p]{32})$')
        ext_listing = [str(x) for x in ext_listing if ext_id_re.match(x)]
        log.debug(f' - {len(ext_listing)} files in Extensions directory will be processed: {str(ext_listing)}')

        disk_count = 0
        # Process each directory with an ext_id name
        for ext_id in ext_listing:
            manifest, extension_version = self.load_extension_manifest(extension_directory_path / ext_id)

            if not manifest:
                continue

            locale_messages = {}
            if manifest.get('default_locale'):
                locale_messages_path = (
                        extension_directory_path / ext_id / extension_version / '_locales' /
                        manifest['default_locale'] / 'messages.json'
                )
                if locale_messages_path.exists():
                    try:
                        with open(locale_messages_path, encoding='utf-8', errors='replace') as f:
                            locale_messages = json.load(f)
                    except (IOError, json.JSONDecodeError) as e:
                        log.warning(f" - Error processing extension {ext_id}: {e}")

            name = self.get_localized_messages(locale_messages, manifest.get('name', ''))
            description = self.get_localized_messages(locale_messages, manifest.get('description', ''))

            # Merge into the shared per-extension record. On-disk data is authoritative
            # for name/description/version/manifest, and its content_scripts come from the
            # actual unpacked files (preferred over the Secure Preferences cached copy).
            ext = self._extensions_by_id.get(ext_id)
            if ext is None:
                ext = Chrome.BrowserExtension(
                    profile=profile, ext_id=ext_id, name=name, description=description,
                    version=manifest.get('version'), permissions=manifest.get('permissions'),
                    manifest=json.dumps(manifest))
                self._extensions_by_id[ext_id] = ext
            else:
                ext.name = name or ext.name
                ext.description = description or ext.description
                ext.version = manifest.get('version') or ext.version
                ext.permissions = manifest.get('permissions') or ext.permissions
                ext.manifest = json.dumps(manifest)
            ext.on_disk = True
            ext.profile = profile
            if manifest.get('content_scripts'):
                ext.content_scripts = manifest['content_scripts']
            disk_count += 1

        self.artifacts_counts['Extensions'] = disk_count
        log.info(f' - Parsed {disk_count} items')
        self._rebuild_installed_extensions()

    def _rebuild_installed_extensions(self):
        """Rebuild installed_extensions['data'] from the merged per-extension records.

        No 'presentation' key is set: the merged extension data is rendered by the
        dedicated nested 'Extensions' worksheet in analysis.generate_excel rather than
        the generic flat-table presentation path.
        """
        data = sorted(self._extensions_by_id.values(),
                      key=lambda e: (e.name or e.ext_id or '').lower())
        self.installed_extensions = {'data': data}

    def get_extension_settings(self, path, preferences_file):
        """Parse extensions.settings from the Secure Preferences file.

        Records are merged by ext_id into the same per-extension structure
        populated from the on-disk Extensions/ directory by get_extensions(), and the
        install/update times are emitted as timestamped Timeline rows.
        """
        # mojom ManifestLocation -> human-readable
        # From https://source.chromium.org/chromium/chromium/src/+/main:extensions/common/mojom/manifest.mojom
        EXTENSION_LOCATIONS = {
            0: 'Invalid',
            1: 'Internal (Web Store)',
            2: 'External (pref)',
            3: 'External (registry)',
            4: 'Unpacked (developer mode)',
            5: 'Component',
            6: 'External pref download',
            7: 'External policy download',
            8: 'Command line',
            9: 'External policy',
            10: 'External component',
        }
        # Legacy 'state' pref values (historical Extension::State). This key is now obsolete
        # in current Chrome (it appears in ExtensionPrefs' obsolete-keys list; disabled
        # status is tracked via disable_reasons), but older profiles still write it, so we
        # still decode it when present. Pref handling / obsolescence:
        # From https://source.chromium.org/chromium/chromium/src/+/main:extensions/browser/extension_prefs.cc
        EXTENSION_STATES = {
            0: 'Disabled',
            1: 'Enabled',
            2: 'External extension uninstalled',
        }

        log.info('Extension Settings (Secure Preferences):')
        pref_path = os.path.join(path, preferences_file)
        source_item = os.path.relpath(pref_path, self.profile_path)
        try:
            log.info(f' - Reading from {pref_path}')
            with open(pref_path, encoding='utf-8', errors='replace') as f:
                prefs = json.loads(f.read())
        except Exception as e:
            log.exception(f' - Error decoding {preferences_file} file {pref_path}: {e}')
            self.artifacts_counts[preferences_file] = 'Failed'
            return

        settings = prefs.get('extensions', {}).get('settings', {})
        if not settings:
            log.info(' - No extensions.settings found')
            self.artifacts_counts[preferences_file] = 0
            return

        timestamped_items = []
        count = 0

        # Per-extension pref keys (manifest, granted_permissions, withholding_permissions,
        # runtime_granted_permissions, first_install_time, last_update_time, from_webstore,
        # was_installed_by_default, location, state) are defined/written by ExtensionPrefs.
        # From https://source.chromium.org/chromium/chromium/src/+/main:extensions/browser/extension_prefs.cc
        for ext_id, v in settings.items():
            if not isinstance(v, dict):
                continue

            manifest = v.get('manifest') if isinstance(v.get('manifest'), dict) else {}

            # Each permission-set pref (granted / withholding / runtime_granted) holds
            # 'api' (API permissions), 'explicit_host' (cross-origin API access), and
            # 'scriptable_host' (content script injection scope) lists.
            def _perm_list(perm_key, sub_key):
                perms = v.get(perm_key)
                if isinstance(perms, dict):
                    return perms.get(sub_key) or []
                return []

            granted_scriptable = _perm_list('granted_permissions', 'scriptable_host')
            withholding_scriptable = _perm_list('withholding_permissions', 'scriptable_host')
            runtime_scriptable = _perm_list('runtime_granted_permissions', 'scriptable_host')

            content_scripts = manifest.get('content_scripts') or []

            location = v.get('location')
            location_str = EXTENSION_LOCATIONS.get(location, location)
            state = v.get('state')
            state_str = EXTENSION_STATES.get(state, state)

            # Prefer first_install_time; fall back to legacy install_time.
            raw_install = v.get('first_install_time') or v.get('install_time')
            raw_update = v.get('last_update_time')
            install_dt = utils.to_datetime(raw_install, self.timezone, quiet=True) if raw_install else None
            update_dt = utils.to_datetime(raw_update, self.timezone, quiet=True) if raw_update else None

            name = manifest.get('name')

            # Merge into the shared per-extension record (order-independent with get_extensions).
            ext = self._extensions_by_id.get(ext_id)
            if ext is None:
                ext = Chrome.BrowserExtension(
                    profile=path, ext_id=ext_id, name=name,
                    description=manifest.get('description'), version=manifest.get('version'),
                    permissions=manifest.get('permissions'), manifest=json.dumps(manifest))
                self._extensions_by_id[ext_id] = ext
            else:
                # Disk data is authoritative for name/description/version/manifest; only
                # fill from Secure Preferences when the on-disk copy didn't provide them.
                if not ext.name:
                    ext.name = name
                if not ext.description:
                    ext.description = manifest.get('description')
                if not ext.version:
                    ext.version = manifest.get('version')
                if not ext.permissions:
                    ext.permissions = manifest.get('permissions')
                if not ext.manifest:
                    ext.manifest = json.dumps(manifest)

            ext.in_secure_prefs = True
            ext.install_time = install_dt
            ext.update_time = update_dt
            ext.location = location_str
            ext.state = state_str
            # Unpacked extensions store a source 'path' instead of a cached manifest.
            ext.path = v.get('path')
            ext.from_webstore = v.get('from_webstore')
            ext.was_installed_by_default = v.get('was_installed_by_default')
            ext.granted_scriptable_host = granted_scriptable
            ext.withholding_scriptable_host = withholding_scriptable
            ext.runtime_granted_scriptable_host = runtime_scriptable
            ext.granted_api = _perm_list('granted_permissions', 'api')
            ext.withholding_api = _perm_list('withholding_permissions', 'api')
            ext.runtime_granted_api = _perm_list('runtime_granted_permissions', 'api')
            ext.granted_explicit_host = _perm_list('granted_permissions', 'explicit_host')
            ext.withholding_explicit_host = _perm_list('withholding_permissions', 'explicit_host')
            ext.runtime_granted_explicit_host = _perm_list('runtime_granted_permissions', 'explicit_host')
            # On-disk content scripts (actual files) win; otherwise use the cached copy here.
            if not ext.content_scripts and content_scripts:
                ext.content_scripts = content_scripts

            # Emit Timeline rows for install / update events. When the update time equals
            # the install time, emit only the install row.
            display_name = ext.name or ext_id
            host_scope = ', '.join(granted_scriptable) if granted_scriptable else 'none'
            value_str = f'Install source: {location_str} | Granted host scope: {host_scope}'
            timeline_events = [('installed', install_dt, raw_install)]
            if update_dt is not None and update_dt != install_dt:
                timeline_events.append(('updated', update_dt, raw_update))
            for label, dt, raw in timeline_events:
                if dt is None:
                    continue
                pref_item = Chrome.PreferenceItem(
                    self.profile_path, url=ext_id, timestamp=dt,
                    key=f'{display_name} [{ext_id}]',
                    value=value_str,
                    interpretation='')
                pref_item.row_type = f'extension ({label})'
                pref_item.source_item = source_item
                timestamped_items.append(pref_item)

            count += 1

        self.parsed_artifacts.extend(timestamped_items)
        self._rebuild_installed_extensions()
        self.artifacts_counts[preferences_file] = count
        log.info(f' - Parsed {count} extension settings entries '
                 f'({len(timestamped_items)} Timeline events)')

    def get_preferences(self, path, preferences_file):
        def check_and_append_pref(parent, pref, value=None, description=None):
            try:
                # If the preference exists, continue
                if pref in parent.keys():
                    # If no value is specified, use the value from the preference JSON
                    if not value:
                        value = parent[pref]
                    # Append the preference dict to our results array
                    results.append({
                        'group': None,
                        'name': pref,
                        'value': value,
                        'description': description
                    })

                else:
                    results.append({
                        'group': None,
                        'name': pref,
                        'value': '<not present>',
                        'description': description
                    })

            except Exception as e:
                log.exception(f' - Exception parsing Preference item: {e}')

        def check_and_append_pref_and_children(parent, pref, value=None, description=None):
            # If the preference exists, continue
            if parent.get(pref):
                # If no value is specified, use the value from the preference JSON
                if not value:
                    value = parent[pref]
                # Append the preference dict to our results array
                results.append({
                    'group': None,
                    'name': pref,
                    'value': value,
                    'description': description
                })

            else:
                results.append({
                    'group': None,
                    'name': pref,
                    'value': '<not present>',
                    'description': description
                })

        def append_group(group, description=None):
            # Append the preference group to our results array
            results.append({
                'group': group,
                'name': None,
                'value': None,
                'description': description
            })

        def append_pref(pref, value=None, description=None):
            results.append({
                'group': None,
                'name': pref,
                'value': value,
                'description': description
            })

        def expand_language_code(code):
            # From https://cs.chromium.org/chromium/src/components/translate/core/browser/translate_language_list.cc
            codes = {
                  'af': 'Afrikaans',
                  'am': 'Amharic',
                  'ar': 'Arabic',
                  'az': 'Azerbaijani',
                  'be': 'Belarusian',
                  'bg': 'Bulgarian',
                  'bn': 'Bengali',
                  'bs': 'Bosnian',
                  'ca': 'Catalan',
                  'ceb': 'Cebuano',
                  'co': 'Corsican',
                  'cs': 'Czech',
                  'cy': 'Welsh',
                  'da': 'Danish',
                  'de': 'German',
                  'el': 'Greek',
                  'en': 'English',
                  'eo': 'Esperanto',
                  'es': 'Spanish',
                  'et': 'Estonian',
                  'eu': 'Basque',
                  'fa': 'Persian',
                  'fi': 'Finnish',
                  'fy': 'Frisian',
                  'fr': 'French',
                  'ga': 'Irish',
                  'gd': 'Scots Gaelic',
                  'gl': 'Galician',
                  'gu': 'Gujarati',
                  'ha': 'Hausa',
                  'haw': 'Hawaiian',
                  'hi': 'Hindi',
                  'hr': 'Croatian',
                  'ht': 'Haitian Creole',
                  'hu': 'Hungarian',
                  'hy': 'Armenian',
                  'id': 'Indonesian',
                  'ig': 'Igbo',
                  'is': 'Icelandic',
                  'it': 'Italian',
                  'iw': 'Hebrew',
                  'ja': 'Japanese',
                  'ka': 'Georgian',
                  'kk': 'Kazakh',
                  'km': 'Khmer',
                  'kn': 'Kannada',
                  'ko': 'Korean',
                  'ku': 'Kurdish',
                  'ky': 'Kyrgyz',
                  'la': 'Latin',
                  'lb': 'Luxembourgish',
                  'lo': 'Lao',
                  'lt': 'Lithuanian',
                  'lv': 'Latvian',
                  'mg': 'Malagasy',
                  'mi': 'Maori',
                  'mk': 'Macedonian',
                  'ml': 'Malayalam',
                  'mn': 'Mongolian',
                  'mr': 'Marathi',
                  'ms': 'Malay',
                  'mt': 'Maltese',
                  'my': 'Burmese',
                  'ne': 'Nepali',
                  'nl': 'Dutch',
                  'no': 'Norwegian',
                  'ny': 'Nyanja',
                  'pa': 'Punjabi',
                  'pl': 'Polish',
                  'ps': 'Pashto',
                  'pt': 'Portuguese',
                  'ro': 'Romanian',
                  'ru': 'Russian',
                  'sd': 'Sindhi',
                  'si': 'Sinhala',
                  'sk': 'Slovak',
                  'sl': 'Slovenian',
                  'sm': 'Samoan',
                  'sn': 'Shona',
                  'so': 'Somali',
                  'sq': 'Albanian',
                  'sr': 'Serbian',
                  'st': 'Southern Sotho',
                  'su': 'Sundanese',
                  'sv': 'Swedish',
                  'sw': 'Swahili',
                  'ta': 'Tamil',
                  'te': 'Telugu',
                  'tg': 'Tajik',
                  'th': 'Thai',
                  'tl': 'Tagalog',
                  'tr': 'Turkish',
                  'uk': 'Ukrainian',
                  'ur': 'Urdu',
                  'uz': 'Uzbek',
                  'vi': 'Vietnamese',
                  'yi': 'Yiddish',
                  'xh': 'Xhosa',
                  'yo': 'Yoruba',
                  'zh-CN': 'Chinese (Simplified)',
                  'zh-TW': 'Chinese (Traditional)',
                  'zu': 'Zulu'
                }
            return codes.get(code, code)

        def translate_account_capabilities(capability_code):
            # From https://cs.chromium.org/chromium/src/components/signin/internal/identity_manager/account_capabilities_list.h
            account_capabilities = {
                "accountcapabilities/ge2dinbnmnqxa": "Fetch family member info",
                "accountcapabilities/haytqlldmfya": "Show email address in UI",
                "accountcapabilities/ge4tenznmnqxa": "Make Chrome search engine choice screen selection",
                "accountcapabilities/gu2dqlldmfya": "Participate in Chrome Privacy Sandbox trials",
                "accountcapabilities/gi2tklldmfya": "Show history sync opt-ins without minor-mode restrictions",
                "accountcapabilities/gu4dmlldmfya": "Toggle auto updates (ChromeOS)",
                "accountcapabilities/ge3dgmjnmnqxa": "Use ChromeOS generative AI features",
                "accountcapabilities/ge2tkmznmnqxa": "Use Copy Editor feature",
                "accountcapabilities/geztenjnmnqxa": "Use DevTools generative AI features",
                "accountcapabilities/gezdsmbnmnqxa": "Use education-focused features",
                "accountcapabilities/ge2tkobnmnqxa": "Use generative AI in Recorder app",
                "accountcapabilities/ge3dgobnmnqxa": "Use generative AI photo editing",
                "accountcapabilities/geytcnbnmnqxa": "Use Manta service",
                "accountcapabilities/gezdcnbnmnqxa": "Use model execution features",
                "accountcapabilities/ge2tknznmnqxa": "Use speaker label in Recorder app",
                "accountcapabilities/g42tslldmfya": "Allowed for machine learning features",
                "accountcapabilities/guzdslldmfya": "Opted into parental supervision",
                "accountcapabilities/ge4tgnznmnqxa": "Subject to account-level enterprise policies",
                "accountcapabilities/he4tolldmfya": "Subject to Chrome Privacy Sandbox restricted measurement notice",
                "accountcapabilities/g44tilldmfya": "Subject to enterprise policies",
                "accountcapabilities/guydolldmfya": "Subject to parental controls",
                "accountcapabilities/giytmnrnmnqxa": "Use Gemini in Chrome (gated by kGlicEligibilitySeparateAccountCapability)",
            }
            return account_capabilities.get(capability_code, capability_code)


        results = []
        timestamped_preference_items = []
        log.info('Preferences:')

        # Open 'Preferences' file
        pref_path = os.path.join(path, preferences_file)
        source_item = os.path.relpath(pref_path, self.profile_path)
        try:
            log.info(f' - Reading from {pref_path}')
            with open(pref_path, encoding='utf-8', errors='replace') as f:
                prefs = json.loads(f.read())

        except Exception as e:
            log.exception(f' - Error decoding Preferences file {pref_path}: {e}')
            self.artifacts_counts[preferences_file] = 'Failed'
            return

        # Account Information
        if prefs.get('account_info'):
            append_group('Account Information')
            for account in prefs['account_info']:
                for account_item in list(account.keys()):
                    if account_item == 'accountcapabilities':
                        capability_string = ''
                        for accountcapability, enabled in account[account_item].items():
                            if enabled:
                                capability_string += f'{translate_account_capabilities(accountcapability)}; '
                        append_pref("Account Capabilities", capability_string)
                        continue
                    append_pref(account_item, account[account_item])

        # Local file paths
        append_group('Local file paths')
        if prefs.get('download'):
            check_and_append_pref(prefs['download'], 'default_directory')
        if prefs.get('printing'):
            if prefs.get('print_preview_sticky_settings'):
                check_and_append_pref(prefs['printing']['print_preview_sticky_settings'], 'savePath')
        if prefs.get('savefile'):
            check_and_append_pref(prefs['savefile'], 'default_directory')
        if prefs.get('selectfile'):
            check_and_append_pref(prefs['selectfile'], 'last_directory')

        # Autofill
        if prefs.get('autofill'):
            append_group('Autofill')
            check_and_append_pref(prefs['autofill'], 'enabled')

        # Network Prediction
        if prefs.get('net'):
            # NetworkPredictionOptions. The enum was reassigned when network prediction was
            # merged into the preloading setting; older profiles used 0=Always, 1=WifiOnly,
            # 2=Never. Current values:
            # Ref: https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/preloading/preloading_prefs.h
            NETWORK_PREDICTION_OPTIONS = {
                0: 'Standard preloading',
                1: 'WiFi only (deprecated; = default)',
                2: 'No preloading',
                3: 'Extended preloading',
            }
            append_group('Network Prefetching')
            check_and_append_pref(prefs['net'], 'network_prediction_options',
                                  NETWORK_PREDICTION_OPTIONS.get(prefs['net'].get('network_prediction_options')))

        # Clearing Chrome Data
        if prefs.get('browser'):
            append_group('Clearing Chrome Data')
            if prefs['browser'].get('last_clear_browsing_data_time'):
                check_and_append_pref(
                    prefs['browser'], 'last_clear_browsing_data_time',
                    utils.friendly_date(prefs['browser']['last_clear_browsing_data_time']),
                    'Last time the history was cleared')
            check_and_append_pref(prefs['browser'], 'clear_lso_data_enabled')
            if prefs['browser'].get('clear_data'):
                try:
                    check_and_append_pref(
                        prefs['browser']['clear_data'], 'time_period',
                        description='0: past hour; 1: past day; 2: past week; 3: last 4 weeks; '
                                    '4: the beginning of time')
                    check_and_append_pref(prefs['browser']['clear_data'], 'content_licenses')
                    check_and_append_pref(prefs['browser']['clear_data'], 'hosted_apps_data')
                    check_and_append_pref(prefs['browser']['clear_data'], 'cookies')
                    check_and_append_pref(prefs['browser']['clear_data'], 'download_history')
                    check_and_append_pref(prefs['browser']['clear_data'], 'browsing_history')
                    check_and_append_pref(prefs['browser']['clear_data'], 'passwords')
                    check_and_append_pref(prefs['browser']['clear_data'], 'form_data')
                except Exception as e:
                    log.exception(f' - Exception parsing Preference item: {e})')

        append_group('Per Host Zoom Levels', 'These settings persist even when the history is cleared, and may be '
                                             'useful in some cases.')

        # Source: https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/common/page/page_zoom.cc
        def zoom_level_to_zoom_factor(zoom_level):
            if not zoom_level:
                return ''
            try:
                zoom_factor = round(math.pow(1.2, zoom_level), 2)
                return f'{zoom_factor:.0%}'
            except:
                return zoom_level

        # There may be per_host_zoom_levels keys in at least two locations: profile.per_host_zoom_levels and
        # partition.per_host_zoom_levels. The "profile." location may have been deprecated; unsure.
        if prefs.get('profile'):
            if prefs['profile'].get('per_host_zoom_levels'):
                try:
                    for zoom in list(prefs['profile']['per_host_zoom_levels'].keys()):
                        check_and_append_pref(prefs['profile']['per_host_zoom_levels'], zoom,
                                              zoom_level_to_zoom_factor(zoom))
                except Exception as e:
                    log.exception(f' - Exception parsing Preference item: {e})')

        if prefs.get('partition'):
            if prefs['partition'].get('per_host_zoom_levels'):
                try:
                    for partition_key, zoom_levels in list(prefs['partition']['per_host_zoom_levels'].items()):
                        for host, config in zoom_levels.items():
                            if isinstance(config, float):
                                # Example:
                                #  "dfir.blog": -0.5778829311823857
                                append_pref(host, zoom_level_to_zoom_factor(config))
                            elif isinstance(config, dict):
                                # Example:
                                # "dfir.blog": {
                                #     "last_modified": "13252995901366133",
                                #     "zoom_level": -0.5778829311823857
                                #   }
                                append_pref(host, zoom_level_to_zoom_factor(config.get('zoom_level')))
                                timestamped_preference_item = Chrome.SiteSetting(
                                    self.profile_path, url=host,
                                    timestamp=utils.to_datetime(config.get('last_modified'), self.timezone),
                                    key=f'per_host_zoom_levels [in {preferences_file}.partition]',
                                    value=f'Changed zoom level to {zoom_level_to_zoom_factor(config.get("zoom_level"))}',
                                    interpretation='')
                                timestamped_preference_item.row_type += ' (zoom level)'
                                timestamped_preference_item.source_item = source_item
                                timestamped_preference_items.append(timestamped_preference_item)
                except Exception as e:
                    log.exception(f' - Exception parsing Preference item: {e})')

        if prefs.get('password_manager'):
            if prefs['password_manager'].get('profile_store_date_last_used_for_filling'):
                timestamped_preference_item = Chrome.SiteSetting(
                    self.profile_path, url='',
                    timestamp=utils.to_datetime(
                        prefs['password_manager']['profile_store_date_last_used_for_filling'], self.timezone),
                    key=f'profile_store_date_last_used_for_filling [in {preferences_file}.password_manager]',
                    value=prefs['password_manager']['profile_store_date_last_used_for_filling'], interpretation='')
                timestamped_preference_item.row_type += ' (password fill)'
                timestamped_preference_item.source_item = source_item
                timestamped_preference_items.append(timestamped_preference_item)

        if prefs.get('profile'):
            if prefs['profile'].get('content_settings'):
                if prefs['profile']['content_settings'].get('pattern_pairs'):
                    try:
                        append_group('Profile Content Settings', 'These settings persist even when the history is '
                                                                 'cleared, and may be useful in some cases.')
                        for pair in list(prefs['profile']['content_settings']['pattern_pairs'].keys()):
                            # Adding the space before the domain prevents Excel from freaking out...  idk.
                            append_pref(' '+str(pair), str(prefs['profile']['content_settings']['pattern_pairs'][pair]))
                    except Exception as e:
                        log.exception(f' - Exception parsing Preference item: {e})')

                if prefs['profile']['content_settings'].get('exceptions'):

                    for exception_type, exception_data in prefs['profile']['content_settings']['exceptions'].items():
                        try:
                            if not isinstance(exception_data, dict):
                                continue
                            for origin, pref_data in exception_data.items():
                                if pref_data.get('last_modified') and pref_data.get('last_modified') != '0':
                                    row_type_suffix = ' (modified)'
                                    interpretation = ''

                                    # The setting value can be an int that maps to an enum, or a dict for a more
                                    # complicated setting. If it's the simpler int value, translate the enum.
                                    content_settings_values = {
                                        0: 'default',
                                        1: 'allow',
                                        2: 'block'
                                    }

                                    if isinstance(pref_data.get('setting'), int):
                                        interpretation = f'"{exception_type}" set to {pref_data["setting"]} ' \
                                                         f'({content_settings_values.get(pref_data["setting"])})'

                                    pref_item = Chrome.SiteSetting(
                                        self.profile_path, url=origin,
                                        timestamp=utils.to_datetime(pref_data['last_modified'], self.timezone),
                                        key=f'{exception_type} '
                                            f'[in {preferences_file}.profile.content_settings.exceptions]',
                                        value=str(pref_data), interpretation=interpretation)
                                    pref_item.row_type += row_type_suffix
                                    pref_item.source_item = source_item
                                    timestamped_preference_items.append(pref_item)

                                if exception_type.endswith('_engagement'):
                                    row_type_suffix = ' (engagement)'
                                    media_playback_time = pref_data['setting'].get('lastMediaPlaybackTime', 0.0)
                                    engagement_time = pref_data['setting'].get('lastEngagementTime', 0.0)

                                    if media_playback_time:
                                        engagement_item = Chrome.SiteSetting(
                                            self.profile_path, url=origin,
                                            timestamp=utils.to_datetime(media_playback_time, self.timezone),
                                            key=f'lastMediaPlaybackTime in {preferences_file}.profile.'
                                                f'content_settings.exceptions.media_engagement]',
                                            value=str(pref_data), interpretation='')
                                        engagement_item.row_type += row_type_suffix
                                        engagement_item.source_item = source_item
                                        timestamped_preference_items.append(engagement_item)

                                    elif engagement_time:
                                        engagement_item = Chrome.SiteSetting(
                                            self.profile_path, url=origin,
                                            timestamp=utils.to_datetime(engagement_time, self.timezone),
                                            key=f'lastEngagementTime in {preferences_file}.profile.'
                                                f'content_settings.exceptions.site_engagement]',
                                            value=str(pref_data), interpretation='')
                                        engagement_item.row_type += row_type_suffix
                                        engagement_item.source_item = source_item
                                        timestamped_preference_items.append(engagement_item)

                        except Exception as e:
                            log.exception(f' - Exception parsing Preference item: {e})')

                if prefs['profile']['content_settings'].get('permission_actions'):
                    permission_action_enum = {
                        0: 'granted',
                        1: 'denied',
                        2: 'dismissed',
                        3: 'ignored',
                        4: 'revoked',
                        5: 'granted once'
                    }

                    prompt_disposition_enum = {
                        0: "no prompt (ex: changed via settings)",
                        1: "anchored bubble under padlock (desktop)",
                        2: "static right-side location-bar icon (desktop)",
                        3: "animated right-side location-bar icon (desktop)",
                        4: "modal dialog (android)",
                        5: "collapsed bottom infobar (android)",
                        6: "chip on left-hand side of location bar (desktop)",
                        7: "no UI shown (tab closed with pending request)",
                        8: "custom modal dialog",
                        9: "quiet left-side chip; click shows bubble (desktop)",
                        10: "message bubble UI; infobar alternative (android)",
                        11: "quiet abusive chip; auto-shows bubble (desktop)",
                        12: "left-side chip; auto-shows bubble (desktop)",
                        13: "anchored bubble from clicking permission element",
                        14: "native OS permission prompt (macos)",
                        15: "loud message bubble UI (android)",
                    }

                    for permission_type, permission_data_list in prefs['profile']['content_settings']['permission_actions'].items():
                        for permission_data in permission_data_list:
                            interpretation = f'{permission_type} permission was {permission_action_enum.get(permission_data.get("action"))}'

                            if permission_data.get('prompt_disposition'):
                                interpretation += f' via {prompt_disposition_enum.get(permission_data["prompt_disposition"])}'

                            perm_item = Chrome.SiteSetting(
                                self.profile_path, url='',
                                timestamp=utils.to_datetime(permission_data['time'], self.timezone),
                                key=f'{permission_type} '
                                    f'[in {preferences_file}.profile.content_settings.permission_actions]',
                                value=str(permission_data), interpretation=interpretation)
                            perm_item.row_type = 'permission action'
                            perm_item.source_item = source_item
                            timestamped_preference_items.append(perm_item)

        if prefs.get('extensions'):
            if prefs['extensions'].get('autoupdate'):
                # Example (from in Preferences file):
                # "extensions": {
                #     ...
                #     "autoupdate": {
                #         "last_check": "13162668769688981",
                #         "next_check": "13162686093672995"
                #     },
                try:
                    if prefs['extensions']['autoupdate'].get('last_check'):
                        pref_item = Chrome.PreferenceItem(
                            self.profile_path, url='',
                            timestamp=utils.to_datetime(prefs['extensions']['autoupdate']['last_check'], self.timezone),
                            key=f'autoupdate.last_check [in {preferences_file}.extensions]',
                            value=prefs['extensions']['autoupdate']['last_check'], interpretation='')
                        pref_item.source_item = source_item
                        timestamped_preference_items.append(pref_item)
                except Exception as e:
                    log.exception(f' - Exception parsing Preference item: {e})')

        if prefs.get('sessions'):
            if prefs['sessions'].get('event_log'):
                # Source: https://source.chromium.org/chromium/chromium/src/
                #  +/main:chrome/browser/sessions/session_service_log.h
                session_types = {
                    0: 'Start (The profile was started)',
                    1: 'Restore (A restore was triggered)',
                    2: 'Exit (The profile was shut down)',
                    3: 'Write Error (an error in writing the file occurred)',
                    4: 'Restore canceled',
                    5: 'Restore initiated (browser will ask SessionService to restore async)',
                }

                for session_event in prefs['sessions']['event_log']:
                    pref_item = Chrome.PreferenceItem(
                        self.profile_path, url='',
                        timestamp=utils.to_datetime(session_event['time'], self.timezone),
                        key=f'Session event log [in {preferences_file}.sessions]',
                        value=str(session_event),
                        interpretation=f'{session_event["type"]} - '
                                       f'{session_types.get(session_event["type"], "Unknown type")}')
                    pref_item.row_type = 'session'
                    pref_item.source_item = source_item
                    timestamped_preference_items.append(pref_item)

        if prefs.get('signin'):
            if prefs['signin'].get('signedin_time'):
                # Example (from in Preferences file):
                # "signin": {
                #     "signedin_time": "13196354823425155"
                #  },
                try:
                    pref_item = Chrome.PreferenceItem(
                        self.profile_path, url='',
                        timestamp=utils.to_datetime(prefs['signin']['signedin_time'], self.timezone),
                        key=f'signedin_time [in {preferences_file}.signin]',
                        value=prefs['signin']['signedin_time'], interpretation='')
                    pref_item.source_item = source_item
                    timestamped_preference_items.append(pref_item)
                except Exception as e:
                    log.exception(f' - Exception parsing Preference item: {e})')

        if prefs.get('sync'):
            append_group('Sync Settings')
            if prefs['sync'].get('last_poll_time'):
                check_and_append_pref(prefs['sync'], 'last_poll_time',
                                      utils.friendly_date(prefs['sync']['last_poll_time']))

            if prefs['sync'].get('last_synced_time'):
                check_and_append_pref(prefs['sync'], 'last_synced_time',
                                      utils.friendly_date(prefs['sync']['last_synced_time']))

            sync_enabled_items = ['apps', 'autofill', 'bookmarks', 'cache_guid', 'extensions', 'gaia_id',
                                  'has_setup_completed', 'keep_everything_synced', 'passwords', 'preferences',
                                  'requested', 'tabs', 'themes', 'typed_urls']

            for sync_pref in list(prefs['sync'].keys()):
                if sync_pref not in sync_enabled_items:
                    continue

                check_and_append_pref(prefs['sync'], sync_pref)

        if prefs.get('translate_last_denied_time_for_language'):
            try:
                for lang_code, timestamp in prefs['translate_last_denied_time_for_language'].items():
                    # Example (from in Preferences file):
                    # "translate_last_denied_time_for_language": {
                    #   'ar': 1438733440742.06,
                    #   'th': [1447786189498.162],
                    #   'hi': 1438798234384.275,
                    #  },
                    if isinstance(timestamp, list):
                        timestamp = timestamp[0]
                    assert isinstance(timestamp, float)
                    pref_item = Chrome.PreferenceItem(
                        self.profile_path, url='', timestamp=utils.to_datetime(timestamp, self.timezone),
                        key=f'translate_last_denied_time_for_language [in {preferences_file}]',
                        value=f'{lang_code}: {timestamp}',
                        interpretation=f'Declined to translate page from {expand_language_code(lang_code)}')
                    pref_item.source_item = source_item
                    timestamped_preference_items.append(pref_item)
            except Exception as e:
                log.exception(f' - Exception parsing Preference item: {e})')

        if prefs.get('profile'):
            if prefs['profile'].get('creation_time'):
                try:
                    pref_item = Chrome.PreferenceItem(
                        self.profile_path, url='',
                        timestamp=utils.to_datetime(prefs['profile']['creation_time'], self.timezone),
                        key=f'creation_time [in {preferences_file}.profile]',
                        value=prefs['profile']['creation_time'], interpretation='')
                    pref_item.row_type = 'profile creation'
                    pref_item.source_item = source_item
                    timestamped_preference_items.append(pref_item)
                except Exception as e:
                    log.exception(f' - Exception parsing Preference item: {e})')

        # There are multiple instances of a preference item with the key as a descriptive name
        # and the value as a timestamp. Try to parse these generically (with a timestamp "floor"
        # to not erroneously parse any integer or boolean values as very small timestamps).
        # Keys that are explicitly parsed above are skipped here to avoid duplicates.
        explicitly_parsed_keys = {'profile.creation_time'}
        timestamp_floor = datetime.datetime(2010, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)

        def parse_potential_timestamp_preference_value(key_label, raw_value):
            if key_label in explicitly_parsed_keys:
                return
            if isinstance(raw_value, (list, dict)):
                return

            parsed_timestamp = utils.to_datetime(raw_value, timezone=self.timezone, quiet=True)
            if parsed_timestamp < timestamp_floor:
                return

            pref_item = Chrome.PreferenceItem(
                self.profile_path, url='', timestamp=parsed_timestamp,
                key=f'{key_label} [in {preferences_file}]',
                value=f'{raw_value}', interpretation='')
            pref_item.source_item = source_item
            timestamped_preference_items.append(pref_item)

        for top_level_key, value in prefs.items():
            parse_potential_timestamp_preference_value(top_level_key, value)

            if isinstance(value, dict):
                # Try the same approach one level deep as well
                for second_level_key, second_value in value.items():
                    parse_potential_timestamp_preference_value(f'{top_level_key}.{second_level_key}', second_value)

        self.parsed_artifacts.extend(timestamped_preference_items)

        self.artifacts_counts[preferences_file] = len(results) + len(timestamped_preference_items)
        log.info(f' - Parsed {self.artifacts_counts[preferences_file]} items')

        try:
            profile_folder = os.path.split(path)[1]
        except:
            profile_folder = 'error'

        presentation = {'title': f'Preferences ({profile_folder})',
                        'columns': [
                            {'display_name': 'Group',
                             'data_name': 'group',
                             'display_width': 8},
                            {'display_name': 'Setting Name',
                             'data_name': 'name',
                             'display_width': 40},
                            {'display_name': 'Value',
                             'data_name': 'value',
                             'display_width': 35},
                            {'display_name': 'Description',
                             'data_name': 'description',
                             'display_width': 60},
                            ]}

        self.preferences.append({'data': results, 'presentation': presentation})

    def get_platform_notifications(self, path, dir_name):
        try:
            from ccl_chromium_reader.ccl_chromium_notifications import NotificationReader
        except ImportError as e:
            log.exception(f' - Exception importing ccl_chromium_notifications: {e}')
            self.artifacts_counts['Platform Notifications'] = 'Failed'
            return

        result_list = []
        log.info('Platform Notifications:')
        pn_root_path = os.path.join(path, dir_name)
        log.info(f' - Reading from {pn_root_path}')
        source_item = os.path.relpath(pn_root_path, self.profile_path)

        try:
            with NotificationReader(pathlib.Path(pn_root_path)) as reader:
                for notification in reader.read_notifications():
                    try:
                        # CCL returns naive UTC datetimes; mark as UTC before timezone conversion
                        creation_time = notification.creation_time.replace(
                            tzinfo=datetime.timezone.utc)
                        timestamp = utils.to_datetime(creation_time, self.timezone)

                        # Build structured value with available fields (excluding title, shown in key)
                        value_parts = []
                        if notification.body:
                            value_parts.append(f'Body: {notification.body}')
                        if notification.icon:
                            value_parts.append(f'Icon: {notification.icon}')
                        if notification.image:
                            value_parts.append(f'Image: {notification.image}')
                        if notification.badge:
                            value_parts.append(f'Badge: {notification.badge}')
                        if notification.closed_reason is not None:
                            value_parts.append(f'Closed Reason: {notification.closed_reason.name}')
                        if notification.timestamp:
                            value_parts.append(f'App Timestamp: {notification.timestamp}')
                        if notification.time_until_first_click_millis:
                            value_parts.append(f'First Click: {notification.time_until_first_click_millis}ms')
                        if notification.time_until_last_click_millis:
                            value_parts.append(f'Last Click: {notification.time_until_last_click_millis}ms')
                        if notification.time_until_close_millis:
                            value_parts.append(f'Close Time: {notification.time_until_close_millis}ms')
                        if notification.actions:
                            actions_str = '; '.join(
                                f'{a.title} ({a.action})' for a in notification.actions if a.title)
                            if actions_str:
                                value_parts.append(f'Actions: {actions_str}')
                        if notification.data is not None:
                            value_parts.append(f'Data: {notification.data}')

                        value = '\n'.join(value_parts)

                        pn_record = Chrome.SiteSetting(
                            self.profile_path, url=notification.origin,
                            timestamp=timestamp,
                            key=notification.title or '',
                            value=value, interpretation='')
                        pn_record.row_type = 'notification (shown)'
                        pn_record.source_item = source_item
                        result_list.append(pn_record)

                        # Create click event records from first/last click offsets
                        click_times = set()
                        if notification.time_until_first_click_millis:
                            click_times.add(notification.time_until_first_click_millis)
                        if notification.time_until_last_click_millis:
                            click_times.add(notification.time_until_last_click_millis)

                        for click_ms in click_times:
                            click_timestamp = utils.to_datetime(
                                creation_time + datetime.timedelta(milliseconds=click_ms),
                                self.timezone)
                            click_record = Chrome.SiteSetting(
                                self.profile_path, url=notification.origin,
                                timestamp=click_timestamp,
                                key=notification.title or '',
                                value=value, interpretation='')
                            click_record.row_type = 'notification (clicked)'
                            click_record.source_item = source_item
                            result_list.append(click_record)

                    except Exception as e:
                        log.warning(f' - Exception parsing notification: {e}')

        except Exception as e:
            log.warning(f' - Could not open {pn_root_path} as LevelDB; {e}')
            self.artifacts_counts['Platform Notifications'] = 'Failed'
            return

        log.info(f' - Parsed {len(result_list)} items')
        self.artifacts_counts['Platform Notifications'] = len(result_list)
        self.parsed_artifacts.extend(result_list)

    def get_service_workers(self, path, dir_name):
        """Parse service worker registrations from the Service Worker/Database LevelDB.

        Decodes the ServiceWorkerRegistrationData protobuf stored under REG: keys.
        See content/browser/service_worker/service_worker_database.proto in Chromium.
        """
        results = []

        sw_root_path = os.path.join(path, dir_name)
        ldb_path = os.path.join(sw_root_path, 'Database')
        log.info('Service Workers:')
        log.info(f' - Reading from {ldb_path}')

        if not os.path.isdir(ldb_path):
            log.error(f' - {ldb_path} is not a directory')
            self.artifacts_counts['Service Workers'] = 'Failed'
            return

        log.info(f' - Using ccl_leveldb v{ccl_chromium_reader.storage_formats.ccl_leveldb.__version__}')

        ldb_records = None
        try:
            ldb_records = ccl_chromium_reader.storage_formats.ccl_leveldb.RawLevelDb(pathlib.Path(ldb_path))
        except ValueError as e:
            log.warning(f' - Error reading records ({e}); possible LevelDB corruption')
            self.artifacts_counts['Service Workers'] = 'Failed'
            return

        from pyhindsight.lib.proto.components.services.storage.service_worker.service_worker_database_pb2 import \
            ServiceWorkerRegistrationData, ServiceWorkerResourceRecord
        from pyhindsight.lib.sw_user_data import decode_user_data

        def enum_name(descriptor, value):
            if value is None:
                return None
            ev = descriptor.values_by_number.get(value)
            return ev.name if ev else value

        # Pass 1: scan the entire LDB to build lookup maps. PRES (purgeable)
        # records carry only the resource_id in their key; to backfill the
        # scope we need resource_id -> version_id (from RES:/URES: keys, even
        # deleted ones in the log) and version_id -> scope_url (from any REG:
        # value, live or historical). RES:/URES: scopes also benefit, since
        # iteration order isn't guaranteed to put REG: before its resources.
        # REG_USER_DATA: records use registration_id directly (not version_id),
        # so we also build registration_id -> scope_url.
        seen_reg_ids = set()
        version_to_scope = {}
        regid_to_scope = {}
        resource_to_version = {}
        # resource_id -> (url, sha256_hex_or_None) from RES:/URES: proto values.
        # Used to enrich ScriptCache/ body rows with the URL the script was
        # fetched from and to verify on-disk bytes against the LDB-recorded hash.
        resource_to_record = {}

        for record in ldb_records.iterate_records_raw():
            key = record.user_key
            if key.startswith(b'REG:'):
                nul_pos = key.rfind(b'\x00')
                if nul_pos > len(b'REG:'):
                    try:
                        seen_reg_ids.add(int(key[nul_pos + 1:]))
                    except ValueError:
                        pass
                if record.value:
                    try:
                        reg = ServiceWorkerRegistrationData()
                        reg.ParseFromString(record.value)
                        version_to_scope.setdefault(reg.version_id, reg.scope_url)
                        regid_to_scope.setdefault(reg.registration_id, reg.scope_url)
                    except Exception:
                        pass
            elif key.startswith(b'RES:') or key.startswith(b'URES:'):
                prefix_len = 4 if key.startswith(b'RES:') else 5
                rest = key[prefix_len:]
                nul_pos = rest.find(b'\x00')
                if nul_pos < 0:
                    continue
                try:
                    version_id = int(rest[:nul_pos])
                    resource_id = int(rest[nul_pos + 1:])
                except ValueError:
                    continue
                resource_to_version.setdefault(resource_id, version_id)
                if record.value and resource_id not in resource_to_record:
                    try:
                        rr = ServiceWorkerResourceRecord()
                        rr.ParseFromString(record.value)
                        url = rr.url if rr.HasField('url') else None
                        sha = rr.sha256_checksum if rr.HasField('sha256_checksum') else None
                        resource_to_record[resource_id] = (url, sha)
                    except Exception:
                        pass

        def scope_for_resource(resource_id, version_id=None):
            if version_id is None:
                version_id = resource_to_version.get(resource_id)
            if version_id is None:
                return None, None
            return version_id, version_to_scope.get(version_id)

        # User-data dispatcher lives in pyhindsight.lib.sw_user_data; each
        # known REG_USER_DATA: subsystem has its own decoder module. Imported
        # at the top of this method.

        # Pass 2: emit records, using the maps to enrich resource rows.
        regid_to_origin_records = []
        registration_count = 0
        resource_count = 0
        user_data_count = 0

        try:
            for record in ldb_records.iterate_records_raw():
                key = record.user_key

                if key.startswith(b'REG:'):
                    if not record.value:
                        continue  # deletion marker

                    reg = ServiceWorkerRegistrationData()
                    try:
                        reg.ParseFromString(record.value)
                    except Exception as e:
                        log.warning(f' - Failed to decode REG record: {e}')
                        continue

                    nav_preload_enabled = None
                    nav_preload_header = None
                    if reg.HasField('navigation_preload_state'):
                        nav_preload_enabled = reg.navigation_preload_state.enabled
                        if reg.navigation_preload_state.HasField('header'):
                            nav_preload_header = reg.navigation_preload_state.header

                    results.append(Chrome.ServiceWorkerItem(
                        profile=self.profile_path,
                        origin=reg.scope_url,
                        scope_url=reg.scope_url,
                        script_url=reg.script_url,
                        registration_id=reg.registration_id,
                        version_id=reg.version_id,
                        is_active=reg.is_active,
                        has_fetch_handler=reg.has_fetch_handler,
                        last_update_check_time=utils.to_datetime(reg.last_update_check_time, self.timezone),
                        resources_total_size_bytes=reg.resources_total_size_bytes if reg.HasField(
                            'resources_total_size_bytes') else None,
                        navigation_preload_enabled=nav_preload_enabled,
                        navigation_preload_header=nav_preload_header,
                        update_via_cache=enum_name(
                            ServiceWorkerRegistrationData.ServiceWorkerUpdateViaCacheType.DESCRIPTOR,
                            reg.update_via_cache),
                        script_type=enum_name(
                            ServiceWorkerRegistrationData.ServiceWorkerScriptType.DESCRIPTOR,
                            reg.script_type),
                        script_response_time=utils.to_datetime(reg.script_response_time, self.timezone)
                            if reg.HasField('script_response_time') else None,
                        seq=record.seq,
                        state=record.state.name,
                        source_path=str(record.origin_file),
                    ))
                    registration_count += 1

                elif key.startswith(b'REGID_TO_ORIGIN:'):
                    try:
                        reg_id = int(key[len(b'REGID_TO_ORIGIN:'):])
                    except ValueError:
                        continue
                    origin = record.value.decode('utf-8', errors='replace') if record.value else ''
                    regid_to_origin_records.append((record, reg_id, origin))

                elif key.startswith(b'RES:') or key.startswith(b'URES:'):
                    is_committed = key.startswith(b'RES:')
                    prefix = b'RES:' if is_committed else b'URES:'
                    rest = key[len(prefix):]
                    nul_pos = rest.find(b'\x00')
                    if nul_pos < 0:
                        continue
                    try:
                        version_id = int(rest[:nul_pos])
                        resource_id_from_key = int(rest[nul_pos + 1:])
                    except ValueError:
                        continue

                    url = None
                    size_bytes = None
                    sha256 = None
                    if record.value:
                        rr = ServiceWorkerResourceRecord()
                        try:
                            rr.ParseFromString(record.value)
                            url = rr.url
                            size_bytes = rr.size_bytes if rr.HasField('size_bytes') else None
                            sha256 = rr.sha256_checksum if rr.HasField('sha256_checksum') else None
                        except Exception as e:
                            log.warning(f' - Failed to decode {prefix.decode()} record: {e}')

                    results.append(Chrome.ServiceWorkerResourceItem(
                        profile=self.profile_path,
                        scope_url=version_to_scope.get(version_id),
                        version_id=version_id,
                        resource_id=resource_id_from_key,
                        url=url,
                        size_bytes=size_bytes,
                        sha256_checksum=sha256,
                        resource_state='committed' if is_committed else 'uncommitted',
                        seq=record.seq,
                        state=record.state.name,
                        source_path=str(record.origin_file),
                    ))
                    resource_count += 1

                elif key.startswith(b'PRES:'):
                    # Purgeable: empty value, key carries only the resource_id.
                    # Backfill version_id and scope from the maps built in pass 1.
                    try:
                        resource_id = int(key[len(b'PRES:'):])
                    except ValueError:
                        continue
                    version_id, scope = scope_for_resource(resource_id)
                    results.append(Chrome.ServiceWorkerResourceItem(
                        profile=self.profile_path,
                        scope_url=scope,
                        version_id=version_id,
                        resource_id=resource_id,
                        url=None,
                        size_bytes=None,
                        sha256_checksum=None,
                        resource_state='purgeable',
                        seq=record.seq,
                        state=record.state.name,
                        source_path=str(record.origin_file),
                    ))
                    resource_count += 1

                elif key.startswith(b'REG_USER_DATA:'):
                    # REG_USER_DATA:<registration_id>\x00<user_data_key>
                    # Value is opaque bytes, often a subsystem-defined protobuf.
                    rest = key[len(b'REG_USER_DATA:'):]
                    nul_pos = rest.find(b'\x00')
                    if nul_pos < 0:
                        continue
                    try:
                        ud_reg_id = int(rest[:nul_pos])
                    except ValueError:
                        continue
                    try:
                        user_data_key = rest[nul_pos + 1:].decode('utf-8')
                    except UnicodeDecodeError:
                        user_data_key = rest[nul_pos + 1:].decode('utf-8', errors='replace')

                    if record.value:
                        subsystem, decoded, event_time = decode_user_data(
                            user_data_key, record.value, self.timezone)
                    else:
                        subsystem, decoded, event_time = ('user data', '', None)  # deletion marker

                    item = Chrome.ServiceWorkerUserDataItem(
                        profile=self.profile_path,
                        scope_url=regid_to_scope.get(ud_reg_id),
                        registration_id=ud_reg_id,
                        user_data_key=user_data_key,
                        subsystem=subsystem,
                        decoded_value=decoded,
                        raw_value_size=len(record.value) if record.value else 0,
                        seq=record.seq,
                        state=record.state.name,
                        source_path=str(record.origin_file),
                        event_time=event_time,
                    )
                    item.row_type = f'service worker ({subsystem})'
                    results.append(item)
                    user_data_count += 1

            # Orphan REGID_TO_ORIGIN entries: live reverse-index records whose
            # registration_id never appeared in any REG: key in this LDB. These
            # indicate a SW that was registered, then had its REG: record
            # cleaned up (or compacted away) without the reverse index also
            # being deleted — useful "ghost" evidence.
            orphan_count = 0
            for rec, reg_id, origin in regid_to_origin_records:
                if reg_id in seen_reg_ids:
                    continue
                if rec.state.name != 'Live':
                    continue
                orphan = Chrome.ServiceWorkerItem(
                    profile=self.profile_path,
                    origin=origin,
                    scope_url=origin,
                    script_url=None,
                    registration_id=reg_id,
                    version_id=None,
                    is_active=None,
                    has_fetch_handler=None,
                    last_update_check_time=None,
                    resources_total_size_bytes=None,
                    navigation_preload_enabled=None,
                    navigation_preload_header=None,
                    update_via_cache=None,
                    script_type=None,
                    script_response_time=None,
                    seq=rec.seq,
                    state=rec.state.name,
                    source_path=str(rec.origin_file),
                )
                orphan.row_type = 'service worker (orphan registration)'
                results.append(orphan)
                orphan_count += 1
        finally:
            ldb_records.close()

        # ScriptCache/ extraction. Sibling directory to Database/; a Chromium
        # simple disk_cache keyed by the resource_id (as ASCII). Lets us
        # recover the actual SW script bytes — including for resources whose
        # LDB rows are now Deleted/PRES: but whose bytes haven't yet been
        # purged from disk.
        script_cache_path = os.path.join(sw_root_path, 'ScriptCache')
        script_count = 0
        if os.path.isdir(script_cache_path):
            log.info(f' - Reading ScriptCache from {script_cache_path}')
            try:
                sc = ccl_chromium_reader.ccl_chromium_cache.ChromiumSimpleFileCache(
                    pathlib.Path(script_cache_path))
            except Exception as e:
                log.warning(f' - Could not open ScriptCache as disk_cache: {e}')
                sc = None
            if sc is not None:
                try:
                    for cache_key in sc.keys():
                        try:
                            resource_id = int(cache_key)
                        except ValueError:
                            # Non-numeric key — not a SW resource entry; skip.
                            continue
                        version_id = resource_to_version.get(resource_id)
                        ldb_url, ldb_sha256 = resource_to_record.get(
                            resource_id, (None, None))
                        scope = version_to_scope.get(version_id) if version_id is not None else None

                        # A given cache key can technically resolve to multiple
                        # entries (hash collisions / stale entries); iterate them.
                        try:
                            bodies = sc.get_cachefile(cache_key)
                            metas = sc.get_metadata(cache_key)
                            infos = sc.get_entry_info(cache_key)
                        except Exception as e:
                            log.warning(f' - Failed to read ScriptCache entry {cache_key}: {e}')
                            continue
                        for body, meta, info in zip(bodies, metas, infos):
                            body_sha = hashlib.sha256(body).hexdigest() if body else None
                            sha_match = None
                            if ldb_sha256 and body_sha:
                                sha_match = (body_sha.lower() == ldb_sha256.lower())

                            http_status = None
                            content_type = None
                            response_time = None
                            request_time = None
                            if meta is not None:
                                try:
                                    declarations = list(meta.http_header_declarations)
                                    if declarations:
                                        http_status = declarations[0]
                                except Exception:
                                    pass
                                try:
                                    for hname, hval in meta.http_header_attributes:
                                        if hname.lower() == 'content-type':
                                            content_type = hval
                                            break
                                except Exception:
                                    pass
                                # CachedMetadata.response_time is already a
                                # datetime (Windows epoch == 1601-01-01 means
                                # "not recorded"); only surface real values.
                                if meta.response_time and meta.response_time.year > 1601:
                                    response_time = utils.to_datetime(
                                        meta.response_time, self.timezone)
                                if meta.request_time and meta.request_time.year > 1601:
                                    request_time = utils.to_datetime(
                                        meta.request_time, self.timezone)

                            results.append(Chrome.ServiceWorkerScriptItem(
                                profile=self.profile_path,
                                scope_url=scope,
                                version_id=version_id,
                                resource_id=resource_id,
                                url=ldb_url,
                                http_status=http_status,
                                content_type=content_type,
                                body_size=len(body) if body is not None else None,
                                body_sha256=body_sha,
                                body_sha256_match=sha_match,
                                response_time=response_time,
                                request_time=request_time,
                                source_file=info.source_file if info else None,
                                source_path=os.path.join(script_cache_path,
                                                          info.source_file) if info else script_cache_path,
                            ))
                            script_count += 1
                finally:
                    sc.close()

        # CacheStorage/ extraction. Sibling directory holding per-origin
        # Chromium disk_caches populated by the Web Cache API (caches.put()).
        # Layout: CacheStorage/<origin-hash>/index.txt + <UUID>/ subdirs.
        cache_storage_path = os.path.join(sw_root_path, 'CacheStorage')
        cache_storage_count = 0
        if os.path.isdir(cache_storage_path):
            log.info(f' - Reading CacheStorage from {cache_storage_path}')
            from pyhindsight.lib.proto.content.browser.cache_storage.cache_storage_pb2 import (
                CacheStorageIndex, CacheMetadata, CacheResponse)
            simple_cache_file_cls = ccl_chromium_reader.ccl_chromium_cache.SimpleCacheFile
            for origin_hash_dir in os.listdir(cache_storage_path):
                origin_root = os.path.join(cache_storage_path, origin_hash_dir)
                if not os.path.isdir(origin_root):
                    continue
                index_path = os.path.join(origin_root, 'index.txt')
                if not os.path.isfile(index_path):
                    continue
                idx = CacheStorageIndex()
                try:
                    with open(index_path, 'rb') as f:
                        idx.ParseFromString(f.read())
                except Exception as e:
                    log.warning(f' - Failed to parse {index_path}: {e}')
                    continue

                storage_key = idx.storage_key if idx.HasField('storage_key') \
                    else (idx.origin if idx.HasField('origin') else None)

                for cache_meta in idx.cache:
                    cache_uuid = cache_meta.cache_dir if cache_meta.HasField('cache_dir') else ''
                    if cache_meta.HasField('u16string_name'):
                        try:
                            cache_name = cache_meta.u16string_name.decode('utf-16-le')
                        except UnicodeDecodeError:
                            cache_name = cache_meta.name
                    else:
                        cache_name = cache_meta.name
                    cache_subdir = os.path.join(origin_root, cache_uuid)
                    if not os.path.isdir(cache_subdir):
                        continue
                    try:
                        sc = ccl_chromium_reader.ccl_chromium_cache.ChromiumSimpleFileCache(
                            pathlib.Path(cache_subdir))
                    except Exception as e:
                        log.warning(f' - Could not open {cache_subdir} as disk_cache: {e}')
                        continue
                    try:
                        for cache_key in sc.keys():
                            try:
                                file_names = sc.get_file_for_key(cache_key)
                            except Exception:
                                continue
                            for fname in file_names:
                                scf_path = os.path.join(cache_subdir, fname)
                                try:
                                    scf = simple_cache_file_cls(scf_path)
                                    s0 = scf.get_stream_0()
                                    s1 = scf.get_stream_1()
                                    scf.close()
                                except Exception as e:
                                    log.warning(f' - Failed to read {scf_path}: {e}')
                                    continue

                                meta = CacheMetadata()
                                try:
                                    meta.ParseFromString(s0)
                                except Exception as e:
                                    log.warning(
                                        f' - Failed to parse CacheMetadata for {cache_key[:80]}: {e}')
                                    continue

                                entry_time = utils.to_datetime(meta.entry_time, self.timezone) \
                                    if meta.HasField('entry_time') else None
                                response_time = utils.to_datetime(
                                    meta.response.response_time, self.timezone) \
                                    if meta.response.HasField('response_time') else None
                                final_url = meta.response.url_list[-1] if meta.response.url_list else None
                                if final_url == cache_key:
                                    final_url = None  # don't duplicate the URL when it's identical
                                response_mime_type = meta.response.mime_type \
                                    if meta.response.HasField('mime_type') else None
                                body_sha = hashlib.sha256(s1).hexdigest() if s1 else None

                                results.append(Chrome.ServiceWorkerCacheStorageItem(
                                    profile=self.profile_path,
                                    storage_key=storage_key,
                                    origin_hash=origin_hash_dir,
                                    cache_name=cache_name,
                                    cache_uuid=cache_uuid,
                                    request_url=cache_key,
                                    request_method=meta.request.method,
                                    response_status=meta.response.status_code,
                                    response_status_text=meta.response.status_text,
                                    response_type=CacheResponse.ResponseType.Name(
                                        meta.response.response_type),
                                    response_mime_type=response_mime_type,
                                    final_url=final_url,
                                    body_size=len(s1) if s1 is not None else None,
                                    body_sha256=body_sha,
                                    entry_time=entry_time,
                                    response_time=response_time,
                                    source_file=fname,
                                    source_path=scf_path,
                                ))
                                cache_storage_count += 1

                                # Dual-emit to the Timeline as a cache row.
                                # CacheStorage entries are HTTP responses that
                                # JS explicitly chose to cache via caches.put();
                                # response_time is set by Chrome's network stack
                                # and is as reliable as the HTTP cache's
                                # response_time. The distinct row_type warns the
                                # reader that this row reflects a deliberate JS
                                # cache (which may be old precached content),
                                # not an automatic HTTP cache fill.
                                headers_dict = {}
                                for h in meta.response.headers:
                                    headers_dict[h.name] = h.value
                                etag_val = ''
                                last_mod_val = ''
                                for hname, hval in headers_dict.items():
                                    lname = hname.lower()
                                    if lname == 'etag' and not etag_val:
                                        etag_val = hval
                                    elif lname == 'last-modified' and not last_mod_val:
                                        last_mod_val = hval

                                body_size_val = len(s1) if s1 is not None else 0
                                mime_label = response_mime_type or 'not specified'
                                data_summary = f'{mime_label} ({body_size_val} bytes)'

                                tl_item = WebBrowser.CacheItem(
                                    profile=self.profile_path,
                                    url=cache_key,
                                    title=None,
                                    request_time=response_time,
                                    locations=f'cache: {cache_name!r}; uuid: {cache_uuid}; file: {fname}',
                                    key=cache_key,
                                    metadata=None,
                                    data=None,
                                )
                                tl_item.row_type = 'cache (service worker)'
                                tl_item.data_summary = data_summary
                                tl_item.http_headers_str = str(headers_dict) if headers_dict else ''
                                tl_item.etag = etag_val
                                tl_item.last_modified = last_mod_val
                                tl_item.source_item = os.path.relpath(
                                    scf_path, self.profile_path)
                                self.parsed_artifacts.append(tl_item)
                    finally:
                        sc.close()

        log.info(f' - Parsed {registration_count} registration records, '
                 f'{resource_count} resource records, {user_data_count} user-data records, '
                 f'{orphan_count} orphan registrations, {script_count} script bodies, '
                 f'{cache_storage_count} cache storage entries')
        self.artifacts_counts['Service Workers'] = len(results)
        self.parsed_storage.extend(results)

    def get_cache(self, path, dir_name, row_type=None):
        # Set up empty return array
        results = []

        cache_path_to_parse = pathlib.Path(path, dir_name)
        log.info(f'Cache items from {cache_path_to_parse}:')
        profile = ccl_chromium_reader.ChromiumProfileFolder(path=pathlib.Path(path), cache_folder=cache_path_to_parse)
        log.info(f' - Using ccl_chromium_cache v{ccl_chromium_reader.ccl_chromium_cache.__version__}')

        cache_display_name = dir_name
        if dir_name == 'Cache_Data':
            cache_display_name = 'Cache'

        # Using any() - returns True if directory has any contents
        if not any(pathlib.Path(cache_path_to_parse).iterdir()):
            log.info(' - Cache path is empty')
            return

        cache_items = profile.iterate_cache(url=None, omit_cached_data=False)
        source_item = os.path.relpath(os.path.join(path, dir_name), self.profile_path)

        try:
            for cache_item in cache_items:
                if not cache_item.metadata:
                    continue

                parsed_item = WebBrowser.CacheItem(
                    profile=self.profile_path, url=cache_item.key.url,
                    request_time=utils.to_datetime(cache_item.metadata.request_time.replace(tzinfo=datetime.timezone.utc), self.timezone),
                    locations=str({'data': cache_item.data_location, 'metadata': cache_item.metadata_location}),
                    key=cache_item.key, metadata=cache_item.metadata, data=cache_item.data, title=None)

                parsed_item.row_type = row_type
                parsed_item.data_summary = parsed_item.create_data_summary()
                parsed_item.stringify_http_headers()
                parsed_item.etag = (cache_item.metadata.get_attribute("etag") or [""])[0]
                parsed_item.last_modified = (cache_item.metadata.get_attribute("last-modified") or [""])[0]
                parsed_item.source_item = source_item

                results.append(parsed_item)

        except Exception as e:
            log.error(f' - Exception parsing Cache items: {e})', exc_info=True)
            self.artifacts_counts[cache_display_name] = 'Failed'
            return

        self.artifacts_counts[cache_display_name] = len(results)
        log.info(f' - Parsed {len(results)} items')
        self.parsed_artifacts.extend(results)

    def get_unified_extension_data(self, path, dir_name):
        results = []

        # Grab file list of input directory
        ldb_path = os.path.join(path, dir_name)
        log.info(f'{dir_name}:')
        log.info(f' - Reading from {ldb_path}')
        log.info(f' - Using ccl_leveldb v{ccl_chromium_reader.storage_formats.ccl_leveldb.__version__}')

        if not os.path.isdir(ldb_path):
            log.error(f' - {ldb_path} is not a directory')
            self.artifacts_counts[f'{dir_name}'] = 'Failed'
            return

        ldb_file_listing = os.listdir(ldb_path)
        log.debug(f' - {len(ldb_file_listing)} files in {dir_name} directory')

        ldb_records = None

        try:
            ldb_records = ccl_chromium_reader.storage_formats.ccl_leveldb.RawLevelDb(pathlib.Path(ldb_path))
        except ValueError as e:
            log.warning(f' - Error reading records ({e}); possible LevelDB corruption')
            self.artifacts_counts[f'{dir_name}'] = 'Failed'

        # For the 'Extension Scripts' StateStore, capture the latest (highest-seq,
        # non-deleted) 'dynamic_scripts' value per extension for the live merge, and ALSO
        # every physical record version (older seqs + deletion tombstones) so superseded /
        # removed dynamic scripts can be recovered. The '<ext_id>.dynamic_scripts'
        # StateStore key is scripting::kRegisteredScriptsStorageKey ("dynamic_scripts").
        # From https://source.chromium.org/chromium/chromium/src/+/main:extensions/browser/scripting_constants.h
        dynamic_scripts_raw = {}    # ext_id -> (seq, json_value)  -- current/live
        dynamic_scripts_all = []    # [(ext_id, seq, state, value)] -- every recoverable record

        if ldb_records:
            for record in ldb_records.iterate_records_raw():
                user_key = record.user_key.decode()
                ext_id = None
                ext_name = ""
                m = re.fullmatch(r'([a-p]{32})\.(.*)$', user_key)
                if m:
                    ext_id = m.group(1)
                    user_key = m.group(2)

                if ext_id:
                    ext_name = self.get_extension_name_from_id(ext_id)

                parsed = Chrome.ExtensionStorageItem(
                    profile=self.profile_path, extension_id=ext_id, extension_name=ext_name, key=user_key, value=record.value.decode(),
                    seq=record.seq, state=record.state.name, source_path=str(record.origin_file), offset=record.offset,
                    was_compressed=record.was_compressed)
                parsed.row_type = dir_name.lower()

                results.append(parsed)

                if dir_name == 'Extension Scripts' and ext_id and user_key == 'dynamic_scripts':
                    dynamic_scripts_all.append((ext_id, record.seq, record.state.name, parsed.value))
                    if record.state.name != 'Deleted':
                        prior = dynamic_scripts_raw.get(ext_id)
                        if prior is None or record.seq > prior[0]:
                            dynamic_scripts_raw[ext_id] = (record.seq, parsed.value)

            ldb_records.close()
            self.artifacts_counts[f'{dir_name}'] = len(results)

        if dynamic_scripts_raw:
            self._merge_dynamic_scripts(dynamic_scripts_raw)
        if dynamic_scripts_all:
            self._carve_dynamic_scripts(dynamic_scripts_all)

        log.info(f' - Parsed {len(results)} {dir_name} items')
        self.parsed_extension_data.extend(results)

    def get_dnr_extension_rules(self, path, dir_name):
        """Parse declarativeNetRequest DYNAMIC rules from
        ``<profile>/DNR Extension Rules/<ext_id>/rules.json``.
        """
        results = []
        dnr_path = os.path.join(path, dir_name)
        log.info(f'{dir_name}:')
        log.info(f' - Reading from {dnr_path}')

        if not os.path.isdir(dnr_path):
            log.error(f' - {dnr_path} is not a directory')
            self.artifacts_counts[dir_name] = 'Failed'
            return

        for ext_id in sorted(os.listdir(dnr_path)):
            ext_dir = os.path.join(dnr_path, ext_id)
            if not os.path.isdir(ext_dir):
                continue

            ext_name = self.get_extension_name_from_id(ext_id)
            rules_json = os.path.join(ext_dir, 'rules.json')
            if not os.path.isfile(rules_json):
                # The indexed flatbuffer can exist without a JSON copy; flag it so the
                # omission is visible rather than silently skipped.
                if os.path.isfile(os.path.join(ext_dir, 'rules.fbs')):
                    log.warning(f' - {ext_id}: rules.fbs present but no rules.json '
                                f'(flatbuffer decode not yet supported)')
                continue

            try:
                with open(rules_json, encoding='utf-8', errors='replace') as f:
                    rules = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                log.warning(f' - Error reading {rules_json}: {e}')
                continue

            if not isinstance(rules, list):
                log.warning(f' - Unexpected rules.json shape for {ext_id} (not a list)')
                continue

            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                # The extension-assigned rule id (rule['id']) is the only key-like value
                # in rules.json; surface it bare (the file itself is a flat JSON array
                # with no real on-disk keys).
                rule_id = rule.get('id')
                parsed = Chrome.ExtensionStorageItem(
                    profile=self.profile_path, extension_id=ext_id, extension_name=ext_name,
                    key='' if rule_id is None else str(rule_id),
                    value=json.dumps(rule, sort_keys=True),
                    state='Live', source_path=rules_json)
                parsed.row_type = dir_name.lower()
                results.append(parsed)

        self.artifacts_counts[dir_name] = len(results)
        log.info(f' - Parsed {len(results)} {dir_name} items')
        self.parsed_extension_data.extend(results)

    @staticmethod
    def _normalize_dynamic_script(entry):
        """Normalize a dynamically-registered script (Extension Scripts StateStore) to the
        same shape as a manifest content_scripts block. Dynamic scripts use camelCase keys
        and list their files as {'file': ...} / {'code': ...} objects, unlike the manifest.

        Field schema (id, matches, excludeMatches, js, css, runAt, allFrames, world,
        matchOriginAsFallback) from the chrome.scripting / chrome.userScripts API:
        From https://source.chromium.org/chromium/chromium/src/+/main:extensions/common/api/scripting.idl
        The 'source' value (USER_SCRIPT / DYNAMIC_CONTENT_SCRIPT) is the serialized
        UserScript::Source:
        From https://source.chromium.org/chromium/chromium/src/+/main:extensions/common/user_script.h
        """
        def file_list(items):
            out = []
            for it in items or []:
                if isinstance(it, dict):
                    out.append(it.get('file') or ('(inline code)' if 'code' in it else ''))
                else:
                    out.append(it)
            return [x for x in out if x]

        return {
            'id': entry.get('id'),
            'matches': entry.get('matches', []) or [],
            'exclude_matches': entry.get('excludeMatches') or entry.get('exclude_matches') or [],
            'run_at': entry.get('runAt') or entry.get('run_at'),
            'all_frames': entry.get('allFrames', entry.get('all_frames')),
            'world': entry.get('world'),
            'js': file_list(entry.get('js')),
            'css': file_list(entry.get('css')),
            # 'USER_SCRIPT' for chrome.userScripts, else a dynamic content script.
            'kind': entry.get('source') or 'DYNAMIC_CONTENT_SCRIPT',
        }

    @staticmethod
    def _extract_json_objects(text):
        """Best-effort recovery of top-level {...} objects from a (possibly truncated)
        JSON value, ignoring braces inside strings. Used to salvage individual scripts
        from partial LevelDB records the json parser can't load whole."""
        objects = []
        depth = 0
        start = None
        in_string = False
        escape = False
        for i, ch in enumerate(text):
            if in_string:
                if escape:
                    escape = False
                elif ch == '\\':
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == '}':
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start is not None:
                        objects.append(text[start:i + 1])
                        start = None
        return objects

    @staticmethod
    def _parse_dynamic_scripts_value(value):
        """Parse a dynamic_scripts record value into a list of script entries.
        Returns (entries, partial) where partial=True when the value could not be parsed
        as whole JSON and individual objects were salvaged instead."""
        try:
            data = json.loads(value)
            if isinstance(data, list):
                return data, False
            if isinstance(data, dict):
                return [data], False
            return [], False
        except (ValueError, TypeError):
            entries = []
            for frag in Chrome._extract_json_objects(value or ''):
                try:
                    entries.append(json.loads(frag))
                except (ValueError, TypeError):
                    continue
            return entries, True

    @staticmethod
    def _dynamic_script_sig(s):
        """Signature for de-duplicating recovered scripts against the live set and each
        other (independent of key ordering / list ordering)."""
        return (
            s.get('kind'), s.get('id'), s.get('run_at'), bool(s.get('all_frames')),
            s.get('world'),
            tuple(sorted(s.get('matches') or [])),
            tuple(sorted(s.get('exclude_matches') or [])),
            tuple(sorted(s.get('js') or [])),
            tuple(sorted(s.get('css') or [])),
        )

    def _get_or_create_extension(self, ext_id):
        ext = self._extensions_by_id.get(ext_id)
        if ext is None:
            ext = Chrome.BrowserExtension(
                profile=os.path.split(self.profile_path)[1], ext_id=ext_id, name=None,
                description=None, version=None, permissions=None, manifest=None)
            self._extensions_by_id[ext_id] = ext
        return ext

    def _merge_dynamic_scripts(self, dynamic_scripts_raw):
        merged = 0
        for ext_id, (_seq, value) in dynamic_scripts_raw.items():
            entries, partial = self._parse_dynamic_scripts_value(value)
            if not entries:
                continue
            ext = self._get_or_create_extension(ext_id)
            scripts = []
            for e in entries:
                if not isinstance(e, dict):
                    continue
                s = self._normalize_dynamic_script(e)
                if partial:
                    s['partial'] = True
                scripts.append(s)
            ext.dynamic_scripts = scripts
            merged += len(scripts)
        if merged:
            self._rebuild_installed_extensions()
            log.info(f' - Merged {merged} dynamically-registered script(s) into extension records')

    def _carve_dynamic_scripts(self, records):
        """Recover dynamic scripts from every physical 'dynamic_scripts' record (older
        sequence numbers and deletion tombstones), keeping those not present in the current
        live set -- i.e. scripts that were registered at some point and later removed."""
        # Signatures already represented in the live set, per extension.
        live_sigs = {}
        for ext_id, ext in self._extensions_by_id.items():
            live_sigs[ext_id] = {self._dynamic_script_sig(s)
                                 for s in (getattr(ext, 'dynamic_scripts', None) or [])}

        recovered = {}  # ext_id -> {sig: script}
        for ext_id, _seq, state, value in records:
            entries, partial = self._parse_dynamic_scripts_value(value)
            for e in entries:
                if not isinstance(e, dict):
                    continue
                s = self._normalize_dynamic_script(e)
                sig = self._dynamic_script_sig(s)
                if sig in live_sigs.get(ext_id, set()):
                    continue  # still registered; shown as a live row already
                slot = recovered.setdefault(ext_id, {})
                if sig not in slot:
                    s['partial'] = partial
                    s['recovered_state'] = state
                    slot[sig] = s

        count = 0
        for ext_id, slot in recovered.items():
            if not slot:
                continue
            ext = self._get_or_create_extension(ext_id)
            ext.historical_dynamic_scripts = list(slot.values())
            count += len(slot)
        if count:
            self._rebuild_installed_extensions()
            log.info(f' - Recovered {count} historical/removed dynamic script(s) from superseded records')

    def get_partitioned_extension_data(self, path, dir_name):
        results = []
        any_failed = False

        # Grab file list of input directory
        top_path = os.path.join(path, dir_name)
        log.info(f'{dir_name}:')
        log.info(f' - Reading from {top_path}')
        if not os.path.isdir(top_path):
            log.error(f' - {top_path} is not a directory')
            self.artifacts_counts[f'{dir_name}'] = 'Failed'
            return

        top_file_listing = os.listdir(top_path)

        # Only process directories with the expected naming convention
        # (Chrome extension IDs are 32 chars in a-p: the first 128 bits of a
        # SHA-256 of the extension's public key, with hex digits 0-f remapped to a-p)
        ext_id_re = re.compile(r'^([a-p]{32})$')
        ext_listing = [str(x) for x in top_file_listing if ext_id_re.match(x)]
        log.debug(f' - {len(ext_listing)} files in {dir_name} directory will be processed: {str(ext_listing)}')

        for ext_id in ext_listing:
            # Grab file list of input directory
            ldb_path = os.path.join(path, dir_name, ext_id)
            log.info(f'{dir_name}:')
            log.info(f' - Reading from {ldb_path}')
            log.info(f' - Using ccl_leveldb v{ccl_chromium_reader.storage_formats.ccl_leveldb.__version__}')

            if not os.path.isdir(ldb_path):
                log.error(f' - {ldb_path} is not a directory')
                self.artifacts_counts[f'{dir_name}'] = 'Failed'
                any_failed = True
                continue

            ldb_file_listing = os.listdir(ldb_path)
            log.debug(f' - {len(ldb_file_listing)} files in {dir_name} directory')

            ldb_records = None

            try:
                ldb_records = ccl_chromium_reader.storage_formats.ccl_leveldb.RawLevelDb(pathlib.Path(ldb_path))
            except ValueError as e:
                log.warning(f' - Error reading records ({e}); possible LevelDB corruption')
                self.artifacts_counts[f'{dir_name}'] = 'Failed'

            if ldb_records:
                for record in ldb_records.iterate_records_raw():
                    user_key = record.user_key.decode()
                    parsed = Chrome.ExtensionStorageItem(
                        profile=self.profile_path, extension_id=ext_id, extension_name=self.get_extension_name_from_id(ext_id), key=user_key, value=record.value.decode(),
                        seq=record.seq, state=record.state.name, source_path=str(record.origin_file),
                        offset=record.offset, was_compressed=record.was_compressed)
                    parsed.row_type = dir_name.lower()

                    results.append(parsed)

                ldb_records.close()

        if any_failed:
            self.artifacts_counts[f'{dir_name}'] = 'Failed'
        else:
            self.artifacts_counts[f'{dir_name}'] = len(results)
        log.info(f' - Parsed {len(results)} {dir_name} items')
        self.parsed_extension_data.extend(results)

    @staticmethod
    def parse_ls_ldb_record(record):
        """
        From https://cs.chromium.org/chromium/src/components/services/storage/dom_storage/local_storage_impl.cc:

        // LevelDB database schema
        // =======================
        //
        // Version 1 (in sorted order):
        //   key: "VERSION"
        //   value: "1"
        //
        //   key: "META:" + <url::Origin 'origin'>
        //   value: <LocalStorageOriginMetaData serialized as a string>
        //
        //   key: "_" + <url::Origin> 'origin'> + '\x00' + <script controlled key>
        //   value: <script controlled value>
        """
        parsed = {
            'seq': record['seq'],
            'state': record['state'],
            'origin_file': record['origin_file']
        }

        if record['key'].startswith('META:'.encode('utf-8')):
            parsed['record_type'] = 'META'
            parsed['origin'] = record['key'][5:].decode()
            parsed['key'] = record['key'][5:].decode()

            # From https://cs.chromium.org/chromium/src/components/services/storage/dom_storage/
            #   local_storage_database.proto:
            # message LocalStorageOriginMetaData
            #   required int64 last_modified = 1;
            #   required uint64 size_bytes = 2;
            # TODO: consider redoing this using protobufs
            if record['value'].startswith(b'\x08'):
                ptr = 1
                last_modified, bytes_read = utils.read_varint(record['value'][ptr:])
                size_bytes, _ = utils.read_varint(record['value'][ptr + bytes_read:])
                parsed['value'] = f'Last modified: {last_modified}; size: {size_bytes}'
            return parsed

        elif record['key'] == b'VERSION':
            return

        elif record['key'].startswith(b'_'):
            parsed['record_type'] = 'entry'
            try:
                parsed['origin'], parsed['key'] = record['key'][1:].split(b'\x00', 1)
                parsed['origin'] = parsed['origin'].decode()

                if parsed['key'].startswith(b'\x01'):
                    parsed['key'] = parsed['key'].lstrip(b'\x01').decode()

                elif parsed['key'].startswith(b'\x00'):
                    parsed['key'] = parsed['key'].lstrip(b'\x00').decode('utf-16')

            except Exception as e:
                log.error("Origin/key parsing error: {}".format(e))
                return

            try:
                if record['value'].startswith(b'\x01'):
                    parsed['value'] = record['value'].lstrip(b'\x01').decode('utf-8', errors='replace')

                elif record['value'].startswith(b'\x00'):
                    parsed['value'] = record['value'].lstrip(b'\x00').decode('utf-16', errors='replace')

                elif record['value'].startswith(b'\x08'):
                    parsed['value'] = record['value'].lstrip(b'\x08').decode()

                elif record['value'] == b'':
                    parsed['value'] = ''

            except Exception as e:
                log.error(f'Value parsing error: {e}')
                return

        for item in parsed.values():
            assert not isinstance(item, bytes)

        return parsed

    def build_logical_fs_path(self, node, parent_path=None):
        if not parent_path:
            parent_path = []

        parent_path.append(node['name'])
        node['path'] = parent_path
        for child_node in node['children'].values():
            self.build_logical_fs_path(child_node, parent_path=list(node['path']))

    def flatten_nodes_to_list(self, output_list, node):
        output_row = {
            'type': node['type'],
            'origin': node['path'][0],
            'logical_path': '\\'.join(node['path'][1:]),
            'local_path': node['fs_path'],
            'seq': node['seq'],
            'state': node['state'],
            'source_path': node['source_path'],
            'file_exists': node.get('file_exists'),
            'file_size': node.get('file_size'),
            'magic_results': node.get('magic_results')
        }

        if node.get('modification_time'):
            output_row['modification_time'] = utils.to_datetime(node['modification_time'])

        output_list.append(output_row)
        for child_node in node['children'].values():
            self.flatten_nodes_to_list(output_list, child_node)

    @staticmethod
    def get_local_file_info(file_path):
        file_size, magic_results = None, None
        exists = os.path.isfile(file_path)

        if exists:
            file_size = os.stat(file_path).st_size

        if file_size:
            magic_candidates = puremagic.magic_file(file_path)
            if magic_candidates:
                for magic_candidate in magic_candidates:
                    if magic_candidate.mime_type != '':
                        magic_results = f'{magic_candidate.mime_type} ({magic_candidate.confidence:.0%})'
                        break
                    else:
                        magic_results = f'{magic_candidate.name} ({magic_candidate.confidence:.0%})'

        return exists, file_size, magic_results

    def get_file_system(self, path, dir_name):

        result_list = []
        result_count = 0

        # Grab listing of 'File System' directory
        log.info('File System:')
        fs_root_path = os.path.join(path, dir_name)
        log.info(f' - Reading from {fs_root_path}')
        if not os.path.isdir(fs_root_path):
            log.error(f' - {fs_root_path} is not a directory')
            self.artifacts_counts['File System'] = 'Failed'
            return

        fs_root_listing = os.listdir(fs_root_path)
        log.debug(f' - {len(fs_root_listing)} files in File System directory: {str(fs_root_listing)}')

        # 'Origins' is a LevelDB that holds the mapping for each of the [000, 001, 002, ... ] dirs to
        # web origin (https_www.google.com_0)
        if 'Origins' in fs_root_listing:
            ldb_path = os.path.join(fs_root_path, 'Origins')
            origins = utils.get_ldb_records(ldb_path, 'ORIGIN:')
            for origin in origins:
                origin_domain = origin['key'].decode()
                origin_id = origin['value'].decode()
                origin_root_path = os.path.join(fs_root_path, origin_id)

                # Each Origin can have a temporary (t) and persistent (p) storage section.
                # Process each separately as they have independent file_id numbering.
                for fs_type in ['t', 'p']:
                    fs_type_path = os.path.join(origin_root_path, fs_type)
                    if not os.path.isdir(fs_type_path):
                        continue

                    log.debug(f' - Found \'{fs_type}\' data directory for origin {origin_domain}')

                    # Within each storage section is a 'Paths' leveldb, which holds the logical structure
                    # relationship between the files stored in this section.
                    fs_paths_path = os.path.join(fs_type_path, 'Paths')
                    if not os.path.isdir(fs_paths_path):
                        continue

                    # Initialize data structures for this fs_type (each has independent file_id numbering)
                    node_tree = {}
                    backing_files = {}
                    path_nodes = {
                        '0': {
                            'name': origin_domain, 'origin_id': origin_id, 'type': 'origin',
                            'fs_path': os.path.join('File System', origin_id),
                            'seq': origin['seq'], 'state': origin['state'],
                            'source_path': origin['origin_file'], 'children': {}
                        }
                    }

                    # The 'Paths' ldbs can have entries of four different types:
                    # // - ("CHILD_OF:|parent_id|:<name>", "|file_id|"),
                    # // - ("LAST_FILE_ID", "|last_file_id|"),
                    # // - ("LAST_INTEGER", "|last_integer|"),
                    # // - ("|file_id|", "pickled FileInfo")
                    # // where FileInfo has |parent_id|, |data_path|, |name| and |modification_time|
                    # from cs.chromium.org/chromium/src/storage/browser/file_system/sandbox_directory_database.cc

                    path_items = utils.get_ldb_records(fs_paths_path)

                    # Loop over records looking for "file_id" records to build backing_files dict. We skip
                    # deleted records here, as deleted "file_id" records aren't useful. We'll loop over this
                    # again below to get the "CHILD_OF" records, as they might be out of order due to deletions.
                    for item in path_items:
                        # Deleted records have no value
                        if item['value'] == b'':
                            continue

                        # This will find keys that start with a number, rather than letter (ASCII code),
                        # which only matches "file_id" items (from above list of four types).
                        if item['key'][0] < 58:
                            overall_length, ptr = utils.read_int32(item['value'], 0)
                            parent_id, ptr = utils.read_int64(item['value'], ptr)
                            backing_file_path, ptr = utils.read_string(item['value'], ptr)
                            name, ptr = utils.read_string(item['value'], ptr)
                            mod_time, ptr = utils.read_int64(item['value'], ptr)

                            backing_files[item['key'].decode()] = {
                                'modification_time': mod_time,
                                'seq': item['seq'],
                                'state': item['state'],
                                'source_path': item['origin_file']
                            }

                            path_parts = re.split(r'[/\\]', backing_file_path)
                            # Need at least two segments to index [0] and [1]; a
                            # single-segment (or empty) path falls through to the else
                            # branch, which joins the path as-is.
                            if len(path_parts) >= 2:
                                normalized_backing_file_path = os.path.join(
                                    path_nodes['0']['fs_path'], fs_type, path_parts[0], path_parts[1])
                                file_exists, file_size, magic_results = self.get_local_file_info(
                                           os.path.join(self.profile_path, normalized_backing_file_path))
                                backing_files[item['key'].decode()]['file_exists'] = file_exists
                                backing_files[item['key'].decode()]['file_size'] = file_size
                                backing_files[item['key'].decode()]['magic_results'] = magic_results

                            else:
                                normalized_backing_file_path = os.path.join(
                                    path_nodes['0']['fs_path'], fs_type, backing_file_path)

                            backing_files[item['key'].decode()]['backing_file_path'] = normalized_backing_file_path

                    # Loop over records again, this time to add to the path_nodes dict (used later to construct
                    # the logical path for items in FileSystem. We look at deleted records here; while the value
                    # is empty, the key still exists and has useful info in it.
                    for item in path_items:
                        if not item['key'].startswith(b'CHILD_OF:'):
                            continue

                        # Key format is CHILD_OF:<parent_id>:<name>. The name can itself
                        # contain ':' (e.g. a filename with a colon), so split only on the
                        # first delimiter; partition never raises if ':' is absent.
                        parent, _, name = item['key'][9:].partition(b':')

                        path_node_key = item['value'].decode()
                        if item['value'] == b'':
                            path_node_key = f"deleted-{item['seq']}"

                        path_nodes[path_node_key] = {
                            'name': name.decode(),
                            'type': fs_type,
                            'origin_id': origin_id,
                            'parent': parent.decode(),
                            'fs_path': '',
                            'modification_time': '',
                            'seq': item['seq'],
                            'state': item['state'],
                            'source_path': item['origin_file'],
                            'children': {}
                        }

                        if not item['value'] == b'':
                            value_dict = {
                                'fs_path': backing_files[item['value'].decode()]['backing_file_path'],
                                'modification_time': backing_files[item['value'].decode()]['modification_time'],
                                'file_exists': backing_files[item['value'].decode()].get('file_exists'),
                                'file_size': backing_files[item['value'].decode()].get('file_size'),
                                'magic_results': backing_files[item['value'].decode()].get('magic_results'),
                            }
                            path_nodes[path_node_key].update(value_dict)

                        result_count += 1

                    # Build logical paths for the FileSystem
                    for entry_id, node in path_nodes.items():
                        parent_id = node.get('parent')
                        if not parent_id:
                            node_tree[entry_id] = node
                            continue

                        parent_node = path_nodes.get(parent_id)
                        if parent_node is None:
                            log.debug(f' - Missing parent {parent_id} for node {entry_id}; treating as root')
                            node_tree[entry_id] = node
                            continue

                        parent_node['children'][entry_id] = node

                    if '0' not in node_tree:
                        log.debug(' - Missing root node; skipping logical path build for this origin')
                        continue

                    self.build_logical_fs_path(node_tree['0'])
                    flattened_list = []
                    self.flatten_nodes_to_list(flattened_list, node_tree['0'])

                    for item in flattened_list:
                        result_list.append(Chrome.FileSystemItem(
                            profile=self.profile_path, origin=item.get('origin'), key=item.get('logical_path'),
                            value=item.get('local_path'), seq=item['seq'], state=item['state'],
                            source_path=str(item['source_path']), last_modified=item.get('modification_time'),
                            file_exists=item.get('file_exists'), file_size=item.get('file_size'),
                            magic_results=item.get('magic_results')
                        ))

        log.info(f' - Parsed {len(result_list)} items')
        self.artifacts_counts['File System'] = len(result_list)
        self.parsed_storage.extend(result_list)

    def get_site_characteristics(self, path, dir_name):
        result_list = []

        self.build_md5_hash_list_of_origins()

        log.info('Site Characteristics:')
        sc_root_path = os.path.join(path, dir_name)
        log.info(f' - Reading from {sc_root_path}')

        # Grab listing of 'Site Characteristics' directory
        if not os.path.isdir(sc_root_path):
            log.error(f' - {sc_root_path} is not a directory')
            self.artifacts_counts['Site Characteristics'] = 'Failed'
            return

        sc_root_listing = os.listdir(sc_root_path)
        log.debug(f' - {len(sc_root_listing)} files in Site Characteristics directory: {str(sc_root_listing)}')

        source_item = os.path.relpath(sc_root_path, self.profile_path)

        items = utils.get_ldb_records(sc_root_path)
        for item in items:
            try:
                from pyhindsight.lib.proto.components.performance_manager.persistence.site_data.site_data_pb2 import SiteDataProto

                if item['key'] == b'database_metadata':
                    if item['value'] != b'1':
                        log.warning(f' - Expected type 1; got type {item["value"].encode()}. Trying to parse anyway.')
                    continue

                raw_proto = item['value']

                # Deleted records won't have a value
                if raw_proto:
                    # SiteDataProto built from components/performance_manager/persistence/site_data/site_data.proto
                    parsed_proto = SiteDataProto.FromString(raw_proto)
                    last_loaded = parsed_proto.last_loaded
                else:
                    parsed_proto = ''
                    last_loaded = 0

                matched_url = self.origin_hashes.get(item['key'].decode(), f'MD5 of origin: {item["key"].decode()}')

                sc_record = Chrome.SiteSetting(
                    self.profile_path, url=matched_url, timestamp=utils.to_datetime(last_loaded, self.timezone),
                    key=f'Status: {item["state"]}', value=str(parsed_proto), interpretation='')
                sc_record.row_type += ' (characteristic)'
                sc_record.source_item = source_item
                result_list.append(sc_record)

            except Exception as e:
                log.exception(f' - Exception parsing SiteDataProto ({item}): {e}')

        log.info(f' - Parsed {len(result_list)} items')
        self.artifacts_counts['Site Characteristics'] = len(result_list)
        self.parsed_artifacts.extend(result_list)

    def get_sync_data(self, path, dir_name):
        result_list = []

        log.info('Sync Data:')
        sync_data_root_path = os.path.join(path, dir_name)
        log.info(f' - Reading from {sync_data_root_path}')

        # Grab listing of 'Sync Data' directory
        if not os.path.isdir(sync_data_root_path):
            log.error(f' - {sync_data_root_path} is not a directory')
            self.artifacts_counts['Sync Data'] = 'Failed'
            return

        sd_root_listing = os.listdir(sync_data_root_path)
        log.debug(f' - {len(sd_root_listing)} files in Sync Data directory: {str(sd_root_listing)}')

        if 'LevelDB' in sd_root_listing:
            sync_data_root_path = os.path.join(sync_data_root_path, 'LevelDB')

        log.info(f' - Reading from {sync_data_root_path}')

        items = utils.get_ldb_records(sync_data_root_path)

        from pyhindsight.lib.proto.components.sync.protocol.device_info_specifics_pb2 import DeviceInfoSpecifics
        from pyhindsight.lib.proto.components.sync.protocol.session_specifics_pb2 import SessionSpecifics
        from pyhindsight.lib.proto.components.sync.protocol.entity_metadata_pb2 import EntityMetadata
        from pyhindsight.lib.proto.components.sync.protocol.data_type_state_pb2 import DataTypeState
        from pyhindsight.lib.proto.components.sync.protocol.user_event_specifics_pb2 import UserEventSpecifics
        from pyhindsight.lib.proto.components.sync.protocol.app_specifics_pb2 import AppSpecifics
        from pyhindsight.lib.proto.components.sync.protocol.user_consent_specifics_pb2 import UserConsentSpecifics
        from pyhindsight.lib.proto.components.sync.protocol.persisted_entity_data_pb2 import PersistedEntityData
        from pyhindsight.lib.proto.components.sync.protocol.sync_enums_pb2 import SyncEnums

        os_type_labels = {
            'OS_TYPE_UNSPECIFIED': 'Unspecified',
            'OS_TYPE_WINDOWS': 'Windows',
            'OS_TYPE_MAC': 'macOS',
            'OS_TYPE_LINUX': 'Linux',
            'OS_TYPE_CHROME_OS_ASH': 'ChromeOS (Ash)',
            'OS_TYPE_ANDROID': 'Android',
            'OS_TYPE_IOS': 'iOS',
            'OS_TYPE_CHROME_OS_LACROS': 'ChromeOS (Lacros)',
            'OS_TYPE_FUCHSIA': 'Fuchsia',
        }
        for item in items:
            raw_proto = item['value']
            parsed_proto = None
            record_type = "sync data"
            value_str = ""

            # Only live records have a value
            if raw_proto:
                if item['key'].startswith(b'device_info-dt'):
                    record_type = 'device info'
                    parsed_proto = DeviceInfoSpecifics.FromString(raw_proto)
                    cache_guid = parsed_proto.cache_guid
                    if cache_guid:
                        os_type_value = parsed_proto.os_type
                        model_value = parsed_proto.model
                        try:
                            os_type_value = SyncEnums.OsType.Name(os_type_value)
                        except ValueError:
                            pass
                        if isinstance(os_type_value, str):
                            os_type_value = os_type_labels.get(os_type_value, os_type_value)

                        if cache_guid not in self.originator_guids:
                            self.originator_guids[cache_guid] = {
                                'hostname': parsed_proto.client_name,
                                'os_type': os_type_value,
                                'model': model_value,
                            }

                elif b'-GlobalMetadata' in item['key']:
                    record_type = 'global metadata'
                    # There's a "token" field (#2) that isn't supposed to be anything parseable, but it sometimes is
                    # a nested protobuf; I'm unsure of the matching proto definition. Not parsing it for now.
                    parsed_proto = DataTypeState.FromString(raw_proto)

                elif item['key'].startswith(b'sessions-dt'):
                    record_type = 'sessions'
                    parsed_proto = SessionSpecifics.FromString(raw_proto)

                elif item['key'].startswith(b'preferences-dt'):
                    record_type = 'preferences'
                    parsed_proto = PersistedEntityData.FromString(raw_proto)

                elif item['key'].startswith(b'user_events-dt'):
                    record_type = 'user events'
                    parsed_proto = UserEventSpecifics.FromString(raw_proto)

                elif item['key'].startswith(b'apps-dt'):
                    record_type = 'apps'
                    parsed_proto = AppSpecifics.FromString(raw_proto)

                elif item['key'].startswith(b'user_consent-dt'):
                    record_type = 'user consent'
                    parsed_proto = UserConsentSpecifics.FromString(raw_proto)

                elif item['key'].startswith(b'search_engines-dt'):
                    record_type = 'search engine'
                    parsed_proto = PersistedEntityData.FromString(raw_proto)

                elif item['key'].startswith((b'sessions-md-', b'preferences-md-', b'search_engines-md-',
                                            b'device_info-md-', b'user_events-md-', b'priority_preferences-md-',
                                             b'extensions-md-', b'themes-md-', b'apps-md-', b'user_consent-md-')):
                    record_type = 'entity metadata'
                    parsed_proto = EntityMetadata.FromString(raw_proto)

                else:
                    # Idea: add parsing via blackboxprotobuf of protos we don't have the definitions for.
                    parsed_proto = None
                    log.debug(f" - Sync Data proto parsed empty for key {item['key']} (value_len={len(raw_proto)})")

            # Deleted records won't have a value
            else:
                value_str = ""

            # If we have a value, but it wasn't parsed from a proto we know about, show the raw value
            if raw_proto and not parsed_proto:
                value_str = f"Raw value: {item['value'].hex()}"

            if parsed_proto:
                value_str = str(parsed_proto)

            key_value = item.get('key')
            if isinstance(key_value, bytes):
                key_value = key_value.decode(errors='replace')

            sync_record = Chrome.SyncDataItem(
                profile=self.profile_path,
                key=key_value,
                value=value_str,
                row_type=record_type,
                interpretation='',
                source_path=str(item.get('origin_file', '')),
                offset=item.get('offset'),
                seq=item.get('seq'),
                state=item.get('state'),
                file_type=item.get('file_type'))
            result_list.append(sync_record)

        log.info(f' - Parsed {len(result_list)} items')
        self.artifacts_counts['Sync Data'] = len(result_list)
        self.parsed_sync_data.extend(result_list)

    def build_hsts_domain_hashes(self):
        domains = self.get_clean_hostnames()

        for domain in domains:

            # From https://source.chromium.org/chromium/chromium/src/+
            #  /main:net/http/transport_security_state.cc;l=223:
            #   Converts |hostname| from dotted form ("www.google.com") to the form
            #   used in DNS: "\x03www\x06google\x03com", lowercases that, and returns
            #   the result.
            domain_parts = domain.lower().split('.')
            while len(domain_parts) > 1:
                dns_hostname = ''
                for domain_part in domain_parts:
                    dns_hostname += f'{chr(len(domain_part))}{domain_part}'
                dns_hostname += chr(0)

                # From https://source.chromium.org/chromium/chromium/src/+
                #  /main:net/http/transport_security_persister.h;l=103:
                #    The JSON dictionary keys are strings containing
                #    Base64(SHA256(TransportSecurityState::CanonicalizeHost(domain))).
                hashed_domain = base64.b64encode(
                    hashlib.sha256(dns_hostname.encode()).digest()).decode('utf-8')

                # Check if this is new hash (break if not), add it to the dict,
                # and then repeat with the leading domain part removed.
                if hashed_domain in self.hsts_hashes:
                    break
                self.hsts_hashes[hashed_domain] = '.'.join(domain_parts)
                domain_parts = domain_parts[1:]

    def get_transport_security(self, path, dir_name):
        result_list = []

        # Use the URLs from other previously-processed artifacts to generate hashes of domains
        # in the form Chrome uses as the 'host' identifier.
        self.build_hsts_domain_hashes()

        log.info('Transport Security (HSTS):')
        ts_file_path = os.path.join(path, dir_name)
        log.info(f' - Reading from {ts_file_path}')

        # From https://source.chromium.org/chromium/chromium/src/+
        #  /main:net/http/transport_security_persister.h;l=103:
        #    The JSON dictionary keys are strings containing
        #    Base64(SHA256(TransportSecurityState::CanonicalizeHost(domain))).
        #    The reason for hashing them is so that the stored state does not
        #    trivially reveal a user's browsing history to an attacker reading the
        #    serialized state on disk.

        source_item = os.path.relpath(ts_file_path, self.profile_path)

        with open(ts_file_path, encoding='utf-8', errors='replace') as f:
            ts_json = json.loads(f.read())

            # As of now (2021), there are two versions of the TransportSecurity JSON file.
            # Version 2 has a top level "version" key (with a value of 2), and version 1
            # has the HSTS domain hashes as top level keys.

            # Version 2
            if ts_json.get('version'):
                assert ts_json['version'] == 2, '"2" is only supported value for "version"'
                hsts = ts_json['sts']

                for item in hsts:
                    if item['host'] in self.hsts_hashes:
                        hsts_domain = self.hsts_hashes[item['host']]
                    else:
                        hsts_domain = f'Encoded domain: {item["host"]}'

                    hsts_record = Chrome.SiteSetting(
                        self.profile_path, url=hsts_domain,
                        timestamp=utils.to_datetime(item['sts_observed'], self.timezone),
                        key='HSTS observed', value=str(item), interpretation='')
                    hsts_record.row_type += ' (hsts)'
                    hsts_record.source_item = source_item
                    result_list.append(hsts_record)

            # Version 1
            elif len(ts_json):
                for hashed_domain, domain_settings in ts_json.items():
                    if hashed_domain in self.hsts_hashes:
                        hsts_domain = self.hsts_hashes[hashed_domain]
                    else:
                        hsts_domain = f'{hashed_domain} (encoded domain)'

                    if domain_settings.get('sts_observed'):
                        hsts_record = Chrome.SiteSetting(
                            self.profile_path, url=hsts_domain,
                            timestamp=utils.to_datetime(domain_settings['sts_observed'], self.timezone),
                            key='HSTS observed', value=f'{hashed_domain}: {domain_settings}', interpretation='')
                        hsts_record.row_type += ' (hsts)'
                        hsts_record.source_item = source_item
                        result_list.append(hsts_record)

            else:
                log.warning('Unable to process TransportSecurity file; could not determine version.')
                return

        log.info(f' - Parsed {len(result_list)} items')
        self.artifacts_counts['HSTS'] = len(result_list)
        self.parsed_artifacts.extend(result_list)

    def resolve_kg_entities(self, api_key):
        """Resolve Knowledge Graph entity/category IDs to human-readable names via Google's KG API."""
        if not self.kg_entities or not api_key:
            if self.kg_entities and not api_key:
                log.warning('Knowledge Graph entity IDs found but no API key configured; '
                            'skipping resolution. Add "kg_api_key" to hindsight_config.json to enable.')
            return

        import urllib.request
        import urllib.parse
        import urllib.error

        unresolved_ids = [kid for kid, name in self.kg_entities.items() if name is None]
        if not unresolved_ids:
            return

        log.info(f'Resolving {len(unresolved_ids)} Knowledge Graph entity ID(s)')

        # The KG API supports up to 20 IDs per request
        batch_size = 20
        for i in range(0, len(unresolved_ids), batch_size):
            batch = unresolved_ids[i:i + batch_size]
            params = urllib.parse.urlencode({'key': api_key, 'ids': batch}, doseq=True)
            url = f'https://kgsearch.googleapis.com/v1/entities:search?{params}'

            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode('utf-8'))

                for element in data.get('itemListElement', []):
                    result = element.get('result', {})
                    kg_id = result.get('@id', '').replace('kg:', '')
                    name = result.get('name')
                    if kg_id and name and kg_id in self.kg_entities:
                        self.kg_entities[kg_id] = name

            except urllib.error.HTTPError as e:
                log.warning(f'KG API HTTP error: {e.code} {e.reason}')
                break
            except urllib.error.URLError as e:
                log.warning(f'KG API connection error: {e.reason}')
                break
            except Exception as e:
                log.warning(f'KG API error: {e}')
                break

        resolved_count = sum(1 for v in self.kg_entities.values() if v is not None)
        log.info(f'Resolved {resolved_count}/{len(self.kg_entities)} Knowledge Graph entity ID(s)')

    def process(self, api_keys=None):
        supported_databases = ['History', 'Archived History', 'Media History', 'Web Data', 'Cookies',
                               'Login Data', 'Login Data For Account'
                               'Extension Cookies', 'Network Action Predictor', 'DIPS']
        supported_subdirs = ['Local Storage', 'Extensions', 'File System', 'Platform Notifications', 'Network', 'Sessions', 'Service Worker', 'shared_proto_db']
        supported_jsons = ['Bookmarks', 'TransportSecurity']  # , 'Preferences']
        supported_items = supported_databases + supported_subdirs + supported_jsons
        log.debug(f'Supported items: {supported_items}')

        input_listing = os.listdir(self.profile_path)
        for input_file in input_listing:
            # If input_file is in our supported db list, or if the input_file name starts with a
            # value in supported_databases followed by '__' (used to add in dbs from additional sources)
            if input_file in supported_databases or \
                    input_file.startswith(tuple([db + '__' for db in supported_databases])):
                # Process structure from Chrome database files
                self.build_structure(self.profile_path, input_file)

        network_listing = None
        if 'Network' in input_listing:
            network_listing = os.listdir(os.path.join(self.profile_path, 'Network'))
            for input_file in network_listing:
                if input_file in supported_databases or \
                        input_file.startswith(tuple([db + '__' for db in supported_databases])):
                    # Process structure from Chrome database files
                    self.build_structure(self.profile_path, input_file)

        # Use the structure of the input files to determine possible Chrome versions
        self.determine_version()

        if len(self.version) > 1:
            self.display_version = f'{self.version[0]}-{self.version[-1]}'
        elif len(self.version) == 1:
            self.display_version = self.version[0]
        else:
            print('Unable to determine browser version')

        log.info(f'Detected {self.browser_name} version {self.display_version}')

        log.info('Found the following supported files or directories:')
        for input_file in input_listing:
            if input_file in supported_items:
                log.info(f' - {input_file}')

        group_order = [
            "User Activity",
            "Website Storage",
            "Browser Extensions",
            "Configuration & Supporting Data",
        ]

        with self.processing_display(group_order) as driver:
            # User Activity
            driver.group("User Activity")
            if 'History' in input_listing:
                driver.run(
                    'URL', 'History', self.get_history,
                    self.profile_path, 'History', self.version, 'url',
                    display_key='History', display_value=f'URL records')

                driver.run(
                    'Download', 'History_downloads', self.get_downloads,
                    self.profile_path, 'History', self.version, 'download',
                    display_key='History_downloads', display_value=f'Download records')

            if 'shared_proto_db' in input_listing:
                driver.run(
                    'Downloads (shared_proto_db)', 'shared_proto_db downloads',
                    self.get_shared_proto_db_downloads, self.profile_path, 'shared_proto_db',
                    display_key='shared_proto_db downloads',
                    display_value='shared_proto_db download records')

            if 'Archived History' in input_listing:
                driver.run(
                    'Archived History', 'Archived History', self.get_history,
                    self.profile_path, 'Archived History', self.version, 'url (archived)',
                    display_key='Archived History', display_value='Archived URL records')

            if 'Media History' in input_listing:
                driver.run(
                    'Media History', 'Media History', self.get_media_history,
                    self.profile_path, 'Media History', self.version, 'media (playback end)',
                    display_key='Media History', display_value='Media History records')

            if 'Web Data' in input_listing:
                driver.run(
                    'Autofill', 'Autofill', self.get_autofill,
                    self.profile_path, 'Web Data', self.version,
                    display_key='Autofill', display_value='Autofill records')

            if 'Login Data' in input_listing:
                driver.run(
                    'Login Data', 'Login Data', self.get_login_data,
                    self.profile_path, 'Login Data', self.version,
                    display_key='Login Data', display_value='Login Data records')

            if 'Login Data For Account' in input_listing:
                driver.run(
                    'Login Data', 'Login Data', self.get_login_data,
                    self.profile_path, 'Login Data For Account', self.version,
                    display_key='Login Data', display_value='Login Data (Account) records')

            if 'Bookmarks' in input_listing:
                driver.run(
                    'Bookmarks', 'Bookmarks', self.get_bookmarks,
                    self.profile_path, 'Bookmarks', self.version,
                    display_key='Bookmarks', display_value='Bookmark records')

            if 'Sessions' in input_listing:
                driver.run(
                    'Sessions', 'Sessions', self.get_sessions,
                    self.profile_path, 'Sessions',
                    display_key='Sessions', display_value='Session (SNSS) records')

            # Website Storage
            driver.group("Website Storage")
            if network_listing and 'Cookies' in network_listing:
                driver.run(
                    'Network Cookies', 'Cookies', self.get_cookies,
                    os.path.join(self.profile_path, 'Network'), 'Cookies', self.version,
                    display_key='Cookies', display_value='Cookie records')

            elif 'Cookies' in input_listing:
                driver.run(
                    'Cookies', 'Cookies', self.get_cookies,
                    self.profile_path, 'Cookies', self.version,
                    display_key='Cookies', display_value='Cookie records')

            if self.cache_path is not None and self.cache_path != '':
                c_path, c_dir = os.path.split(self.cache_path)
                driver.run(
                    'Cache', 'Cache', self.get_cache,
                    c_path, c_dir, row_type='cache',
                    display_key='Cache', display_value='Cache records')

            elif 'Cache' in input_listing:
                if os.path.isdir(os.path.join(self.profile_path, 'Cache', 'Cache_Data')):
                    driver.run(
                        'Cache', 'Cache', self.get_cache,
                        os.path.join(self.profile_path, 'Cache'), 'Cache_Data', row_type='cache',
                        display_key='Cache', display_value='Cache records')
                else:
                    driver.run(
                        'Cache', 'Cache', self.get_cache,
                        self.profile_path, 'Cache', row_type='cache',
                        display_key='Cache', display_value='Cache records')
                
            for cache_dir, cache_type in [('GPUCache', 'gpu'), ('Media Cache', 'media'),
                                            ('DawnCache', 'dawn'), ('DawnWebGPUCache', 'dawn webgpu'),
                                            ('DawnGraphiteCache', 'dawn graphite')]:
                if cache_dir in input_listing:
                    driver.run(
                        cache_dir, cache_dir, self.get_cache,
                        self.profile_path, cache_dir, row_type=f'cache ({cache_type})',
                        display_key=cache_dir, display_value=f'{cache_dir} records')

            if 'Local Storage' in input_listing:
                driver.run(
                    'Local Storage', 'Local Storage', self.get_local_storage,
                    self.profile_path, 'Local Storage',
                    display_key='Local Storage', display_value='Local Storage records')

            if 'Session Storage' in input_listing:
                driver.run(
                    'Session Storage', 'Session Storage', self.get_session_storage,
                    self.profile_path, 'Session Storage',
                    display_key='Session Storage', display_value='Session Storage records')

            if 'IndexedDB' in input_listing:
                driver.run(
                    'IndexedDB', 'IndexedDB', self.get_indexeddb,
                    self.profile_path, 'IndexedDB',
                    display_key='IndexedDB', display_value='IndexedDB records')

            if 'File System' in input_listing:
                driver.run(
                    'File System', 'File System', self.get_file_system,
                    self.profile_path, 'File System',
                    display_key='File System', display_value='File System items')

            if 'Platform Notifications' in input_listing:
                driver.run(
                    'Platform Notifications', 'Platform Notifications', self.get_platform_notifications,
                    self.profile_path, 'Platform Notifications',
                    display_key='Platform Notifications', display_value='Platform Notification records')

            if 'Service Worker' in input_listing:
                driver.run(
                    'Service Workers', 'Service Workers', self.get_service_workers,
                    self.profile_path, 'Service Worker',
                    display_key='Service Workers', display_value='Service Worker registrations')

            # Browser Extensions
            driver.group("Browser Extensions")

            if 'Extensions' in input_listing:
                driver.run(
                    'Extensions', 'Extensions', self.get_extensions,
                    self.profile_path, 'Extensions',
                    display_key='Extensions', display_value='Installed Extensions')

            if 'Secure Preferences' in input_listing:
                driver.run(
                    'Extension Settings', 'Secure Preferences', self.get_extension_settings,
                    self.profile_path, 'Secure Preferences',
                    display_key='Extension Settings', display_value='Extension settings entries')

            if 'Extension Cookies' in input_listing:
                # Workaround to cap the version at 65 for Extension Cookies, as until that
                # point it has the same database format as Cookies
                # TODO: Need to revisit this, as in v69 the structures are the same again, but
                # I don't have test data for v67 or v68 to tell when it changed back.
                ext_cookies_version = self.version
                # if min(self.version) > 65:
                #     ext_cookies_version.insert(0, 65)

                driver.run(
                    'Extension Cookies', 'Extension Cookies', self.get_cookies,
                    self.profile_path, 'Extension Cookies', ext_cookies_version,
                    display_key='Extension Cookies', display_value='Extension Cookie records')

            for directory in ['Extension Rules', 'Extension Scripts', 'Extension State']:
                if directory in input_listing:
                    driver.run(
                        directory, directory, self.get_unified_extension_data,
                        self.profile_path, directory,
                        display_key=f'{directory}', display_value=f'{directory} records')

            if 'DNR Extension Rules' in input_listing:
                driver.run(
                    'DNR Extension Rules', 'DNR Extension Rules', self.get_dnr_extension_rules,
                    self.profile_path, 'DNR Extension Rules',
                    display_key='DNR Extension Rules', display_value='DNR Extension Rules records')

            for directory in ['Local App Settings', 'Local Extension Settings',
                              'Managed Extension Settings', 'Sync App Settings', 'Sync Extension Settings']:
                if directory in input_listing:
                    driver.run(
                        directory, directory, self.get_partitioned_extension_data,
                        self.profile_path, directory,
                        display_key=f'{directory}', display_value=f'{directory} records')

            # Configuration & Supporting Data
            driver.group("Configuration & Supporting Data")

            if 'Preferences' in input_listing:
                driver.run(
                    'Preferences', 'Preferences', self.get_preferences,
                    self.profile_path, 'Preferences',
                    display_key='Preferences', display_value='Preference items')

            if 'Site Characteristics Database' in input_listing:
                driver.run(
                    'Site Characteristics', 'Site Characteristics', self.get_site_characteristics,
                    self.profile_path, 'Site Characteristics Database',
                    display_key='Site Characteristics', display_value='Site Characteristics records')

            if 'Sync Data' in input_listing:
                driver.run(
                    'Sync Data', 'Sync Data', self.get_sync_data,
                    self.profile_path, 'Sync Data',
                    display_key='Sync Data', display_value='Sync Data records')

            if network_listing and 'TransportSecurity' in network_listing:
                driver.run(
                    'Network HSTS', 'HSTS', self.get_transport_security,
                    os.path.join(self.profile_path, 'Network'), 'TransportSecurity',
                    display_key='HSTS', display_value='HSTS records')

            elif 'TransportSecurity' in input_listing:
                driver.run(
                    'HSTS', 'HSTS', self.get_transport_security,
                    self.profile_path, 'TransportSecurity',
                    display_key='HSTS', display_value='HSTS records')

            if 'DIPS' in input_listing:
                driver.run(
                    'DIPS Popups', 'DIPS Popups', self.get_dips_popups,
                    self.profile_path, 'DIPS', self.version,
                    display_key='DIPS Popups', display_value='DIPS Popup records')

                driver.run(
                    'DIPS', 'DIPS', self.get_dips,
                    self.profile_path, 'DIPS', self.version,
                    display_key='DIPS', display_value='DIPS records')

        # Destroy the cached key so that JSON serialization doesn't
        # have a cardiac arrest on the non-unicode binary data.
        self.cached_key = None

        # Resolve Knowledge Graph entity IDs to human-readable names
        if api_keys is None:
            api_keys = {}
        self.resolve_kg_entities(api_keys.get('kg_api_key'))

        # Enrich URLItems with resolved KG names and build display strings
        def _resolve_ids(id_list):
            """Convert list of 'kg_id:weight' strings to 'name (weight)' display strings."""
            items = []
            for raw in id_list:
                if ':' in raw:
                    kg_id, weight = raw.rsplit(':', 1)
                else:
                    kg_id, weight = raw, ''
                name = self.kg_entities.get(kg_id) or kg_id
                items.append(f'{name} ({weight})' if weight else name)
            return ', '.join(items)

        for artifact in self.parsed_artifacts:
            if isinstance(artifact, Chrome.URLItem):
                if artifact.category_ids:
                    artifact.categories_str = _resolve_ids(artifact.category_ids)
                if artifact.entity_ids:
                    artifact.entities_str = _resolve_ids(artifact.entity_ids)

        self.parsed_artifacts.sort()
        self.parsed_storage.sort()

        # Clean temp directory after processing profile
        if not self.no_copy:
            log.info(f'Deleting temporary directory {self.temp_dir}')
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                log.error(f'Exception deleting temporary directory: {e}')

    class URLItem(WebBrowser.URLItem):
        def decode_transition(self):
            self.transition_friendly = utils.decode_page_transition(self.transition)

        def decode_source(self):
            # https://source.chromium.org/chromium/chromium/src/+/main:components/history/core/browser/history_types.h
            source_friendly = {
                0:    'Synced',               # Synchronized from somewhere else.
                1:    'Local',                # User browsed. In my experience, this value isn't written; it will be
                                              # null. See https://cs.chromium.org/chromium/src/components/history/
                None: 'Local',                #  core/browser/visit_database.cc
                2:    'Added by Extension',   # Added by an extension.
                3:    'Firefox (Imported)',
                4:    'IE (Imported)',
                5:    'Safari (Imported)',
                6:    'Chrome/Edge (Imported)',                
                7:    'EdgeHTML (Imported)'}

            raw = self.visit_source

            if raw in list(source_friendly.keys()):
                self.visit_source = source_friendly[raw]

    class DownloadItem(WebBrowser.DownloadItem):
        def __init__(
                self, profile, download_id, url, received_bytes, total_bytes, state, full_path=None, start_time=None,
                end_time=None, target_path=None, current_path=None, opened=None, danger_type=None,
                interrupt_reason=None, etag=None, last_modified=None, chain_index=None, interrupt_reason_friendly=None,
                danger_type_friendly=None, state_friendly=None, status_friendly=None, **extra_fields):
            WebBrowser.DownloadItem.__init__(
                self, profile, download_id, url, received_bytes, total_bytes, state, full_path=full_path,
                start_time=start_time, end_time=end_time, target_path=target_path, current_path=current_path,
                opened=opened, danger_type=danger_type, interrupt_reason=interrupt_reason, etag=etag,
                last_modified=last_modified, chain_index=chain_index,
                interrupt_reason_friendly=interrupt_reason_friendly, danger_type_friendly=danger_type_friendly,
                state_friendly=state_friendly, status_friendly=status_friendly, **extra_fields)

        def decode_interrupt_reason(self):
            interrupts = {
                # Success
                0:  'No Interrupt',
                # from download_interrupt_reason_values.h on Chromium site
                # File errors

                # Generic file operation failure.
                1:  'File Error',

                # The file cannot be accessed due to security restrictions.
                2:  'Access Denied',

                # There is not enough room on the drive.
                3:  'Disk Full',

                # The directory or file name is too long.
                5:  'Path Too Long',

                # The file is too large for the file system to handle.
                6:  'File Too Large',

                # The file contains a virus.
                7:  'Virus',

                # The file was in use. Too many files are opened at once. We have run out of memory.
                10: 'Temporary Problem',

                # The file was blocked due to local policy.
                11: 'Blocked',

                # An attempt to check the safety of the download failed due to unexpected reasons.
                # See http://crbug.com/153212.
                12: 'Security Check Failed',

                # An attempt was made to seek past the end of a file in opening a
                # file (as part of resuming a previously interrupted download).
                13: 'Resume Error',

                # The partial file didn't match the expected hash.
                14: 'File Hash Mismatch',

                # The source and the target of the download were the same.
                15: 'File Same as Source',

                # Network errors
                # Generic network failure.
                20: 'Network Error',

                # The network operation timed out.
                21: 'Operation Timed Out',

                # The network connection has been lost.
                22: 'Connection Lost',

                # The server has gone down.
                23: 'Server Down',

                # The network request was invalid. This may be due to the original
                # URL or a redirected URL having an unsupported scheme, being an
                # invalid URL, or being disallowed by policy.
                24: 'Invalid Request',

                # Server responses
                # The server indicates that the operation has failed (generic).
                30: 'Server Error',

                # The server does not support range requests.
                31: 'Range Request Error',

                # Obsolete. The download request does not meet the specified precondition.
                # Internal use only: the file has changed on the server.
                32: 'Server Precondition Error',

                # The server does not have the requested data.
                33: 'Unable to get file',

                # Server didn't authorize access to resource.
                34: 'Server Unauthorized',

                # Server certificate problem.
                35: 'Server Certificate Problem',

                # Server access forbidden.
                36: 'Server Access Forbidden',

                # Unexpected server response. This might indicate that the responding
                # server may not be the intended server.
                37: 'Server Unreachable',

                # The server sent fewer bytes than the content-length header. It may
                # indicate that the connection was closed prematurely, or the
                # Content-Length header was invalid. The download is only
                # interrupted if strong validators are present. Otherwise, it is
                # treated as finished.
                38: 'Content Length Mismatch',

                # An unexpected cross-origin redirect happened.
                39: 'Cross Origin Redirect',

                # User input
                # The user canceled the download.
                40: 'Canceled',

                # The user shut down the browser.
                41: 'Browser Shutdown',

                # Crash
                # The browser crashed.
                50: 'Browser Crashed'
            }

            if self.interrupt_reason in list(interrupts.keys()):
                self.interrupt_reason_friendly = interrupts[self.interrupt_reason]
            elif self.interrupt_reason is None:
                self.interrupt_reason_friendly = None
            else:
                self.interrupt_reason_friendly = '[Error - Unknown Interrupt Code]'
                log.error(f' - Error decoding interrupt code for download "{self.url}"')

        def decode_danger_type(self):
            # from download_danger_type.h on Chromium site
            dangers = {
                # The download is safe.
                0: 'Not Dangerous',

                # A dangerous file to the system (eg: a pdf or extension from places
                # other than gallery).
                1: 'Dangerous',

                # Safe Browsing download service shows this URL leads to malicious
                # file download.
                2: 'Dangerous URL',

                # SafeBrowsing download service shows this file content as being
                # malicious.
                3: 'Dangerous Content',

                # The content of this download may be malicious (eg: extension is
                # exe but Safe Browsing has not finished checking the content).
                4: 'Content May Be Malicious',

                # Safe Browsing download service checked the contents of the
                # download, but didn't have enough data to determine whether
                # it was malicious.
                5: 'Uncommon Content',

                # The download was evaluated to be one of the other types of danger,
                # but the user told us to go ahead anyway.
                6: 'Dangerous But User Validated',

                # Safe Browsing download service checked the contents of the
                # download and didn't have data on this specific file,
                # but the file was served from a host known to serve mostly malicious content.
                7: 'Dangerous Host',

                # Applications and extensions that modify browser and/or computer
                # settings.
                8: 'Potentially Unwanted',

                # Download URL allowed by enterprise policy.
                9: 'Allowlisted by Policy',

                # Download is pending a more detailed verdict.
                10: 'Pending Scan',

                # Download is password protected, and should be blocked according
                # to policy.
                11: 'Blocked - Password Protected',

                # Download is too large, and should be blocked according to policy.
                12: 'Blocked - Too Large',

                # Download deep scanning identified sensitive content, and
                # recommended warning the user.
                13: 'Warning - Sensitive Content',

                # Download deep scanning identified sensitive content, and
                # recommended blocking the file.
                14: 'Blocked - Sensitive Content',

                # Download deep scanning identified no problems.
                15: 'Safe - Deep Scanned',

                # Download deep scanning identified a problem, but the file has
                # already been opened by the user.
                16: 'Dangerous, but user opened',

                # The user is enrolled in the Advanced Protection Program, and
                # the server has recommended this file be deep scanned.
                17: 'Prompt for Scanning',

                # Deprecated: The download has a file type that is unsupported for
                # deep scanning, and should be blocked according to policy.
                18: 'Blocked - Unsupported Type',

                # SafeBrowsing download service has classified this file as
                # being associated with account compromise through stealing cookies.
                19: 'Dangerous - Account Compromise',

                # The user has chosen to deep scan this file, but the scan has
                # failed. The safety of this download is unknown.
                20: 'Deep Scan Failed',

                # The server has recommended this encrypted archive prompt the user
                # for a password to use locally for further scanning.
                21: 'Encrypted - Prompt User for Password for Local Scanning',

                # Download is pending a more detailed verdict after a prompt to use
                # the password locally for further scanning.
                22: 'Encrypted - Pending Detailed Verdict after Local Scanning',

                # Download scan is unsuccessful, and should be blocked according to
                # the policy.
                23: 'Blocked - Scan Failed'
            }

            if self.danger_type in list(dangers.keys()):
                self.danger_type_friendly = dangers[self.danger_type]
            elif self.danger_type is None:
                self.danger_type_friendly = None
            else:
                self.danger_type_friendly = '[Error - Unknown Danger Code]'
                log.error(f' - Error decoding danger code for download "{self.url}"')

        def decode_download_state(self):
            # from download_item.h on Chromium site
            states = {
                # Download is actively progressing.
                0: 'In Progress',

                # Download is completely finished.
                1: 'Complete',

                # Download has been canceled.
                2: 'Canceled',

                # '3' was the old 'Interrupted' code until a bugfix in Chrome v22. 22+ it's '4'
                3: 'Interrupted',

                # This state indicates that the download has been interrupted.
                4: 'Interrupted'
            }

            if self.state in list(states.keys()):
                self.state_friendly = states[self.state]
            else:
                self.state_friendly = '[Error - Unknown State]'
                log.error(f' - Error decoding download state for download "{self.url}"')

        def create_friendly_status(self):
            try:
                status = "%s -  %i%% [%i/%i]" % \
                         (self.state_friendly, (float(self.received_bytes) / float(self.total_bytes)) * 100,
                          self.received_bytes, self.total_bytes)
            except ZeroDivisionError:
                status = "%s -  %i bytes" % (self.state_friendly, self.received_bytes)
            except:
                status = "[parsing error]"
                log.error(" - Error creating friendly status message for download '{}'".format(self.url))
            self.status_friendly = status
