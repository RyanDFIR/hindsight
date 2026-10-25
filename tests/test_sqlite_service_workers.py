import datetime
import logging
import os
import sqlite3
import tempfile
import unittest

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.webbrowser import WebBrowser

REF = datetime.datetime(2024, 1, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
SHARED_COLUMNS = {'type', 'origin', 'key', 'value', 'modification_time', 'interpretation', 'profile',
                  'source_path', 'seq', 'state', 'state_friendly'}


class _ErrorCapture:
    """Capture what pyhindsight.analysis logs at ERROR during a block."""

    def __enter__(self):
        self.messages = []
        capture = self

        class _Handler(logging.Handler):
            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    capture.messages.append(record.getMessage())

        self.handler = _Handler(level=logging.DEBUG)
        self.logger = logging.getLogger('pyhindsight.analysis')
        self.previous_level = self.logger.level
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.previous_level)
        return False


def _service_worker_items():
    """One record of every Service Worker shape the Chrome parser emits."""
    registration = WebBrowser.ServiceWorkerItem(
        profile='/profile', origin='https://example.com/', scope_url='https://example.com/',
        script_url='https://example.com/sw.js', registration_id=7, version_id=21, is_active=True,
        has_fetch_handler=False, last_update_check_time=REF, resources_total_size_bytes=4096,
        navigation_preload_enabled=False, navigation_preload_header=None, update_via_cache='IMPORTS',
        script_type='CLASSIC', script_response_time=REF, seq=10, state='Live',
        source_path='Service Worker/Database/000003.log')

    orphan = WebBrowser.ServiceWorkerItem(
        profile='/profile', origin='https://ghost.example/', scope_url='https://ghost.example/',
        script_url=None, registration_id=9, version_id=None, is_active=None, has_fetch_handler=None,
        last_update_check_time=None, resources_total_size_bytes=None, navigation_preload_enabled=None,
        navigation_preload_header=None, update_via_cache=None, script_type=None,
        script_response_time=None, seq=11, state='Live', source_path='Service Worker/Database/000003.log')
    orphan.row_type = 'service worker (orphan registration)'

    resource = WebBrowser.ServiceWorkerResourceItem(
        profile='/profile', scope_url='https://example.com/', version_id=21, resource_id=288,
        url='https://example.com/sw.js', size_bytes=1234, sha256_checksum='ab' * 32,
        resource_state='committed', seq=12, state='Deleted', source_path='Service Worker/Database/000003.log')

    script = WebBrowser.ServiceWorkerScriptItem(
        profile='/profile', scope_url='https://example.com/', version_id=21, resource_id=288,
        url='https://example.com/sw.js', http_status='HTTP/1.1 200 OK',
        content_type='application/javascript', body_size=1200, body_sha256='cd' * 32,
        body_sha256_match=False, response_time=REF, request_time=None, source_file='f_000001',
        source_path='Service Worker/ScriptCache')

    cache_entry = WebBrowser.ServiceWorkerCacheStorageItem(
        profile='/profile', storage_key='https://example.com/', origin_hash='abc123', cache_name='v1',
        cache_uuid='uuid-1', request_url='https://example.com/app.js', request_method='GET',
        response_status=200, response_status_text='OK', response_type='BASIC',
        response_mime_type='text/javascript', final_url=None, body_size=900, body_sha256='ef' * 32,
        entry_time=REF, response_time=REF, source_file='index', source_path='Service Worker/CacheStorage')

    user_data = WebBrowser.ServiceWorkerUserDataItem(
        profile='/profile', scope_url='https://example.com/', registration_id=7,
        user_data_key='push_registration_id', subsystem='push subscription',
        decoded_value='endpoint=https://push.example/abc', raw_value_size=64, seq=13, state='Live',
        source_path='Service Worker/Database/000003.log', event_time=None)
    user_data.row_type = 'service worker (push subscription)'

    return [registration, orphan, resource, script, cache_entry, user_data]


class TestSqliteServiceWorkers(unittest.TestCase):
    """Service Worker records have their own SQLite table.

    They used to share `storage`, where only type/origin/key/value and a few generic
    columns existed, so registration and version IDs, script type, cache name, HTTP
    status and the hashes survived only packed into `value`, where nothing could query
    them.
    """

    @classmethod
    def setUpClass(cls):
        cls.items = _service_worker_items()
        session = AnalysisSession.__new__(AnalysisSession)
        session.parsed_artifacts = []
        session.parsed_storage = list(cls.items)
        session.parsed_extension_data = []
        session.parsed_sync_data = []
        session.preferences = []
        session.installed_extensions = []

        # sqlite3 keeps the output file open on Windows, so cleanup is best-effort.
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db_path = os.path.join(cls._tmp.name, 'output.sqlite')
        with _ErrorCapture() as captured:
            session.generate_sqlite(db_path)
        cls.errors = captured.messages

        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        try:
            cls.rows = {row['type']: dict(row) for row in connection.execute('SELECT * FROM service_workers')}
            cls.storage_types = [row[0] for row in connection.execute('SELECT type FROM storage')]
            cls.columns = [row['name'] for row in connection.execute('PRAGMA table_info(service_workers)')]
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_every_service_worker_record_lands_in_its_own_table(self):
        self.assertEqual(sorted(item.row_type for item in self.items), sorted(self.rows))
        self.assertEqual([], [t for t in self.storage_types if t.startswith('service worker')])

    def test_nothing_is_reported_missing(self):
        self.assertEqual([], [m for m in self.errors if 'MISSING from the SQLite' in m], self.errors)

    def test_registration_fields_are_columns(self):
        row = self.rows['service worker (registration)']
        self.assertEqual(7, row['registration_id'])
        self.assertEqual(21, row['version_id'])
        self.assertEqual(1, row['is_active'])
        self.assertEqual(0, row['has_fetch_handler'])
        self.assertEqual('CLASSIC', row['script_type'])
        self.assertEqual('IMPORTS', row['update_via_cache'])
        self.assertEqual('https://example.com/sw.js', row['script_url'])
        self.assertEqual(4096, row['resources_total_size_bytes'])
        self.assertTrue(row['modification_time'].startswith('2024-01-15'))
        self.assertTrue(row['script_response_time'].startswith('2024-01-15'))

    def test_resource_and_script_fields_are_columns(self):
        resource = self.rows['service worker (resource)']
        self.assertEqual(288, resource['resource_id'])
        self.assertEqual(1234, resource['size_bytes'])
        self.assertEqual('ab' * 32, resource['sha256_checksum'])
        self.assertEqual('committed', resource['resource_state'])
        self.assertEqual(0, resource['state'])
        self.assertEqual('Deleted', resource['state_friendly'])

        script = self.rows['service worker (script body)']
        self.assertEqual('HTTP/1.1 200 OK', script['http_status'])
        self.assertEqual('application/javascript', script['content_type'])
        self.assertEqual(1200, script['body_size'])
        # A body that does not match the LDB-recorded hash is a finding, so the flag has
        # to be queryable, not buried in the value string.
        self.assertEqual(0, script['body_sha256_match'])

    def test_cache_and_user_data_fields_are_columns(self):
        cache_entry = self.rows['service worker (cache storage)']
        self.assertEqual('v1', cache_entry['cache_name'])
        self.assertEqual('uuid-1', cache_entry['cache_uuid'])
        self.assertEqual(200, cache_entry['response_status'])
        self.assertEqual('https://example.com/app.js', cache_entry['request_url'])
        self.assertTrue(cache_entry['entry_time'].startswith('2024-01-15'))

        user_data = self.rows['service worker (push subscription)']
        self.assertEqual('push subscription', user_data['subsystem'])
        self.assertEqual('push_registration_id', user_data['user_data_key'])
        self.assertEqual(64, user_data['raw_value_size'])

    def test_absent_values_are_null_not_empty(self):
        self.assertIsNone(self.rows['service worker (orphan registration)']['modification_time'])
        self.assertIsNone(self.rows['service worker (orphan registration)']['script_url'])
        self.assertIsNone(self.rows['service worker (script body)']['request_time'])
        self.assertIsNone(self.rows['service worker (push subscription)']['event_time'])

    def test_column_names_are_item_attribute_names(self):
        # The column names double as the JSONL keys, which come from the same attributes;
        # a column no item carries would be a name that exists in only one format.
        attributes = set()
        for item in self.items:
            attributes.update(vars(item))
        unmatched = [name for name in self.columns if name not in SHARED_COLUMNS and name not in attributes]
        self.assertEqual([], unmatched)


if __name__ == '__main__':
    unittest.main()
