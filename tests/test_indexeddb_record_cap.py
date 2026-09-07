import logging
import os
import tempfile
import unittest
from unittest import mock

from pyhindsight.browsers.chrome import Chrome


class _WarningCapture:
    """Capture what ParseFailures logs while a parse runs."""

    def __enter__(self):
        self.messages = []
        capture = self

        class _Handler(logging.Handler):
            def emit(self, record):
                if record.levelno >= logging.WARNING:
                    capture.messages.append(record.getMessage())

        self.handler = _Handler(level=logging.DEBUG)
        self.logger = logging.getLogger('pyhindsight.browsers.webbrowser')
        self.previous_level = self.logger.level
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.previous_level)
        return False


class _Record:
    def __init__(self, seq):
        self.is_live = True
        self.ldb_seq_no = seq
        self.database_name = 'db'
        self.external_value_path = None
        self.key = mock.Mock(value=f'key{seq}', key_type=mock.Mock(name='n'), raw_key=b'\x00')
        self.value = {'v': seq}


class _ObjStore:
    def __init__(self, count):
        self.count = count
        self.iterated = 0

    def iterate_records(self):
        for seq in range(self.count):
            self.iterated += 1
            yield _Record(seq)


class _Database:
    def __init__(self, store):
        self.object_store_names = ['store']
        self._store = store

    def get_object_store_by_name(self, name):
        return self._store


class _WrappedIndexDB:
    def __init__(self, store):
        self._db = _Database(store)
        self.database_ids = [mock.Mock(dbid_no=1)]

    def __getitem__(self, _):
        return self._db

    def close(self):
        pass


class TestIndexedDBRecordCap(unittest.TestCase):
    """A large store must be capped by measurement, not by name.

    The previous protection was a skip keyed to one extension's literal directory
    name, so every other large store still parsed fully. The cap now truncates any
    store, and reports the truncation through `unparsed.source` the way the
    hard-coded skip reported its skip.
    """

    def _run(self, record_count, cap):
        with tempfile.TemporaryDirectory() as tmp:
            idb_dir = os.path.join(tmp, 'IndexedDB')
            store_dir_name = 'https_example.com_0.indexeddb.leveldb'
            os.makedirs(os.path.join(idb_dir, store_dir_name))

            browser = Chrome.__new__(Chrome)
            browser.profile_path = tmp
            browser.parsed_storage = []
            browser.indexeddb_max_records_per_store = cap
            browser.resolve_indexeddb_blob_refs = lambda record, origin: record.value

            store = _ObjStore(record_count)
            with mock.patch(
                    'ccl_chromium_reader.ccl_chromium_indexeddb.WrappedIndexDB',
                    return_value=_WrappedIndexDB(store)):
                result = browser.get_indexeddb(tmp, 'IndexedDB')
            return result, store, browser.parsed_storage, store_dir_name

    def test_a_store_under_the_cap_is_read_whole(self):
        result, store, parsed, _ = self._run(record_count=10, cap=100)

        self.assertEqual(10, len(parsed))
        self.assertEqual(0, result.unparsed_sources)

    def test_a_store_over_the_cap_is_truncated_not_skipped(self):
        # The hard-coded rule yielded nothing at all for the one store it named. A
        # capped store yields its first `cap` records, which is strictly more.
        result, store, parsed, _ = self._run(record_count=500, cap=100)

        self.assertEqual(100, len(parsed))
        self.assertEqual(1, result.unparsed_sources)

    def test_the_cap_bounds_the_iteration_and_not_only_the_rows_kept(self):
        # Iterating a million-record store is the hang the cap exists to prevent, so
        # it has to stop pulling records, not just stop appending them.
        result, store, parsed, _ = self._run(record_count=5000, cap=50)

        self.assertLessEqual(store.iterated, 51)

    def test_the_truncation_names_the_store_and_how_far_it_got(self):
        # `unparsed.source` logs each failure as it happens, which is what an examiner
        # reads to learn the store is incompletely represented rather than inferring it
        # from a suspiciously round record count.
        with _WarningCapture() as captured:
            result, store, parsed, store_dir_name = self._run(record_count=200, cap=25)

        self.assertEqual(25, len(parsed))
        self.assertEqual(1, result.unparsed_sources)
        matching = [m for m in captured.messages if store_dir_name in m]
        self.assertTrue(matching, captured.messages)
        self.assertIn('truncated at 25 records', matching[0])

    def test_a_none_cap_disables_truncation(self):
        result, store, parsed, _ = self._run(record_count=300, cap=None)

        self.assertEqual(300, len(parsed))
        self.assertEqual(0, result.unparsed_sources)


if __name__ == '__main__':
    unittest.main()
