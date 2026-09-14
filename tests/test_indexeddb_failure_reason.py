import os
import tempfile
import unittest
from unittest import mock

from pyhindsight.browsers.chrome import Chrome
from tests.test_indexeddb_record_cap import _Record, _WarningCapture


class _ObjStore:
    """Yields `count` records, then raises `error` if one is given."""

    def __init__(self, count, error=None):
        self.count = count
        self.error = error

    def iterate_records(self):
        for seq in range(self.count):
            yield _Record(seq)
        if self.error is not None:
            raise self.error


class _Database:
    def __init__(self, stores):
        self._stores = stores
        self.object_store_names = list(stores)

    def get_object_store_by_name(self, name):
        return self._stores[name]


class _WrappedIndexDB:
    def __init__(self, database):
        self._db = database
        self.database_ids = [mock.Mock(dbid_no=1)]

    def __getitem__(self, _):
        return self._db

    def close(self):
        pass


class TestIndexedDBFailureReason(unittest.TestCase):
    """When an object store fails part way, the reason says how far *that* store got.

    The count used to be `len(results)`, every record the IndexedDB parse had kept so
    far across earlier stores, and a bare `NotImplementedError()` left the reason's
    parentheses empty (#358).
    """

    def _run(self, wrapped):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, 'IndexedDB', 'https_example.com_0.indexeddb.leveldb'))

            browser = Chrome.__new__(Chrome)
            browser.profile_path = tmp
            browser.parsed_storage = []
            browser.indexeddb_max_records_per_store = None
            browser.resolve_indexeddb_blob_refs = lambda record, origin: record.value

            with _WarningCapture() as captured, mock.patch(
                    'ccl_chromium_reader.ccl_chromium_indexeddb.WrappedIndexDB', return_value=wrapped):
                result = browser.get_indexeddb(tmp, 'IndexedDB')
            return result, browser.parsed_storage, captured.messages

    def test_the_count_is_for_the_failing_object_store_not_the_whole_parse(self):
        database = _Database({
            'healthy': _ObjStore(82),
            'certs': _ObjStore(1, NotImplementedError()),
        })

        result, parsed, messages = self._run(_WrappedIndexDB(database))

        self.assertEqual(83, len(parsed))
        self.assertEqual(1, result.unparsed_sources)
        failure = [m for m in messages if '.certs' in m]
        self.assertEqual(1, len(failure), messages)
        self.assertIn('1 records read from this object store before the failure', failure[0])
        self.assertNotIn('82', failure[0])
        self.assertNotIn('83', failure[0])

    def test_an_exception_with_no_message_is_named_by_its_type(self):
        database = _Database({'certs': _ObjStore(0, NotImplementedError())})

        _, _, messages = self._run(_WrappedIndexDB(database))

        failure = [m for m in messages if '.certs' in m]
        self.assertEqual(1, len(failure), messages)
        self.assertIn('unexpected exception (NotImplementedError)', failure[0])
        self.assertIn('0 records read from this object store', failure[0])

    def test_an_exception_message_is_kept_after_its_type(self):
        database = _Database({'certs': _ObjStore(2, KeyError('schema'))})

        _, _, messages = self._run(_WrappedIndexDB(database))

        failure = [m for m in messages if '.certs' in m]
        self.assertIn("unexpected exception (KeyError: 'schema')", failure[0])
        self.assertIn('2 records read from this object store', failure[0])

    def test_a_store_directory_failure_names_the_exception_type(self):
        wrapped = mock.Mock(side_effect=NotImplementedError())

        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, 'IndexedDB', 'https_example.com_0.indexeddb.leveldb'))
            browser = Chrome.__new__(Chrome)
            browser.profile_path = tmp
            browser.parsed_storage = []
            browser.indexeddb_max_records_per_store = None
            with _WarningCapture() as captured, mock.patch(
                    'ccl_chromium_reader.ccl_chromium_indexeddb.WrappedIndexDB', wrapped):
                browser.get_indexeddb(tmp, 'IndexedDB')

        failure = [m for m in captured.messages if 'https_example.com_0.indexeddb.leveldb' in m]
        self.assertEqual(1, len(failure), captured.messages)
        self.assertIn('unexpected exception (NotImplementedError)', failure[0])


if __name__ == '__main__':
    unittest.main()
