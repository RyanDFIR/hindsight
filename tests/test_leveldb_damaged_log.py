import pathlib
import struct
import tempfile
import unittest

from pyhindsight.lib.ccl_chromium_reader.storage_formats import ccl_leveldb

from pyhindsight.browsers.chrome import Chrome, iterate_leveldb_records
from pyhindsight.browsers.webbrowser import ParseFailures, ParseResult


def _log_entry(seq, key, value):
    """One LevelDB log block (a "full" entry) holding a write batch with one value."""
    batch = struct.pack('<QI', seq, 1) + bytes([1, len(key)]) + key + bytes([len(value)]) + value
    return struct.pack('<IHB', 0, len(batch), 1) + batch


# A block header of zeros, as left by an abrupt shutdown at the end of a .log file.
# LevelDB skips it; ccl_leveldb raises ValueError on the unknown block type.
_ZERO_HEADER = bytes(7)


class TestDamagedLevelDbLog(unittest.TestCase):
    """A damaged LevelDB .log file must not abort the run (issue #374)."""

    def _write_ldb(self, directory):
        ldb = pathlib.Path(directory)
        (ldb / '000003.log').write_bytes(
            _log_entry(1, b'before', b'kept') + _ZERO_HEADER + _log_entry(2, b'after', b'lost'))
        (ldb / '000005.log').write_bytes(_log_entry(3, b'next', b'file'))
        return ldb

    def test_records_before_the_damage_and_in_later_files_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            ldb = self._write_ldb(tmp)
            unparsed = ParseFailures('Test')
            ldb_records = ccl_leveldb.RawLevelDb(ldb)
            try:
                keys = [record.user_key for record in iterate_leveldb_records(ldb_records, unparsed)]
            finally:
                ldb_records.close()

        self.assertEqual([b'before', b'next'], keys)
        self.assertEqual(1, len(unparsed.sources))
        self.assertTrue(unparsed.sources[0][0].endswith('000003.log'))
        self.assertTrue(unparsed.result(len(keys)).is_partial)
        # ccl's ValueError for an unknown block type has no message of its own.
        self.assertEqual('damaged LevelDB data (unexpected block)', unparsed.sources[0][1])

    def test_a_write_batch_cut_short_is_also_reported(self):
        # These raise IndexError and struct.error from ccl rather than ValueError.
        kept = _log_entry(1, b'before', b'kept')
        too_few_entries = struct.pack('<QI', 2, 3) + bytes([1, 5]) + b'after' + bytes([1]) + b'x'
        cases = {
            'claims more entries than it holds':
                struct.pack('<IHB', 0, len(too_few_entries), 1) + too_few_entries,
            'shorter than its header': struct.pack('<IHB', 0, 3, 1) + b'\x01\x02\x03',
        }
        for name, damaged in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                ldb = pathlib.Path(tmp)
                (ldb / '000003.log').write_bytes(kept + damaged)
                (ldb / '000005.log').write_bytes(_log_entry(3, b'next', b'file'))
                unparsed = ParseFailures('Test')
                ldb_records = ccl_leveldb.RawLevelDb(ldb)
                try:
                    keys = [record.user_key for record in iterate_leveldb_records(ldb_records, unparsed)]
                finally:
                    ldb_records.close()

                self.assertIn(b'before', keys)
                self.assertEqual(b'next', keys[-1])
                self.assertEqual(1, len(unparsed.sources))
                self.assertTrue(unparsed.sources[0][0].endswith('000003.log'))

    def test_extension_storage_is_partial_instead_of_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            ldb = pathlib.Path(tmp, 'Extension State')
            ldb.mkdir()
            self._write_ldb(ldb)
            chrome = Chrome(tmp, no_copy=True)
            chrome.parsed_extension_data = []
            result = chrome.get_unified_extension_data(tmp, 'Extension State')

        self.assertIsInstance(result, ParseResult)
        self.assertEqual(2, result.count)
        self.assertEqual(1, result.unparsed_sources)


if __name__ == '__main__':
    unittest.main()
