import os
import pathlib
import struct
import tempfile
import unittest

from pyhindsight import utils
from pyhindsight.lib.ccl_chromium_reader.storage_formats import ccl_leveldb

from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.webbrowser import ParseFailures, ParseResult


def _log_entry(seq, key, value):
    """One LevelDB log block (a "full" entry) holding a write batch with one value."""
    batch = struct.pack('<QI', seq, 1) + bytes([1, len(key)]) + key + bytes([len(value)]) + value
    return struct.pack('<IHB', 0, len(batch), 1) + batch


# A block header of zeros. At the end of a .log file this is the space an abrupt
# shutdown leaves behind, which holds no records; LevelDB skips the rest of the block.
_ZERO_HEADER = bytes(7)


def _read(ldb):
    unparsed = ParseFailures('Test')
    ldb_records = ccl_leveldb.RawLevelDb(ldb)
    try:
        keys = [record.user_key for record in utils.iterate_leveldb_records(ldb_records, unparsed)]
    finally:
        ldb_records.close()
    return keys, unparsed


class TestDamagedLevelDbLog(unittest.TestCase):
    """A damaged LevelDB .log file must not abort the run (issue #374)."""

    def _write_ldb(self, directory):
        ldb = pathlib.Path(directory)
        (ldb / '000003.log').write_bytes(
            _log_entry(1, b'before', b'kept') + _ZERO_HEADER + _log_entry(2, b'after', b'lost'))
        (ldb / '000005.log').write_bytes(_log_entry(3, b'next', b'file'))
        return ldb

    def test_a_zero_filled_tail_is_a_clean_read(self):
        # The issue #374 file: records, then zeros to the end. Nothing is lost.
        with tempfile.TemporaryDirectory() as tmp:
            ldb = pathlib.Path(tmp)
            (ldb / '000003.log').write_bytes(_log_entry(1, b'before', b'kept') + bytes(600))
            keys, unparsed = _read(ldb)

        self.assertEqual([b'before'], keys)
        self.assertEqual([], unparsed.sources)
        self.assertFalse(unparsed.result(len(keys)).is_partial)

    def test_records_before_the_damage_and_in_later_files_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys, unparsed = _read(self._write_ldb(tmp))

        self.assertEqual([b'before', b'next'], keys)
        self.assertEqual(1, len(unparsed.sources))
        self.assertTrue(unparsed.sources[0][0].endswith('000003.log'))
        self.assertTrue(unparsed.result(len(keys)).is_partial)
        # The record after the zeros is skipped, as LevelDB skips it, but reported.
        self.assertEqual('damaged LevelDB data (38 bytes skipped in 1 place; '
                         'first at offset 32: data after zero-filled space)', unparsed.sources[0][1])

    def test_a_write_batch_cut_short_is_also_reported(self):
        kept = _log_entry(1, b'before', b'kept')
        too_few_entries = struct.pack('<QI', 2, 3) + bytes([1, 5]) + b'after' + bytes([1]) + b'x'
        cases = {
            'claims more entries than it holds':
                (struct.pack('<IHB', 0, len(too_few_entries), 1) + too_few_entries,
                 'write batch cut short at entry 2 of 3'),
            'shorter than its header':
                (struct.pack('<IHB', 0, 3, 1) + b'\x01\x02\x03', 'write batch shorter than its 12-byte header'),
        }
        for name, (damaged, reason) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                ldb = pathlib.Path(tmp)
                (ldb / '000003.log').write_bytes(kept + damaged)
                (ldb / '000005.log').write_bytes(_log_entry(3, b'next', b'file'))
                keys, unparsed = _read(ldb)

                self.assertIn(b'before', keys)
                self.assertEqual(b'next', keys[-1])
                self.assertEqual(1, len(unparsed.sources))
                self.assertTrue(unparsed.sources[0][0].endswith('000003.log'))
                self.assertTrue(unparsed.sources[0][1].endswith(f': {reason})'))

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


class TestGetLdbRecordsReportsDamage(unittest.TestCase):
    """get_ldb_records used to stop at the first damaged file and only log a warning, so
    the artifact read as a clean run with fewer records."""

    def test_damage_is_reported_and_later_files_are_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            ldb = pathlib.Path(tmp)
            (ldb / '000003.log').write_bytes(
                _log_entry(1, b'before', b'kept') + _ZERO_HEADER + _log_entry(2, b'after', b'lost'))
            (ldb / '000005.log').write_bytes(_log_entry(3, b'next', b'file'))
            unparsed = ParseFailures('Test')
            records = utils.get_ldb_records(tmp, unparsed)

        self.assertEqual([b'before', b'next'], [r['key'] for r in records])
        self.assertEqual(1, len(unparsed.sources))
        self.assertTrue(unparsed.sources[0][0].endswith('000003.log'))

    def test_a_leveldb_that_cannot_be_opened_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, 'not-there')
            unparsed = ParseFailures('Test')
            self.assertEqual([], utils.get_ldb_records(missing, unparsed))

        self.assertEqual(1, len(unparsed.sources))
        self.assertTrue(unparsed.sources[0][1].startswith('could not open as LevelDB'))

    def test_local_storage_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            ldb = pathlib.Path(tmp, 'Local Storage', 'leveldb')
            ldb.mkdir(parents=True)
            (ldb / '000003.log').write_bytes(
                _log_entry(1, b'_https://example.com\x00\x01key', b'\x01value') + _ZERO_HEADER + b'\x01' * 40)
            chrome = Chrome(tmp, no_copy=True)
            result = chrome.get_local_storage(tmp, 'Local Storage')

        self.assertIsInstance(result, ParseResult)
        self.assertEqual(1, result.unparsed_sources)


if __name__ == '__main__':
    unittest.main()
