import logging
import os
import tempfile
import unittest
from unittest import mock

from pyhindsight.browsers.chrome import Chrome


class _CapturingHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append((record.levelno, record.getMessage()))


class _LogCapture:
    """Capture everything pyhindsight.browsers.chrome logs during a block."""

    def __enter__(self):
        self.handler = _CapturingHandler()
        self.logger = logging.getLogger('pyhindsight.browsers.chrome')
        self.previous_level = self.logger.level
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.previous_level)
        return False

    def messages(self, level=None):
        return [m for lvl, m in self.handler.records if level is None or lvl == level]


class TestSiteCharacteristicsDatabaseMetadata(unittest.TestCase):
    """`database_metadata` is bookkeeping, not a SiteDataProto.

    Its value is the store's bare schema version. The record must be skipped, and the
    version it carries reported rather than discarded -- and neither path may raise.
    """

    def _run(self, metadata_value):
        with tempfile.TemporaryDirectory() as tmp:
            sc_dir = os.path.join(tmp, 'Site Characteristics Database')
            os.makedirs(sc_dir)

            browser = Chrome.__new__(Chrome)
            browser.profile_path = tmp
            browser.timezone = None
            browser.parsed_artifacts = []
            browser.origin_hashes = {}
            browser.build_md5_hash_list_of_origins = lambda: None

            record = {
                'key': b'database_metadata', 'value': metadata_value,
                'seq': 1, 'state': 'Live', 'file_type': 'Log',
            }
            with mock.patch('pyhindsight.utils.get_ldb_records', return_value=[record]):
                with _LogCapture() as captured:
                    count = browser.get_site_characteristics(tmp, 'Site Characteristics Database')
            return count, captured, browser.parsed_artifacts

    def test_the_expected_version_is_skipped_and_reported(self):
        count, captured, artifacts = self._run(b'1')

        self.assertEqual(0, count)
        self.assertEqual([], artifacts)
        self.assertTrue(
            any('schema version 1' in m for m in captured.messages(logging.INFO)),
            captured.messages())

    def test_an_unexpected_version_warns_without_raising(self):
        # b'2' is in the wild. The version warning used to call .encode() on a bytes
        # value, which raised AttributeError before reaching the skip, so the record
        # surfaced as `Exception parsing SiteDataProto` on healthy profiles.
        count, captured, artifacts = self._run(b'2')

        self.assertEqual(0, count)
        self.assertEqual([], artifacts)
        self.assertTrue(
            any('schema version 2' in m for m in captured.messages(logging.WARNING)),
            captured.messages())
        self.assertFalse(
            [m for m in captured.messages(logging.ERROR) if 'SiteDataProto' in m],
            captured.messages(logging.ERROR))

    def test_an_undecodable_version_still_does_not_raise(self):
        count, captured, artifacts = self._run(b'\xff\xfe')

        self.assertEqual(0, count)
        self.assertFalse(
            [m for m in captured.messages(logging.ERROR) if 'SiteDataProto' in m],
            captured.messages(logging.ERROR))


if __name__ == '__main__':
    unittest.main()
