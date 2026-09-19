import sqlite3
import tempfile
import unittest
from unittest import mock

from pyhindsight.browsers.chrome import Chrome


class TestRemovedWebDataColumns(unittest.TestCase):
    """Columns Chrome later dropped must narrow to a range, not to "before they existed".

    autofill_profiles.validity_bitfield (Chrome 63) and is_client_validity_states_updated
    (Chrome 71) were both dropped in Chrome 100. Treating their absence as "older than
    63/71" contradicted the other Web Data checks on every Chrome 100+ profile, so the
    whole Web Data block was thrown away with an "eliminated all possible versions" warning.
    """

    def _versions(self, autofill_profile_columns):
        chrome = Chrome('unused')
        chrome.structure = {'Web Data': {
            'autofill_profiles': ['guid', 'language_code'] + autofill_profile_columns,
            'credit_cards': ['guid', 'billing_address_id', 'nickname'],
        }}
        with self.assertNoLogs('pyhindsight.browsers.chrome', level='WARNING'):
            chrome.determine_version()
        return chrome.version

    def test_both_columns_absent_means_chrome_100_or_later(self):
        # credit_cards.nickname puts the profile at 85+, so this is the post-100 shape.
        versions = self._versions([])
        self.assertEqual(100, versions[0])

    def test_both_columns_present_means_before_chrome_100(self):
        versions = self._versions(['validity_bitfield', 'is_client_validity_states_updated'])
        self.assertEqual((85, 99), (versions[0], versions[-1]))

    def test_only_the_older_column_present_means_63_to_70(self):
        chrome = Chrome('unused')
        chrome.structure = {'Web Data': {'autofill_profiles': [
            'guid', 'language_code', 'validity_bitfield']}}
        chrome.determine_version()
        self.assertEqual((63, 70), (chrome.version[0], chrome.version[-1]))


class TestSchemaProbeFailure(unittest.TestCase):
    """A schema probe that can't query a database must skip it, not end the run."""

    def test_an_operational_error_is_logged_and_skipped(self):
        conn = mock.MagicMock()
        conn.cursor.return_value.execute.side_effect = sqlite3.OperationalError('database is locked')
        with tempfile.TemporaryDirectory() as tmp:
            chrome = Chrome(tmp, temp_dir=tmp)
            with mock.patch('pyhindsight.browsers.webbrowser.utils.open_sqlite_db', return_value=conn), \
                    self.assertLogs('pyhindsight.browsers.webbrowser', level='ERROR'):
                chrome.build_structure(tmp, 'History')
        self.assertEqual({}, chrome.structure['History'])
        conn.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
