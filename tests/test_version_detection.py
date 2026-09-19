import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from pyhindsight.browsers import chromium_schema_versions
from pyhindsight.browsers.chrome import Chrome, chrome_versions_for_schema


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


class TestLoginDataTables(unittest.TestCase):

    def test_compromised_credentials_means_chrome_80_to_88(self):
        # Created in Chrome 80, and dropped in 89 when insecure_credentials replaced it.
        # This used to be read as 83+, which put magnet.ctf_2020 (Chrome 80) at 83.
        chrome = Chrome('unused')
        chrome.structure = {'Login Data': {'compromised_credentials': ['url', 'username']}}
        chrome.determine_version()
        self.assertEqual((80, 88), (chrome.version[0], chrome.version[-1]))


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


class TestSchemaVersionFromMeta(unittest.TestCase):
    """build_structure records the version row of a database's meta table."""

    def _probe(self, meta_rows):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(os.path.join(tmp, 'History'))
            conn.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR)')
            if meta_rows is not None:
                conn.execute('CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)')
                conn.executemany('INSERT INTO meta VALUES (?, ?)', meta_rows)
            conn.commit()
            conn.close()
            chrome = Chrome(tmp, temp_dir=tmp)
            chrome.build_structure(tmp, 'History')
        return chrome.schema_versions

    def test_the_version_row_is_read_past_binary_rows(self):
        # History's meta table holds sync state as binary blobs next to the version.
        schema_versions = self._probe([
            ('mmap_status', '-1'), ('version', '42'), ('last_compatible_version', '16'),
            ('typed_url_model_type_state', b'\x0a\xff\xfe\x00\x81')])
        self.assertEqual({'History': 42}, schema_versions)

    def test_no_meta_table_records_nothing(self):
        self.assertEqual({}, self._probe(None))


class TestChromeVersionsForSchema(unittest.TestCase):
    DATA = {10: {'History': 20}, 11: {'History': 20}, 12: {'History': 22}, 13: {'History': 25, 'DIPS': 1}}

    def lookup(self, database, schema_version):
        return chrome_versions_for_schema(database, schema_version, self.DATA)

    def test_a_version_maps_to_every_release_that_writes_it(self):
        self.assertEqual([12], self.lookup('History', 22))
        self.assertEqual([13], self.lookup('History', 25))
        self.assertEqual([13], self.lookup('DIPS', 1))

    def test_the_oldest_releases_version_includes_the_releases_before_the_data(self):
        # The data starts at 10, so 1-9 may have written History 20 too. DIPS first
        # appears after the data starts, so its oldest version gets nothing added.
        self.assertEqual(list(range(1, 12)), self.lookup('History', 20))

    def test_a_version_between_two_releases_is_a_pre_release_of_the_later_one(self):
        self.assertEqual([12], self.lookup('History', 21))
        self.assertEqual([13], self.lookup('History', 23))

    def test_a_version_newer_than_the_data_is_the_newest_release_with_a_warning(self):
        with self.assertLogs('pyhindsight.browsers.chrome', level='WARNING'):
            self.assertEqual([13], self.lookup('History', 30))

    def test_what_the_data_cannot_place_is_none(self):
        self.assertIsNone(self.lookup('History', 19))  # older than the data goes back
        self.assertIsNone(self.lookup('History', None))  # no meta table
        self.assertIsNone(self.lookup('Network Action Predictor', 3))  # not in the data


class TestDetermineVersionFromMeta(unittest.TestCase):

    def test_the_upper_bound_is_the_newest_release_in_the_data(self):
        chrome = Chrome('unused')
        chrome.determine_version()
        self.assertEqual(max(chromium_schema_versions.RELEASE_TAGS), chrome.version[-1])

    def test_meta_versions_decide_over_the_column_checks(self):
        # magnet.ctf_2020's schema versions; its Chrome was 80.0.3987.163. Login Data's
        # column checks would say 89+ (insecure_credentials), but with its meta version
        # placed they don't run.
        chrome = Chrome('unused')
        chrome.structure = {'History': {}, 'Web Data': {}, 'Cookies': {},
                            'Login Data': {'insecure_credentials': ['parent_id']}}
        chrome.schema_versions = {'History': 42, 'Web Data': 82, 'Cookies': 12, 'Login Data': 26}
        with self.assertNoLogs('pyhindsight.browsers.chrome', level='WARNING'):
            chrome.determine_version()
        self.assertEqual([80], chrome.version)

    def test_each_databases_schema_version_is_logged_at_info(self):
        # The default log level is INFO, and this is what says which database set the range.
        chrome = Chrome('unused')
        chrome.structure = {'History': {}}
        chrome.schema_versions = {'History': 42}
        with self.assertLogs('pyhindsight.browsers.chrome', level='INFO') as logs:
            chrome.determine_version()
        self.assertIn(' - History schema version 42: Chrome 79-84', '\n'.join(logs.output))

    def test_the_column_checks_run_when_the_data_cannot_place_a_version(self):
        chrome = Chrome('unused')
        chrome.structure = {'History': {'visits': ['id', 'visit_duration']}}
        chrome.schema_versions = {'History': 1}  # older than the data goes back
        chrome.determine_version()
        self.assertEqual(20, chrome.version[0])


if __name__ == '__main__':
    unittest.main()
