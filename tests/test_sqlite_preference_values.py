import json
import os
import shutil
import sqlite3
import tempfile
import unittest

from pyhindsight.analysis import AnalysisSession


class TestSqlitePreferenceValues(unittest.TestCase):
    """A preference whose value is a dict or list must not fail the SQLite output.

    Chrome's account_info can hold accountcapability_overrides as an empty dict, and
    sqlite3 cannot bind a dict: the preferences insert raised and the whole SQLite
    report was lost. The Preferences sheet already renders such values as JSON.
    """

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        session = AnalysisSession.__new__(AnalysisSession)
        session.parsed_artifacts = []
        session.parsed_storage = []
        session.parsed_extension_data = []
        session.parsed_sync_data = []
        session.installed_extensions = []
        session.preferences = [{
            'presentation': {'title': 'Preferences (Default)'},
            'data': [
                {'group': 'Account Information'},
                {'name': 'accountcapability_overrides', 'value': {}},
                {'name': 'hd', 'value': ['b', 'a'], 'description': {'note': 1}},
                {'name': 'email', 'value': 'bob@example.test'},
            ],
        }]
        self.path = os.path.join(self.directory, 'out.sqlite')
        session.generate_sqlite(self.path)

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_dict_and_list_values_are_stored_as_json(self):
        con = sqlite3.connect(self.path)
        try:
            rows = con.execute('SELECT group_name, name, value, description FROM preferences').fetchall()
        finally:
            con.close()
        self.assertEqual([
            ('Account Information', 'accountcapability_overrides', '{}', None),
            ('Account Information', 'hd', json.dumps(['b', 'a']), '{"note": 1}'),
            ('Account Information', 'email', 'bob@example.test', None),
        ], rows)


if __name__ == '__main__':
    unittest.main()
