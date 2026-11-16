import datetime
import io
import json
import os
import shutil
import sqlite3
import tempfile
import types
import unittest

import openpyxl

from pyhindsight.analysis import AnalysisSession, HindsightEncoder
from pyhindsight.browsers.firefox import Firefox
from pyhindsight.browsers.webbrowser import WebBrowser

UTC = datetime.timezone.utc
FIXTURE_DIR = os.path.join('tests', 'fixtures', 'firefox')
NOT_PARSED = ['content scripts', 'dynamic scripts', 'granted and withheld permissions',
              'DNR rules', 'extension storage']


def _chrome_analysis():
    extension = WebBrowser.BrowserExtension(
        profile='chrome-profile', ext_id='aapocclcgogkmnckokdopfmhonfmgoek', name='Slides',
        description='Create and edit presentations', version='0.10', permissions=None,
        manifest='{}')
    return types.SimpleNamespace(installed_extensions={'data': [extension]},
                                 display_version='Chrome')


def _firefox_analysis():
    ff = Firefox(FIXTURE_DIR, no_copy=True, temp_dir=None, timezone=UTC)
    ff.get_extensions(FIXTURE_DIR, 'extensions.json')
    return types.SimpleNamespace(installed_extensions=ff.installed_extensions,
                                 display_version='Firefox')


class TestExtensionSheets(unittest.TestCase):
    """Both browsers' extensions reach the report once, on the Extensions worksheet.

    Firefox's used to carry a 'presentation', so the generic promotion also gave them
    a flat "Installed Extensions" sheet. In a run with a Chrome profile too, Chrome's
    extensions picked up that presentation and showed on the flat sheet as well.
    """

    @classmethod
    def setUpClass(cls):
        session = AnalysisSession()
        session.timezone = UTC
        session.installed_extensions = None
        session.absorb_browser_analysis('chrome-profile', _chrome_analysis())
        session.absorb_browser_analysis('firefox-profile', _firefox_analysis())
        cls.session = session

        buffer = io.BytesIO()
        session.generate_excel(buffer)
        buffer.seek(0)
        cls.workbook = openpyxl.load_workbook(buffer)

    def test_both_browsers_extensions_are_promoted_once(self):
        self.assertEqual(['data'], list(self.session.installed_extensions))
        ids = [ext.ext_id for ext in self.session.installed_extensions['data']]
        self.assertEqual(['aapocclcgogkmnckokdopfmhonfmgoek', 'uBlock0@raymondhill.net'], ids)

    def test_there_is_no_flat_installed_extensions_sheet(self):
        self.assertIn('Extensions', self.workbook.sheetnames)
        self.assertNotIn('Installed Extensions', self.workbook.sheetnames)

    def test_the_extension_header_rows_carry_version_and_firefox_details(self):
        headers = [row[0] for row in self.workbook['Extensions'].iter_rows(min_row=3, values_only=True)
                   if row[0] and '(' in row[0]]
        chrome, firefox = headers
        self.assertTrue(chrome.startswith('Slides (aapocclcgogkmnckokdopfmhonfmgoek) | Version: 0.10'))
        self.assertTrue(firefox.startswith('uBlock Origin (uBlock0@raymondhill.net) | Version: 1.55.0'))
        for part in ('State: Enabled', 'Found in: extensions.json', 'Install source: app-profile',
                     'Signing: Signed', 'Installed: 2024-01-15', 'Updated: 2024-01-22'):
            self.assertIn(part, firefox)

    def _child_rows(self):
        """The rows under each extension's header row, keyed by the profile they name."""
        rows = {}
        for row in self.workbook['Extensions'].iter_rows(min_row=3, values_only=True):
            if row[1]:
                rows.setdefault(row[7], []).append((row[1], row[2]))
        return rows

    def test_firefox_rows_say_what_was_not_parsed(self):
        # Firefox reads extensions.json only, so it never has content scripts to show.
        # The sheet has to say they were not looked for, not that there are none.
        firefox_profile = self.session.installed_extensions['data'][1].profile
        rows = self._child_rows()[firefox_profile]
        labels = [label for label, _ in rows]
        self.assertIn('permissions', labels)
        self.assertNotIn('(no declarative content scripts)', labels)
        self.assertEqual(', '.join(NOT_PARSED), dict(rows)['not parsed by Hindsight'])

    def test_chrome_rows_keep_the_no_content_scripts_placeholder(self):
        self.assertEqual([('(no declarative content scripts)', None)],
                         self._child_rows()['chrome-profile'])

    def test_jsonl_names_what_was_not_parsed_and_leaves_those_fields_out(self):
        chrome, firefox = (json.loads(json.dumps(ext, cls=HindsightEncoder))
                           for ext in self.session.installed_extensions['data'])

        self.assertEqual(NOT_PARSED, firefox['not_parsed'])
        # An empty list would say the add-on has no content scripts.
        for field in ('content_scripts', 'dynamic_scripts', 'granted_api',
                      'granted_scriptable_host', 'on_disk', 'in_secure_prefs'):
            self.assertNotIn(field, firefox)
        self.assertEqual('{"permissions": ["storage", "webRequest"], "origins": ["<all_urls>"]}',
                         firefox['permissions'])

        self.assertNotIn('not_parsed', chrome)
        self.assertEqual([], chrome['content_scripts'])
        self.assertIs(False, chrome['on_disk'])

    def test_sqlite_names_what_was_not_parsed(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        path = os.path.join(directory, 'out.sqlite')
        self.session.generate_sqlite(path)

        con = sqlite3.connect(path)
        try:
            rows = con.execute('SELECT name, not_parsed FROM installed_extensions').fetchall()
        finally:
            con.close()
        self.assertEqual([('Slides', None), ('uBlock Origin', ', '.join(NOT_PARSED))], rows)


if __name__ == '__main__':
    unittest.main()
