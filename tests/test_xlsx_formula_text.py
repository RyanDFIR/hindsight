import datetime
import io
import unittest

import openpyxl

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.webbrowser import WebBrowser

UTC = datetime.timezone.utc

# What a site could put in a cookie, a storage value or a response header.
PAYLOADS = [
    '=HYPERLINK("http://attacker.example/","click")',
    '=WEBSERVICE("http://attacker.example/")',
    "=cmd|'/c calc'!A1",
    '=1+1',
]


def _cookie(n, payload):
    item = WebBrowser.CookieItem(
        profile='p', host_key=f'.site{n}.test', path='/', name=f'cookie-{n}', value=payload,
        creation_utc=datetime.datetime(2024, 6, 1, 0, 0, n, tzinfo=UTC),
        last_access_utc=None, secure=False, http_only=False)
    item.interpretation = payload
    item.source_item = 'Cookies'
    return item


def _local_storage(n, payload):
    return WebBrowser.LocalStorageItem(
        profile='p', origin='https://example.test', key=f'key-{n}', value=payload, seq=n,
        state='Live', source_path='Local Storage/leveldb', last_modified=None)


class TestXlsxFormulaText(unittest.TestCase):
    """A value from the evidence that starts with "=" is written as text.

    xlsxwriter's write() turns such a string into a formula unless the workbook is
    told not to. Most columns go through write(), and their values come from the sites
    the user visited, so a site could put a live formula in the examiner's report, or
    a malformed one that makes Excel call the workbook corrupt.
    """

    @classmethod
    def setUpClass(cls):
        session = AnalysisSession.__new__(AnalysisSession)
        session.parsed_artifacts = [_cookie(n, p) for n, p in enumerate(PAYLOADS)]
        session.parsed_storage = [_local_storage(n, p) for n, p in enumerate(PAYLOADS)]
        session.parsed_extension_data = []
        session.parsed_sync_data = []
        session.preferences = []
        session.installed_extensions = None
        session.plugin_results = {}
        session.timezone = UTC
        session.artifact_filter = None

        buffer = io.BytesIO()
        session.generate_excel(buffer)
        buffer.seek(0)
        workbook = openpyxl.load_workbook(buffer)
        cls.cells = [cell for sheet in workbook for row in sheet.iter_rows() for cell in row
                     if cell.value is not None]

    def test_no_cell_is_a_formula(self):
        formulas = [f'{cell.parent.title}!{cell.coordinate}: {cell.value}'
                    for cell in self.cells if cell.data_type == 'f']
        self.assertEqual([], formulas)

    def test_the_values_are_kept_as_written(self):
        # In both the Timeline and Storage sheets, unchanged: not dropped, not escaped.
        for sheet in ('Timeline', 'Storage'):
            values = {cell.value for cell in self.cells if cell.parent.title == sheet}
            for payload in PAYLOADS:
                with self.subTest(sheet=sheet, payload=payload):
                    self.assertIn(payload, values)


if __name__ == '__main__':
    unittest.main()
