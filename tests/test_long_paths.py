import json
import logging
import os
import shutil
import tempfile
import unittest

from pyhindsight.analysis import AnalysisSession
from pyhindsight.artifact_filter import ArtifactFilter
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.webbrowser import WebBrowser
from pyhindsight.utils import long_path, short_path

HISTORY_FIXTURE = os.path.join('tests', 'fixtures', 'profiles', '60', 'History')
EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'

# Long enough that "<profile>\Local Extension Settings" is 256-259 characters, where
# os.path.isdir() still answers but os.listdir() (which appends "\*.*") does not, and an
# extension's manifest.json is well past 260; short enough that discovery and History,
# at the top of the profile, still open without help.
PROFILE_PATH_LENGTH = 232


def _extended(path):
    # Built by hand rather than with long_path(), so the fixture does not depend on the
    # code under test.
    return '\\\\?\\' + os.path.abspath(path)


@unittest.skipUnless(os.name == 'nt', 'MAX_PATH is a Windows limit')
class TestProfilesPastMaxPath(unittest.TestCase):
    """A profile whose files sit past Windows' 260-character MAX_PATH.

    Unless long paths are enabled machine-wide, Windows refuses such paths, and a
    profile reaches them easily: Service Worker CacheStorage files sit five directories
    below it, so an evidence folder of ordinary depth is enough. On the
    magnet.ctf_2019 corpus root this crashed the run when one directory fell in the
    256-259 window, and otherwise lost every CacheStorage record past 260 characters
    without a word. (Where long paths are enabled machine-wide this test passes either
    way.)
    """

    def setUp(self):
        self.base = tempfile.mkdtemp()
        padding = PROFILE_PATH_LENGTH - len(self.base) - len('\\Default') - 1
        self.assertGreater(padding, 0, 'temp directory too deep for this test')
        middle = '\\'.join('d' * 100 for _ in range(padding // 101)) + '\\' if padding > 100 else ''
        middle += 'p' * (padding - len(middle))
        self.profile = os.path.join(self.base, middle, 'Default')
        self.assertEqual(PROFILE_PATH_LENGTH, len(self.profile))

        os.makedirs(_extended(self.profile))
        shutil.copyfile(HISTORY_FIXTURE, _extended(os.path.join(self.profile, 'History')))
        os.makedirs(_extended(os.path.join(self.profile, 'Local Extension Settings')))
        version_dir = os.path.join(self.profile, 'Extensions', EXTENSION_ID, '1.0_0')
        os.makedirs(_extended(version_dir))
        with open(_extended(os.path.join(version_dir, 'manifest.json')), 'w', encoding='utf-8') as f:
            json.dump({'name': 'Deep Extension', 'version': '1.0'}, f)
        self.assertGreater(len(os.path.join(version_dir, 'manifest.json')), 260)

    def tearDown(self):
        shutil.rmtree(_extended(self.base), ignore_errors=True)

    def _session(self):
        session = AnalysisSession()
        session.input_path = self.profile
        session.selected_output_format = 'jsonl'
        session.artifact_filter = ArtifactFilter.from_selectors(None, None)
        session.timezone = 'UTC'
        session.temp_dir = os.path.join(self.base, 'temp')
        session.log_path = os.path.join(self.base, 'hindsight.log')
        session.output_name = os.path.join(self.base, 'out')
        return session

    def test_the_run_completes_and_reads_files_past_the_limit(self):
        session = self._session()
        self.assertTrue(session.run())

        downloads = [item for item in session.parsed_artifacts if item.row_type == 'download']
        self.assertEqual(2, len(downloads))
        names = [extension.name for extension in session.installed_extensions['data']]
        self.assertEqual(['Deep Extension'], names)

    def test_the_report_names_the_profile_as_given(self):
        # Files are read through the extended-length form of the path; that form is
        # an implementation detail and must not reach the report.
        session = self._session()
        session.run()
        records = (session.parsed_artifacts + session.installed_extensions['data'])
        self.assertTrue(records)
        for record in records:
            self.assertEqual(self.profile, record.profile)

    def test_no_record_or_output_carries_the_extended_length_form(self):
        # Records also carry absolute source paths built from the profile path, and
        # those reach every output format.
        session = self._session()
        session.run()
        for name in ('parsed_artifacts', 'parsed_storage', 'parsed_extension_data',
                     'parsed_sync_data', 'preferences'):
            for record in getattr(session, name):
                for key, value in vars(record).items():
                    self.assertFalse(isinstance(value, str) and '\\\\?\\' in value,
                                     f'{name}: {key} = {value!r}')
        for fmt in ('jsonl', 'sqlite'):
            path = os.path.join(self.base, f'out.{fmt}')
            getattr(session, f'generate_{fmt}')(path)
            with open(path, 'rb') as f:
                content = f.read()
            # As stored in SQLite, and as JSON escapes it.
            for form in (b'\\\\?\\', b'\\\\\\\\?\\\\'):
                self.assertNotIn(form, content, fmt)

    def test_read_in_place_as_well(self):
        # --nocopy opens each SQLite database where it is, through the long path.
        browser = Chrome(self.profile, no_copy=True, timezone=None)
        browser.process()
        self.assertEqual(2, sum(1 for item in browser.parsed_artifacts if item.row_type == 'download'))
        self.assertEqual(self.profile, browser.display_profile_path)


class TestLongPath(unittest.TestCase):

    @unittest.skipUnless(os.name == 'nt', 'the extended-length form is Windows-only')
    def test_windows_paths(self):
        cases = {
            'C:\\Evidence\\Default': '\\\\?\\C:\\Evidence\\Default',
            'C:/Evidence/Default': '\\\\?\\C:\\Evidence\\Default',
            'C:\\Evidence\\x\\..\\Default': '\\\\?\\C:\\Evidence\\Default',
            '\\\\server\\share\\Default': '\\\\?\\UNC\\server\\share\\Default',
            '\\\\?\\C:\\Evidence\\Default': '\\\\?\\C:\\Evidence\\Default',
            # Device paths, as for a shadow copy: not UNC paths to a server called ".".
            '\\\\.\\C:\\Evidence\\Default': '\\\\?\\C:\\Evidence\\Default',
            '\\\\.\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Default':
                '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Default',
        }
        for given, expected in cases.items():
            with self.subTest(path=given):
                self.assertEqual(expected, long_path(given))

    def test_short_path(self):
        cases = {
            '\\\\?\\C:\\Evidence\\Default': 'C:\\Evidence\\Default',
            '\\\\?\\C:': 'C:',
            '\\\\?\\UNC\\server\\share\\Default': '\\\\server\\share\\Default',
            # No ordinary form to go back to.
            '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Default':
                '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Default',
            '\\\\?\\Volume{0b1c6e5a-0000-0000-0000-100000000000}\\Default':
                '\\\\?\\Volume{0b1c6e5a-0000-0000-0000-100000000000}\\Default',
            'C:\\Evidence\\Default': 'C:\\Evidence\\Default',
        }
        for given, expected in cases.items():
            with self.subTest(path=given):
                self.assertEqual(expected, short_path(given))

    @unittest.skipUnless(os.name == 'nt', 'the extended-length form is Windows-only')
    def test_a_relative_path_is_made_absolute(self):
        self.assertEqual('\\\\?\\' + os.path.abspath('tests'), long_path('tests'))

    @unittest.skipIf(os.name == 'nt', 'unchanged only where there is no MAX_PATH')
    def test_other_platforms_are_unchanged(self):
        for path in ('/home/user/.config/google-chrome/Default', 'relative/Default'):
            self.assertEqual(path, long_path(path))

    def test_no_path(self):
        self.assertIsNone(long_path(None))
        self.assertEqual('', long_path(''))


class _Browser(WebBrowser):
    """A browser read through the extended-length form on any platform, whose
    parse_profile() is whatever the test needs."""

    def __init__(self, parse):
        super().__init__(GIVEN, 'Test')
        self.profile_path = LONG
        self.parse = parse

    def parse_profile(self):
        self.parse(self)


GIVEN = 'C:\\Evidence\\Default'
LONG = '\\\\?\\C:\\Evidence\\Default'


class TestDisplayPaths(unittest.TestCase):

    def test_paths_nested_in_a_record_are_restored(self):
        def parse(browser):
            item = WebBrowser.StorageItem('local storage', LONG, 'https://example.com', 'key', 'value')
            item.locations = {'files': [LONG + '\\IndexedDB\\a.ldb', (LONG + '\\b.log', 7)]}
            browser.parsed_storage.append(item)
            browser.session_structure = {'windows': [{'source': LONG + '\\Sessions\\Session_1'}]}

        browser = _Browser(parse)
        browser.process()
        item = browser.parsed_storage[0]
        self.assertEqual(GIVEN, item.profile)
        self.assertEqual({'files': [GIVEN + '\\IndexedDB\\a.ldb', (GIVEN + '\\b.log', 7)]}, item.locations)
        self.assertEqual(GIVEN + '\\Sessions\\Session_1', browser.session_structure['windows'][0]['source'])

    def test_evidence_that_looks_like_a_long_path_is_untouched(self):
        # A value read from the profile is the evidence, whatever it looks like.
        values = ['\\\\?\\C:\\Users\\bob\\Downloads\\a.exe', LONG + 'Backup\\x', 'see ' + LONG]

        def parse(browser):
            for value in values:
                browser.parsed_storage.append(
                    WebBrowser.StorageItem('local storage', LONG, 'https://example.com', 'key', value))

        browser = _Browser(parse)
        browser.process()
        self.assertEqual(values, [item.value for item in browser.parsed_storage])

    def test_records_are_restored_when_parsing_fails(self):
        def parse(browser):
            browser.parsed_storage.append(WebBrowser.StorageItem('local storage', LONG, 'https://example.com', 'key', ''))
            raise RuntimeError('parser failed')

        browser = _Browser(parse)
        with self.assertRaises(RuntimeError):
            browser.process()
        self.assertEqual(GIVEN, browser.parsed_storage[0].profile)

    def test_the_log_names_paths_as_given(self):
        records = []
        handler = logging.Handler()
        handler.emit = lambda record: records.append(record.getMessage())
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            _Browser(lambda browser: logging.getLogger('pyhindsight.test').warning(
                ' - Reading from %s', LONG + '\\History')).process()
            logging.getLogger('pyhindsight.test').warning(' - After: %s', LONG)
        finally:
            root.removeHandler(handler)
        self.assertEqual([' - Reading from ' + GIVEN + '\\History', ' - After: ' + LONG], records)


if __name__ == '__main__':
    unittest.main()
