import datetime
import os
import tempfile
import unittest
from unittest import mock

from pyhindsight import utils
from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.firefox import Firefox
from pyhindsight.browsers.webbrowser import WebBrowser
from tests.test_cli_smoke import CHROME_FIXTURE, FIXTURE, REPO_ROOT, run_hindsight

FIREFOX_PROFILE = os.path.join(REPO_ROOT, FIXTURE)
CHROME_PROFILE = os.path.join(REPO_ROOT, CHROME_FIXTURE)


class TempDirAssertions(unittest.TestCase):
    def assert_only_left(self, temp_root, expected):
        leftovers = sorted(os.listdir(temp_root)) if os.path.isdir(temp_root) else []
        self.assertEqual(sorted(expected), leftovers, f'unexpected entries in {temp_root}')

    @staticmethod
    def leave_a_file_of_the_callers(temp_root):
        # Something the caller keeps in its own temp directory, which Hindsight must not
        # treat as its own to delete.
        os.makedirs(temp_root, exist_ok=True)
        with open(os.path.join(temp_root, 'callers-notes.txt'), 'w') as f:
            f.write('not Hindsight\'s')


class TestTempDirCleanup(TempDirAssertions):
    """Every browser removes the copies of its databases (#322).

    Chrome removed its temp directory at the end of process(); Firefox had no teardown, so
    each Firefox parse left a full copy of the profile's SQLite databases behind.
    """

    def assert_run_deleted_its_copies(self, tmp):
        with open(os.path.join(tmp, 'hindsight.log'), encoding='utf-8') as log_file:
            # The deletion being logged shows a copy was made, so an empty temp root below
            # means the copies were removed rather than never written.
            self.assertIn('Deleting temporary directory', log_file.read())
        self.assert_only_left(os.path.join(tmp, 'temp'), [])

    def test_a_firefox_run_leaves_no_copied_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', output_dir=tmp, profile=FIXTURE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assert_run_deleted_its_copies(tmp)

    def test_a_chrome_run_still_leaves_no_copied_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', output_dir=tmp, profile=CHROME_FIXTURE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assert_run_deleted_its_copies(tmp)

    def test_the_copy_is_removed_even_when_parsing_raises(self):
        cases = [(Firefox, FIREFOX_PROFILE, 'places.sqlite'),
                 (Chrome, CHROME_PROFILE, 'History')]
        for browser_class, profile, database in cases:
            def copy_then_fail(browser, *args, **kwargs):
                conn = utils.open_sqlite_db(browser, browser.profile_path, database)
                conn.close()
                raise RuntimeError('parser blew up')

            with self.subTest(browser=browser_class.__name__), \
                    tempfile.TemporaryDirectory() as tmp:
                temp_root = os.path.join(tmp, 'temp')
                session = AnalysisSession(input_path=profile, temp_dir=temp_root, no_copy=False)
                with mock.patch.object(browser_class, 'parse_profile', copy_then_fail):
                    with self.assertRaises(RuntimeError):
                        session.run()
                self.assertTrue(os.path.isdir(temp_root), 'no copy was made')
                self.assert_only_left(temp_root, [])


class TestLibraryUse(TempDirAssertions):
    """A browser driven directly, without an AnalysisSession, cleans up after itself too.

    The directory passed as temp_dir is the caller's: only the directory Hindsight made
    inside it is removed.
    """

    def test_a_browsers_process_removes_its_copies_and_nothing_else(self):
        cases = [(Firefox, FIREFOX_PROFILE), (Chrome, CHROME_PROFILE)]
        for browser_class, profile in cases:
            with self.subTest(browser=browser_class.__name__), \
                    tempfile.TemporaryDirectory() as tmp:
                self.leave_a_file_of_the_callers(tmp)
                browser = browser_class(profile, no_copy=False, temp_dir=tmp,
                                        timezone=datetime.timezone.utc)
                with self.assertLogs('pyhindsight.browsers.webbrowser', 'INFO') as logs:
                    browser.process()
                self.assertTrue(browser.parsed_artifacts)
                self.assertTrue(
                    any('Deleting temporary directory' in line for line in logs.output))
                self.assert_only_left(tmp, ['callers-notes.txt'])


class TestRemoveTempDir(TempDirAssertions):
    def browser(self, temp_dir, no_copy=False):
        return WebBrowser('profile', 'Chrome', no_copy=no_copy, temp_dir=temp_dir)

    def test_removes_only_the_directory_it_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.leave_a_file_of_the_callers(tmp)
            browser = self.browser(tmp)
            copy_dir = browser.copy_dir()
            self.assertEqual(os.path.abspath(tmp), os.path.dirname(os.path.abspath(copy_dir)))
            open(os.path.join(copy_dir, 'History'), 'w').close()
            browser.remove_temp_dir()
            self.assert_only_left(tmp, ['callers-notes.txt'])

    def test_nothing_is_deleted_when_nothing_was_copied(self):
        # The regression this guards against: an rmtree of temp_dir itself, which is the
        # caller's directory when a browser is used as a library.
        with tempfile.TemporaryDirectory() as tmp:
            self.leave_a_file_of_the_callers(tmp)
            self.browser(tmp).remove_temp_dir()
            self.assert_only_left(tmp, ['callers-notes.txt'])

    def test_a_temp_dir_that_does_not_exist_yet_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = os.path.join(tmp, 'not-yet', 'temp')
            browser = self.browser(temp_root)
            self.assertTrue(os.path.isdir(browser.copy_dir()))
            browser.remove_temp_dir()
            self.assert_only_left(temp_root, [])

    def test_each_browser_gets_its_own_directory(self):
        # Copies are named only after the database, so two browsers sharing a directory
        # would overwrite (and delete) each other's copies.
        with tempfile.TemporaryDirectory() as tmp:
            first, second = self.browser(tmp), self.browser(tmp)
            self.assertNotEqual(first.copy_dir(), second.copy_dir())
            first.remove_temp_dir()
            self.assertTrue(os.path.isdir(second.copy_dir()))
            second.remove_temp_dir()
            self.assert_only_left(tmp, [])

    def test_no_temp_dir_falls_back_to_the_system_temp_directory(self):
        browser = self.browser(None)
        copy_dir = browser.copy_dir()
        try:
            self.assertEqual(os.path.abspath(tempfile.gettempdir()),
                             os.path.dirname(os.path.abspath(copy_dir)))
        finally:
            browser.remove_temp_dir()
        self.assertFalse(os.path.exists(copy_dir))

    def test_no_copy_reads_in_place_and_creates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            browser = self.browser(tmp, no_copy=True)
            conn = utils.open_sqlite_db(browser, FIREFOX_PROFILE, 'places.sqlite')
            self.assertTrue(conn)
            conn.close()
            browser.remove_temp_dir()
            self.assert_only_left(tmp, [])


if __name__ == '__main__':
    unittest.main()
