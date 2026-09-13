import os
import tempfile
import unittest
from unittest import mock

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.firefox import Firefox
from pyhindsight.browsers.webbrowser import WebBrowser
from tests.test_cli_smoke import CHROME_FIXTURE, FIXTURE, REPO_ROOT, run_hindsight


class TestTempDirCleanup(unittest.TestCase):
    """Every browser removes the per-run copy of its databases (#322).

    Chrome removed its temp directory at the end of process(); Firefox had no teardown, so
    each Firefox parse left a full copy of the profile's SQLite databases behind.
    """

    def assert_no_run_dirs_left(self, temp_root):
        leftovers = os.listdir(temp_root) if os.path.isdir(temp_root) else []
        self.assertEqual([], leftovers, f'temp directories left behind in {temp_root}')

    def test_a_firefox_run_leaves_no_copied_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', output_dir=tmp, profile=FIXTURE)
            self.assertEqual(0, result.returncode, result.stderr)
            with open(os.path.join(tmp, 'hindsight.log'), encoding='utf-8') as log_file:
                self.assertIn('Deleting temporary directory', log_file.read())
            self.assert_no_run_dirs_left(os.path.join(tmp, 'temp'))

    def test_a_chrome_run_still_leaves_no_copied_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', output_dir=tmp, profile=CHROME_FIXTURE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assert_no_run_dirs_left(os.path.join(tmp, 'temp'))

    def test_the_copy_is_removed_even_when_parsing_raises(self):
        def copy_then_fail(browser):
            os.makedirs(browser.temp_dir)
            open(os.path.join(browser.temp_dir, 'places.sqlite'), 'w').close()
            raise RuntimeError('parser blew up')

        with tempfile.TemporaryDirectory() as tmp:
            session = AnalysisSession(
                input_path=os.path.join(REPO_ROOT, FIXTURE), temp_dir=os.path.join(tmp, 'temp'),
                no_copy=False)
            with mock.patch.object(Firefox, 'process', copy_then_fail):
                with self.assertRaises(RuntimeError):
                    session.run()
            self.assert_no_run_dirs_left(os.path.join(tmp, 'temp'))


class TestRemoveTempDir(unittest.TestCase):
    def browser(self, temp_dir, no_copy=False):
        return WebBrowser('profile', 'Chrome', no_copy=no_copy, temp_dir=temp_dir)

    def test_removes_the_directory_and_its_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = os.path.join(tmp, 'run-1-abc')
            os.makedirs(run_dir)
            open(os.path.join(run_dir, 'History'), 'w').close()
            self.browser(run_dir).remove_temp_dir()
            self.assertFalse(os.path.exists(run_dir))

    def test_a_directory_that_was_never_created_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.browser(os.path.join(tmp, 'never-created')).remove_temp_dir()

    def test_no_copy_leaves_the_directory_alone(self):
        # With no_copy the databases are read in place; nothing was copied, so nothing is
        # Hindsight's to delete.
        with tempfile.TemporaryDirectory() as tmp:
            self.browser(tmp, no_copy=True).remove_temp_dir()
            self.assertTrue(os.path.isdir(tmp))


if __name__ == '__main__':
    unittest.main()
