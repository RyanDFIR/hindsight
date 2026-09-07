import logging
import os
import tempfile
import unittest

from pyhindsight import analysis
from pyhindsight.analysis import AnalysisSession


class CapturingHandler(logging.Handler):
    """Collect log records emitted during profile discovery."""

    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


class TestProfileDiscoveryWarning(unittest.TestCase):
    """The 'analysis may not be useful' warning fires only when nothing was found.

    Aiming Hindsight at an app-data root is the normal invocation: the root is
    not itself a profile, so a warning raised before the search recurses fires on
    every healthy run. The warning is only meaningful once the search is done.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.handler = CapturingHandler()
        self.original_handlers = analysis.log.handlers
        self.original_propagate = analysis.log.propagate
        analysis.log.handlers = [self.handler]
        analysis.log.propagate = False
        analysis.log.setLevel(logging.WARNING)

    def tearDown(self):
        analysis.log.handlers = self.original_handlers
        analysis.log.propagate = self.original_propagate

    def warnings_from(self, base_path, **kwargs):
        self.handler.records = []
        self.session = AnalysisSession()
        found = self.session.find_browser_profiles(base_path, **kwargs)
        warnings = [r.getMessage() for r in self.handler.records
                    if r.levelno >= logging.WARNING]
        return found, warnings

    def make_chrome_profile(self, *parts):
        path = os.path.join(self.root, *parts)
        os.makedirs(path)
        open(os.path.join(path, 'History'), 'w').close()
        return path

    def test_app_data_root_with_profiles_below_it_warns_nothing(self):
        default = self.make_chrome_profile('User Data', 'Default')
        second = self.make_chrome_profile('User Data', 'Profile 1')

        found, warnings = self.warnings_from(os.path.join(self.root, 'User Data'))

        self.assertEqual({default, second}, set(found))
        self.assertEqual([], warnings)
        self.assertFalse(self.session.used_input_path_as_profile)

    def test_profile_passed_directly_warns_nothing(self):
        default = self.make_chrome_profile('Default')

        found, warnings = self.warnings_from(default)

        self.assertEqual([default], found)
        self.assertEqual([], warnings)
        self.assertFalse(self.session.used_input_path_as_profile)

    def test_path_with_no_profile_anywhere_below_it_warns_once(self):
        os.makedirs(os.path.join(self.root, 'sub', 'deeper'))
        open(os.path.join(self.root, 'sub', 'readme.txt'), 'w').close()

        found, warnings = self.warnings_from(self.root)

        # The input path is still processed as a profile, as a last resort, but
        # the caller can tell that apart from a genuine single-profile result.
        self.assertEqual([self.root], found)
        self.assertTrue(self.session.used_input_path_as_profile)
        self.assertEqual(1, len(warnings), warnings)
        self.assertIn('No browser profiles found', warnings[0])
        self.assertIn(self.root, warnings[0])

    def test_warn_false_silences_the_duplicate_from_the_early_count(self):
        # hindsight.py counts profiles before run() searches again; only one of
        # the two searches should log.
        found, warnings = self.warnings_from(self.root, warn=False)

        self.assertEqual([self.root], found)
        self.assertEqual([], warnings)
        # Silencing the warning must not silence the fallback itself.
        self.assertTrue(self.session.used_input_path_as_profile)


if __name__ == '__main__':
    unittest.main()
