import unittest

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.webbrowser import (
    ARTIFACT_STATUS_FAILED,
    ARTIFACT_STATUS_SKIPPED,
    WebBrowser,
)


def _browser(counts=None, status=None):
    browser = WebBrowser('profile', 'Chrome')
    browser.artifacts_counts = dict(counts or {})
    browser.artifacts_status = dict(status or {})
    return browser


class TestFinalizeArtifactStatus(unittest.TestCase):
    """Parsers write 'Failed' into the counts dict; finalization splits it back out."""

    def test_failure_moves_out_of_counts_into_status(self):
        browser = _browser({'History': 500, 'Cookies': 'Failed'})
        browser.finalize_artifact_status()
        self.assertEqual({'History': 500}, browser.artifacts_counts)
        self.assertEqual({'Cookies': ARTIFACT_STATUS_FAILED}, browser.artifacts_status)

    def test_failure_does_not_become_a_count_of_zero(self):
        # The bug this replaces: a failed parse used to be reported as "found nothing".
        browser = _browser({'Cookies': 'Failed'})
        browser.finalize_artifact_status()
        self.assertNotIn('Cookies', browser.artifacts_counts)

    def test_genuine_zero_count_is_left_alone(self):
        # The other half of the distinction: 0 is a real, parsed result.
        browser = _browser({'IndexedDB': 0})
        browser.finalize_artifact_status()
        self.assertEqual({'IndexedDB': 0}, browser.artifacts_counts)
        self.assertEqual({}, browser.artifacts_status)

    def test_unrecognized_status_is_preserved_not_rejected(self):
        # The old merge raised ValueError on any status that wasn't 'Fail...'. A status
        # nobody anticipated is still information; losing it is how failures went missing.
        browser = _browser({'Cache': 'Aborted'})
        browser.finalize_artifact_status()
        self.assertEqual({'Cache': 'aborted'}, browser.artifacts_status)
        self.assertNotIn('Cache', browser.artifacts_counts)

    def test_is_idempotent(self):
        browser = _browser({'History': 5, 'Cookies': 'Failed'})
        browser.finalize_artifact_status()
        browser.finalize_artifact_status()
        self.assertEqual({'History': 5}, browser.artifacts_counts)
        self.assertEqual({'Cookies': ARTIFACT_STATUS_FAILED}, browser.artifacts_status)

    def test_existing_status_entries_survive(self):
        # A skip recorded during the run must not be clobbered by finalization.
        browser = _browser({'History': 5}, {'Cache': ARTIFACT_STATUS_SKIPPED})
        browser.finalize_artifact_status()
        self.assertEqual({'Cache': ARTIFACT_STATUS_SKIPPED}, browser.artifacts_status)


class TestSumDictCounts(unittest.TestCase):

    def test_sums_shared_keys(self):
        self.assertEqual(
            {'History': 30, 'Cookies': 5},
            AnalysisSession.sum_dict_counts({'History': 10, 'Cookies': 5}, {'History': 20}))

    def test_keys_only_in_one_dict_are_kept(self):
        self.assertEqual(
            {'History': 10, 'Cookies': 5},
            AnalysisSession.sum_dict_counts({'History': 10}, {'Cookies': 5}))

    def test_a_status_string_is_a_loud_error_not_a_silent_zero(self):
        # Previously this returned {'Cookies': 0}, reporting a failed parse as an empty
        # one. Reaching here now means finalize_artifact_status() was bypassed.
        with self.assertRaises(TypeError) as raised:
            AnalysisSession.sum_dict_counts({}, {'Cookies': 'Failed'})
        self.assertIn('finalize_artifact_status', str(raised.exception))


class TestSessionStatusAggregation(unittest.TestCase):
    """Failures have to stay attached to the profile they happened in."""

    def _session(self, *profiles):
        session = AnalysisSession()
        session.profile_paths = [name for name, _, _ in profiles]
        for name, counts, status in profiles:
            browser = _browser(counts, status)
            session.artifacts_counts = session.sum_dict_counts(
                session.artifacts_counts, browser.artifacts_counts)
            session.record_artifact_status(name, browser)
        return session

    def test_status_is_recorded_per_profile(self):
        session = self._session(
            ('/p1', {'Cookies': 50}, {}),
            ('/p2', {}, {'Cookies': ARTIFACT_STATUS_FAILED}))
        self.assertEqual({'/p2': {'Cookies': ARTIFACT_STATUS_FAILED}}, session.artifacts_status)

    def test_a_failure_in_one_profile_is_not_hidden_by_another_profiles_count(self):
        # The old merge returned {'Cookies': 50} with no trace that a profile failed.
        session = self._session(
            ('/p1', {'Cookies': 50}, {}),
            ('/p2', {}, {'Cookies': ARTIFACT_STATUS_FAILED}))
        self.assertEqual(50, session.artifacts_counts['Cookies'])
        self.assertEqual('failed in 1 of 2 profiles', session.describe_artifact_status('Cookies'))

    def test_summary_lists_the_affected_profiles(self):
        session = self._session(
            ('/p1', {}, {'Cache': ARTIFACT_STATUS_FAILED}),
            ('/p2', {}, {'Cache': ARTIFACT_STATUS_FAILED}))
        self.assertEqual(
            {'Cache': {ARTIFACT_STATUS_FAILED: ['/p1', '/p2']}},
            session.artifact_status_summary())

    def test_single_profile_status_is_described_without_a_profile_count(self):
        session = self._session(('/p1', {}, {'Cache': ARTIFACT_STATUS_SKIPPED}))
        self.assertEqual('skipped', session.describe_artifact_status('Cache'))

    def test_artifact_with_no_status_describes_as_none(self):
        session = self._session(('/p1', {'History': 10}, {}))
        self.assertIsNone(session.describe_artifact_status('History'))


class TestFailureKeysMatchCountKeys(unittest.TestCase):
    """A parser must report a failure under the same key it reports a count under.

    The live display and the run's status summary look an artifact up by its count key.
    A failure filed under a different key (Firefox used to file several under the
    *filename*) is invisible to both: the display falls back to "0", which reads as
    "parsed fine, found nothing" rather than "could not read". Nothing but convention
    keeps the two keys in step, so this checks the source directly.
    """

    BROWSER_MODULES = ('chrome', 'firefox')

    # Helpers that open a database on a parser's behalf and record the failure for it.
    # They take the key as a keyword so the caller stays responsible for naming it.
    OPEN_HELPERS = {'_open'}

    @staticmethod
    def _count_key_source(subscript, source):
        import ast
        return ast.get_source_segment(source, subscript.slice)

    def _mismatches(self, module_name):
        import ast
        import importlib
        import inspect

        module = importlib.import_module(f'pyhindsight.browsers.{module_name}')
        source = inspect.getsource(module)
        tree = ast.parse(source)

        found = []
        for class_node in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            for fn in [n for n in class_node.body if isinstance(n, ast.FunctionDef)]:
                count_keys, failure_keys = set(), set()
                for node in ast.walk(fn):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr in self.OPEN_HELPERS):
                        for keyword in node.keywords:
                            if keyword.arg == 'count_key':
                                key = ast.get_source_segment(source, keyword.value)
                                # None means "a probe, not an artifact parse".
                                if key != 'None':
                                    failure_keys.add(key)
                    if isinstance(node, ast.Assign) and len(node.targets) == 1:
                        target = node.targets[0]
                        if (isinstance(target, ast.Subscript)
                                and isinstance(target.value, ast.Attribute)
                                and target.value.attr == 'artifacts_counts'):
                            key = self._count_key_source(target, source)
                            is_status = (isinstance(node.value, ast.Constant)
                                         and isinstance(node.value.value, str))
                            (failure_keys if is_status else count_keys).add(key)

                # Only meaningful for parsers that report a count at all.
                if not count_keys:
                    continue
                stray = failure_keys - count_keys
                if stray:
                    found.append(f'{module_name}.{fn.name}: '
                                 f'counts under {sorted(count_keys)}, '
                                 f'fails under {sorted(stray)}')
        return found

    def test_no_parser_files_a_failure_under_a_key_it_never_counts(self):
        mismatches = []
        for module_name in self.BROWSER_MODULES:
            mismatches.extend(self._mismatches(module_name))
        self.assertEqual([], mismatches, '\n' + '\n'.join(mismatches))

    def test_the_check_would_catch_a_regression(self):
        # Guard against the audit silently passing because it stopped finding anything.
        import ast
        source = (
            'class P:\n'
            '    def get_thing(self, database):\n'
            "        self.artifacts_counts[database] = 'Failed'\n"
            "        self.artifacts_counts['Thing'] = 5\n")
        tree = ast.parse(source)
        fn = tree.body[0].body[0]
        count_keys, failure_keys = set(), set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                target = node.targets[0]
                key = ast.get_source_segment(source, target.slice)
                is_status = isinstance(node.value.value, str) if isinstance(
                    node.value, ast.Constant) else False
                (failure_keys if is_status else count_keys).add(key)
        self.assertEqual({'database'}, failure_keys - count_keys)


if __name__ == '__main__':
    unittest.main()
