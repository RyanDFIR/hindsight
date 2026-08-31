import unittest

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.webbrowser import (
    ARTIFACT_STATUS_FAILED,
    ARTIFACT_STATUS_SKIPPED,
    ArtifactResult,
    WebBrowser,
)


class TestParserReturnContract(unittest.TestCase):
    """Parsers return a count; they never name the artifact they parsed.

    The key belongs to the driver.run() call that invoked the parser. Parsers used to
    write into a shared dict under a key derived from their own arguments, so two
    layers named the same artifact independently and could disagree.
    """

    PARSER_MODULES = ('chrome', 'firefox')

    @staticmethod
    def _own_nodes(fn):
        """Walk a function's own body, not the bodies of functions nested inside it.

        Several parsers define local helpers whose `return` statements say nothing
        about what the parser itself hands back.
        """
        import ast
        nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        stack = list(fn.body)
        while stack:
            node = stack.pop()
            if isinstance(node, nested):
                # A locally-defined helper: neither it nor anything inside it belongs
                # to the parser's own control flow.
                continue
            yield node
            stack.extend(ast.iter_child_nodes(node))

    def _driver_targets(self, module_name):
        """The parser functions reached through driver.run() in this module."""
        import ast
        import importlib
        import inspect

        module = importlib.import_module(f'pyhindsight.browsers.{module_name}')
        source = inspect.getsource(module)
        names = set()
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'run'
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == 'driver'):
                target = node.args[2]
                if isinstance(target, ast.Attribute):
                    names.add(target.attr)
        return module, source, names

    def test_every_parser_returns_something(self):
        # A parser that falls off the end returns None, which the driver records as a
        # failed parse. That would be a silent, visible-only-at-runtime regression.
        import ast
        for module_name in self.PARSER_MODULES:
            module, source, targets = self._driver_targets(module_name)
            self.assertTrue(targets, module_name)
            tree = ast.parse(source)
            for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
                for fn in [n for n in cls.body if isinstance(n, ast.FunctionDef)]:
                    if fn.name not in targets:
                        continue
                    returns_value = any(
                        isinstance(n, ast.Return) and n.value is not None
                        for n in self._own_nodes(fn))
                    self.assertTrue(
                        returns_value,
                        f'{module_name}.{fn.name} never returns a count; the driver '
                        f'would record it as a failed parse')

    def test_no_parser_returns_a_bare_value_less_return(self):
        # `return` with no value means None means "failed". Every early exit that is
        # not a failure has to say what it produced.
        import ast
        for module_name in self.PARSER_MODULES:
            module, source, targets = self._driver_targets(module_name)
            offenders = []
            tree = ast.parse(source)
            for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
                for fn in [n for n in cls.body if isinstance(n, ast.FunctionDef)]:
                    if fn.name not in targets:
                        continue
                    for n in self._own_nodes(fn):
                        if isinstance(n, ast.Return) and n.value is None:
                            offenders.append(f'{module_name}.{fn.name} line {n.lineno}')
            self.assertEqual(
                [], offenders,
                'bare `return` in a parser is ambiguous -- use `return None` for a '
                f'failure or return a count: {offenders}')


class TestArtifactRecords(unittest.TestCase):
    """One record per artifact holds its label, count, and status together."""

    def setUp(self):
        self.browser = WebBrowser('profile', 'Chrome')

    def test_record_populates_the_derived_views(self):
        self.browser.record_artifact('History', label='URL records', count=500)
        self.assertEqual({'History': 500}, self.browser.artifacts_counts)
        self.assertEqual({'History': 'URL records'}, self.browser.artifacts_display)
        self.assertEqual({}, self.browser.artifacts_status)

    def test_a_failed_artifact_has_a_status_and_no_count(self):
        self.browser.record_artifact('Cookies', label='Cookie records',
                                     status=ARTIFACT_STATUS_FAILED)
        self.assertNotIn('Cookies', self.browser.artifacts_counts)
        self.assertEqual({'Cookies': ARTIFACT_STATUS_FAILED}, self.browser.artifacts_status)

    def test_a_zero_count_is_kept_as_a_count(self):
        self.browser.record_artifact('IndexedDB', label='IndexedDB records', count=0)
        self.assertEqual({'IndexedDB': 0}, self.browser.artifacts_counts)
        self.assertEqual({}, self.browser.artifacts_status)

    def test_label_and_count_cannot_land_under_different_keys(self):
        # The point of one record per artifact: a label always belongs to an artifact
        # that also carries the count, so no phantom "0" row can appear.
        self.browser.record_artifact('Cookies', label='Cookie records', count=3)
        self.assertEqual(set(self.browser.artifacts_display),
                         set(self.browser.artifacts_counts))

    def test_later_calls_add_to_an_existing_record(self):
        self.browser.record_artifact('Cache', label='Cache records')
        self.browser.record_artifact('Cache', count=7)
        result = self.browser.artifact_results['Cache']
        self.assertEqual(ArtifactResult('Cache', label='Cache records', count=7), result)

    def test_derived_views_are_read_only(self):
        # They used to be independently writable dicts, which is how they drifted apart.
        with self.assertRaises(AttributeError):
            self.browser.artifacts_counts = {'History': 1}


class TestSessionAggregation(unittest.TestCase):
    """Counts sum across profiles; outcomes stay attached to their profile."""

    def _session(self, *profiles):
        session = AnalysisSession()
        session.profile_paths = [name for name, _ in profiles]
        for name, records in profiles:
            browser = WebBrowser(name, 'Chrome')
            for key, kwargs in records.items():
                browser.record_artifact(key, **kwargs)
            session.record_profile_results(name, browser)
        return session

    def test_counts_are_summed_across_profiles(self):
        session = self._session(
            ('/p1', {'History': dict(count=10, label='URL records')}),
            ('/p2', {'History': dict(count=25, label='URL records')}))
        self.assertEqual({'History': 35}, session.artifacts_counts)

    def test_status_is_recorded_per_profile(self):
        session = self._session(
            ('/p1', {'Cookies': dict(count=50)}),
            ('/p2', {'Cookies': dict(status=ARTIFACT_STATUS_FAILED)}))
        self.assertEqual({'/p2': {'Cookies': ARTIFACT_STATUS_FAILED}},
                         session.artifacts_status)

    def test_a_failure_in_one_profile_is_not_hidden_by_another_profiles_count(self):
        session = self._session(
            ('/p1', {'Cookies': dict(count=50)}),
            ('/p2', {'Cookies': dict(status=ARTIFACT_STATUS_FAILED)}))
        self.assertEqual(50, session.artifacts_counts['Cookies'])
        self.assertEqual('failed in 1 of 2 profiles',
                         session.describe_artifact_status('Cookies'))

    def test_summary_lists_the_affected_profiles(self):
        session = self._session(
            ('/p1', {'Cache': dict(status=ARTIFACT_STATUS_FAILED)}),
            ('/p2', {'Cache': dict(status=ARTIFACT_STATUS_FAILED)}))
        self.assertEqual({'Cache': {ARTIFACT_STATUS_FAILED: ['/p1', '/p2']}},
                         session.artifact_status_summary())

    def test_single_profile_status_is_described_without_a_profile_count(self):
        session = self._session(('/p1', {'Cache': dict(status=ARTIFACT_STATUS_SKIPPED)}))
        self.assertEqual('skipped', session.describe_artifact_status('Cache'))

    def test_artifact_with_no_status_describes_as_none(self):
        session = self._session(('/p1', {'History': dict(count=10)}))
        self.assertIsNone(session.describe_artifact_status('History'))

    def test_labels_merge_across_profiles(self):
        session = self._session(
            ('/p1', {'History': dict(count=1, label='URL records')}),
            ('/p2', {'Cookies': dict(count=2, label='Cookie records')}))
        self.assertEqual({'History': 'URL records', 'Cookies': 'Cookie records'},
                         session.artifacts_display)


class TestParsersDoNotNameArtifacts(unittest.TestCase):
    """The single-writer invariant, checked against the source.

    Every count/label/status key mismatch this design replaced came from a parser
    naming an artifact independently of the driver. If a parser starts writing into
    the result store again, that whole class of bug comes back.
    """

    BROWSER_MODULES = ('chrome', 'firefox')

    STORE_ATTRS = ('artifacts_counts', 'artifacts_display', 'artifacts_status',
                   'artifact_results')

    def _direct_writes(self, module_name):
        import ast
        import importlib
        import inspect

        module = importlib.import_module(f'pyhindsight.browsers.{module_name}')
        source = inspect.getsource(module)
        offenders = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if (isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Attribute)
                        and target.value.attr in self.STORE_ATTRS):
                    offenders.append(f'{module_name} line {node.lineno}: '
                                     f'writes {target.value.attr}[...] directly')
        return offenders

    def test_no_parser_writes_the_result_store_directly(self):
        offenders = []
        for module_name in self.BROWSER_MODULES:
            offenders.extend(self._direct_writes(module_name))
        self.assertEqual([], offenders, '\n' + '\n'.join(offenders))

    def test_parsers_return_counts_instead(self):
        # Guard against the check above passing because the parsers stopped producing
        # counts at all. Asserts on a boolean, not the source, so a failure message
        # stays readable.
        import ast
        import importlib
        import inspect
        for module_name in self.BROWSER_MODULES:
            module = importlib.import_module(f'pyhindsight.browsers.{module_name}')
            returns = sum(
                1 for node in ast.walk(ast.parse(inspect.getsource(module)))
                if isinstance(node, ast.Return) and node.value is not None)
            self.assertGreater(returns, 20,
                               f'{module_name} has only {returns} value-returning '
                               f'statements; parsers should be returning counts')


if __name__ == '__main__':
    unittest.main()
