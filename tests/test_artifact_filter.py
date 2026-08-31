import unittest

from pyhindsight import artifact_filter
from pyhindsight.artifact_filter import (
    ArtifactFilter,
    UnknownArtifactError,
    format_catalog,
    parse_selectors,
    resolve_selector,
)


class TestSelectorResolution(unittest.TestCase):
    """User-supplied artifact names resolve to canonical names, or fail loudly."""

    def test_canonical_name_resolves_to_itself(self):
        self.assertEqual({'cookies'}, resolve_selector('cookies'))

    def test_alias_resolves_to_canonical_name(self):
        # The issue's own example wording ("only visits, downloads") should just work.
        self.assertEqual({'history'}, resolve_selector('visits'))
        self.assertEqual({'logins'}, resolve_selector('passwords'))
        self.assertEqual({'autofill'}, resolve_selector('form-history'))

    def test_names_are_case_and_separator_insensitive(self):
        for spelling in ('local-storage', 'local_storage', 'Local Storage', '  LOCAL STORAGE  '):
            self.assertEqual({'local-storage'}, resolve_selector(spelling), spelling)

    def test_group_expands_to_its_members(self):
        resolved = resolve_selector('browser-extensions')
        self.assertIn('extensions', resolved)
        self.assertIn('extension-cookies', resolved)
        self.assertNotIn('history', resolved)

    def test_caches_group_covers_every_cache_artifact(self):
        # "skip the caches" is one intent even though the caches are separate artifacts.
        self.assertEqual(
            {'cache', 'gpu-cache', 'media-cache', 'dawn-cache', 'cache-api'},
            resolve_selector('caches'))

    def test_unknown_name_raises_with_suggestions(self):
        with self.assertRaises(UnknownArtifactError) as raised:
            resolve_selector('histry')
        message = str(raised.exception)
        self.assertIn('histry', message)
        self.assertIn('history', message)

    def test_unknown_name_is_never_silently_ignored(self):
        # A typo that resolved to "nothing" would produce an empty report that reads
        # exactly like a profile with no artifacts in it.
        with self.assertRaises(UnknownArtifactError):
            parse_selectors(['history,notathing'])


class TestSelectorParsing(unittest.TestCase):

    def test_comma_separated_list(self):
        self.assertEqual({'history', 'downloads'}, parse_selectors(['history,downloads']))

    def test_repeated_flag_values_accumulate(self):
        self.assertEqual({'history', 'cookies'}, parse_selectors(['history', 'cookies']))

    def test_multi_word_names_survive_parsing(self):
        # Splitting on whitespace as well as commas would turn "media history" into
        # 'media' + 'history' -- two different artifacts, one of them not asked for.
        self.assertEqual({'media-history'}, parse_selectors(['media history']))
        self.assertEqual(
            {'local-storage', 'session-storage'},
            parse_selectors(['Local Storage, Session Storage']))

    def test_blank_entries_are_ignored(self):
        self.assertEqual({'history'}, parse_selectors(['history,', ' ']))


class TestArtifactFilter(unittest.TestCase):

    def test_default_filter_parses_everything(self):
        f = ArtifactFilter()
        self.assertFalse(f.is_active)
        for name in artifact_filter.ARTIFACT_NAMES:
            self.assertTrue(f.should_parse(name), name)

    def test_only_restricts_to_named_artifacts(self):
        f = ArtifactFilter.from_selectors(only_tokens=['history,downloads'])
        self.assertTrue(f.should_parse('history'))
        self.assertTrue(f.should_parse('downloads'))
        self.assertFalse(f.should_parse('cache'))
        self.assertTrue(f.is_active)

    def test_skip_removes_named_artifacts(self):
        f = ArtifactFilter.from_selectors(skip_tokens=['cache'])
        self.assertFalse(f.should_parse('cache'))
        self.assertTrue(f.should_parse('history'))
        # Naming only 'cache' skips the main HTTP cache, not the GPU/Dawn caches.
        self.assertTrue(f.should_parse('gpu-cache'))

    def test_only_and_skip_compose(self):
        f = ArtifactFilter.from_selectors(
            only_tokens=['browser-extensions'], skip_tokens=['extension-cookies'])
        self.assertTrue(f.should_parse('extensions'))
        self.assertFalse(f.should_parse('extension-cookies'))
        self.assertFalse(f.should_parse('history'))

    def test_only_that_names_nothing_is_an_error(self):
        # Falling back to "no filter" here would parse everything under a flag that
        # explicitly asked for a subset.
        with self.assertRaises(UnknownArtifactError):
            ArtifactFilter.from_selectors(only_tokens=[','])

    def test_untagged_artifact_always_parses(self):
        # Failing open: a parser nobody gave a catalog name to must still show up in
        # the report rather than vanish because it can't be named.
        f = ArtifactFilter.from_selectors(only_tokens=['history'])
        self.assertTrue(f.should_parse(None))

    def test_skipped_artifacts_are_recorded(self):
        f = ArtifactFilter.from_selectors(skip_tokens=['cache'])
        f.note_skipped('cache')
        self.assertEqual({'cache'}, f.skipped_artifacts)

    def test_describe_reports_the_active_selection(self):
        self.assertEqual('all artifacts', ArtifactFilter().describe())
        described = ArtifactFilter.from_selectors(
            only_tokens=['history'], skip_tokens=['cache']).describe()
        self.assertIn('only: history', described)
        self.assertIn('skip: cache', described)


class TestCatalogIntegrity(unittest.TestCase):
    """The catalog is the contract between the CLI and the parser call sites."""

    def test_names_and_aliases_are_unique(self):
        seen = {}
        for spec in artifact_filter.CATALOG:
            for token in (spec.name,) + spec.aliases:
                normalized = artifact_filter._normalize(token)
                self.assertNotIn(
                    normalized, seen,
                    f"'{token}' is claimed by both {seen.get(normalized)} and {spec.name}")
                seen[normalized] = spec.name

    def test_group_names_do_not_collide_with_artifact_names(self):
        for group in artifact_filter.GROUP_MEMBERS:
            self.assertNotIn(group, artifact_filter.ARTIFACT_NAMES, group)

    def test_every_artifact_belongs_to_a_displayed_group(self):
        for spec in artifact_filter.CATALOG:
            self.assertIn(spec.group, artifact_filter.GROUP_ORDER, spec.name)

    def test_all_group_covers_the_whole_catalog(self):
        self.assertEqual(set(artifact_filter.ARTIFACT_NAMES), resolve_selector('all'))

    def test_catalog_lists_every_artifact(self):
        rendered = format_catalog()
        for name in artifact_filter.ARTIFACT_NAMES:
            self.assertIn(name, rendered, name)


class TestParserCallSitesAreTagged(unittest.TestCase):
    """Every parser the browsers run must be selectable, and spelled correctly.

    These names are only strings at the call sites, so a typo would silently make an
    artifact unselectable (it fails open and always parses). Checking the source keeps
    the catalog and the call sites from drifting apart as parsers are added.
    """

    @staticmethod
    def _artifact_names_in(module_path):
        import re
        with open(module_path, encoding='utf-8') as source:
            return re.findall(r"artifact='([^']+)'", source.read())

    def _assert_module_tagged(self, module):
        import inspect
        path = inspect.getfile(module)
        used = self._artifact_names_in(path)
        self.assertTrue(used, f'no tagged parser call sites found in {path}')
        for name in used:
            self.assertIn(name, artifact_filter.ARTIFACT_NAMES,
                          f"'{name}' in {path} is not in the artifact catalog")

    def test_chrome_call_sites_use_catalog_names(self):
        from pyhindsight.browsers import chrome
        self._assert_module_tagged(chrome)

    def test_firefox_call_sites_use_catalog_names(self):
        from pyhindsight.browsers import firefox
        self._assert_module_tagged(firefox)

    def test_secondary_cache_selectors_are_catalog_names(self):
        # These are passed to driver.run() as a variable rather than a literal, so the
        # source scan above can't see them.
        from pyhindsight.browsers.chrome import SECONDARY_CACHE_DIRS
        for _, _, selector in SECONDARY_CACHE_DIRS:
            self.assertIn(selector, artifact_filter.ARTIFACT_NAMES, selector)

    def test_every_driver_run_call_is_tagged(self):
        # An untagged call site parses unconditionally, so --only/--skip would quietly
        # have no effect on it. Catch that here rather than in an investigation.
        # Parsed rather than grepped: the source also *mentions* driver.run() in prose.
        import ast
        import inspect
        from pyhindsight.browsers import chrome, firefox
        for module in (chrome, firefox):
            source = inspect.getsource(module)
            untagged = []
            for node in ast.walk(ast.parse(source)):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'run'
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == 'driver'):
                    continue
                if not any(kw.arg == 'artifact' for kw in node.keywords):
                    untagged.append(f'{module.__name__} line {node.lineno}')
            self.assertEqual([], untagged,
                             f'untagged driver.run() calls: {untagged}')


class TestProcessingDisplayHonorsFilter(unittest.TestCase):
    """The filter has to stop the parser running, not just hide its row."""

    def _driver(self, artifact_filter_):
        import io
        import rich.console
        from pyhindsight.browsers.webbrowser import ProcessingDisplay, WebBrowser

        browser = WebBrowser('fixture-profile', 'Chrome', artifact_filter=artifact_filter_)
        browser.display_version = '999'
        driver = ProcessingDisplay(browser, ['Group'])
        # Render into a buffer so the test doesn't paint the terminal.
        driver.console = rich.console.Console(file=io.StringIO(), width=100)
        return driver

    @staticmethod
    def _parser(browser, count=None, calls=None, name=None):
        """A stand-in parser: returns a count, or None to mean "could not read"."""
        def run():
            if calls is not None:
                calls.append(name)
            return count
        return run

    def test_excluded_parser_is_not_called(self):
        calls = []
        driver = self._driver(ArtifactFilter.from_selectors(skip_tokens=['cache']))
        with driver:
            driver.group('Group')
            driver.run('Cache', 'Cache',
                       self._parser(driver.browser, 5, calls, 'cache'),
                       display_value='Cache records', artifact='cache')
        self.assertEqual([], calls)

    def test_included_parser_is_called(self):
        calls = []
        driver = self._driver(ArtifactFilter.from_selectors(skip_tokens=['cache']))
        with driver:
            driver.group('Group')
            driver.run('URL', 'History',
                       self._parser(driver.browser, 3, calls, 'history'),
                       display_value='URL records', artifact='history')
        self.assertEqual(['history'], calls)
        self.assertEqual({'History': 3}, driver.browser.artifacts_counts)

    def test_excluded_artifact_is_recorded_as_skipped_not_as_zero(self):
        # A count of 0 would read as "parsed fine, found nothing"; the artifact was
        # never parsed at all.
        driver = self._driver(ArtifactFilter.from_selectors(skip_tokens=['cache']))
        with driver:
            driver.group('Group')
            driver.run('Cache', 'Cache', self._parser(driver.browser, 5),
                       display_value='Cache records', artifact='cache')
        self.assertNotIn('Cache', driver.browser.artifacts_counts)
        self.assertEqual({'Cache': 'skipped'}, driver.browser.artifacts_status)

    def test_excluded_artifact_keeps_its_label(self):
        # One record per artifact: the label rides along with the status, so output can
        # name what it skipped instead of dropping the row.
        driver = self._driver(ArtifactFilter.from_selectors(skip_tokens=['cache']))
        with driver:
            driver.group('Group')
            driver.run('Cache', 'Cache', self._parser(driver.browser, 5),
                       display_value='Cache records', artifact='cache')
        self.assertEqual({'Cache': 'Cache records'}, driver.browser.artifacts_display)
        label = driver.output_groups['Group'][0][0]
        self.assertEqual('Cache records', label)

    def test_a_failing_parser_is_recorded_as_failed(self):
        driver = self._driver(ArtifactFilter())
        with driver:
            driver.group('Group')
            driver.run('Cookies', 'Cookies', self._parser(driver.browser, None),
                       display_value='Cookie records', artifact='cookies')
        self.assertNotIn('Cookies', driver.browser.artifacts_counts)
        self.assertEqual({'Cookies': 'failed'}, driver.browser.artifacts_status)

    def test_a_zero_count_is_not_a_failure(self):
        driver = self._driver(ArtifactFilter())
        with driver:
            driver.group('Group')
            driver.run('IndexedDB', 'IndexedDB', self._parser(driver.browser, 0),
                       display_value='IndexedDB records', artifact='indexeddb')
        self.assertEqual({'IndexedDB': 0}, driver.browser.artifacts_counts)
        self.assertEqual({}, driver.browser.artifacts_status)

    def test_excluded_artifact_is_recorded_on_the_filter(self):
        artifact_filter_ = ArtifactFilter.from_selectors(skip_tokens=['cache'])
        driver = self._driver(artifact_filter_)
        with driver:
            driver.group('Group')
            driver.run('Cache', 'Cache', self._parser(driver.browser, 5),
                       display_value='Cache records', artifact='cache')
        self.assertEqual({'cache'}, artifact_filter_.skipped_artifacts)

    def test_untagged_call_runs_under_an_only_filter(self):
        calls = []
        driver = self._driver(ArtifactFilter.from_selectors(only_tokens=['history']))
        with driver:
            driver.group('Group')
            driver.run('Mystery', 'Mystery',
                       self._parser(driver.browser, 1, calls, 'mystery'))
        self.assertEqual(['mystery'], calls)

    def test_a_parser_that_returns_nothing_is_recorded_as_failed(self):
        # Returning None is the failure signal, so a parser that falls off the end is
        # reported as a failure rather than silently inheriting anything.
        driver = self._driver(ArtifactFilter())
        with driver:
            driver.group('Group')
            driver.run('History', 'History', self._parser(driver.browser, 7),
                       display_value='URL records', artifact='history')
            driver.run('Quiet', 'Quiet', lambda: None, display_value='Quiet records')
        self.assertEqual({'History': 7}, driver.browser.artifacts_counts)
        self.assertNotIn('Quiet', driver.browser.artifacts_counts)
        self.assertEqual('failed', driver.browser.artifacts_status['Quiet'])


if __name__ == '__main__':
    unittest.main()
