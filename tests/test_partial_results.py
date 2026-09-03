import io
import logging
import re
import unittest

import rich.console

from pyhindsight.browsers.webbrowser import (
    ARTIFACT_STATUS_PARTIAL,
    ParseFailures,
    ParseResult,
    ProcessingDisplay,
    WebBrowser,
)


class _CapturingHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class _LogCapture:
    """Capture everything pyhindsight.browsers.webbrowser logs during a block."""

    def __enter__(self):
        self.handler = _CapturingHandler()
        self.logger = logging.getLogger('pyhindsight.browsers.webbrowser')
        self.previous_level = self.logger.level
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.previous_level)
        return False

    @property
    def messages(self):
        return self.handler.messages


class TestParseFailures(unittest.TestCase):
    """The collector counts what it logs, so the two can't disagree."""

    def test_result_counts_match_what_was_recorded(self):
        unparsed = ParseFailures('Local Storage')
        unparsed.source('a/ls/data.sqlite', 'could not be opened')
        unparsed.source('b/ls/data.sqlite', 'corrupt header')
        unparsed.record('c/key1', 'decode failed')
        result = unparsed.result(412)
        self.assertEqual(ParseResult(412, 2, 1), result)

    def test_every_failure_is_logged_as_it_happens(self):
        with _LogCapture() as captured:
            unparsed = ParseFailures('Local Storage')
            unparsed.source('a/ls/data.sqlite', 'could not be opened')
            unparsed.record('c/key1', 'decode failed')
        joined = '\n'.join(captured.messages)
        self.assertIn('a/ls/data.sqlite', joined)
        self.assertIn('could not be opened', joined)
        self.assertIn('c/key1', joined)
        self.assertIn('decode failed', joined)

    def test_detail_line_count_equals_the_reported_totals(self):
        # The requirement: what the log enumerates and what the run reports are the
        # same numbers, so a reader can reconcile the two.
        with _LogCapture() as captured:
            unparsed = ParseFailures('IndexedDB')
            for i in range(3):
                unparsed.source(f'db{i}.sqlite', 'unreadable')
            for i in range(7):
                unparsed.record(f'db9.sqlite:key{i}', 'decode failed')
            result = unparsed.result(100)
        sources = [m for m in captured.messages if m.startswith(' - Unparsed source')]
        records = [m for m in captured.messages if m.startswith(' - Unparsed record')]
        self.assertEqual(len(sources), result.unparsed_sources)
        self.assertEqual(len(records), result.unparsed_records)

    def test_the_same_failure_is_only_counted_once(self):
        # Some parsers read a file in more than one pass; a truncated file fails
        # identically in each. That is one unparsed source, not one per pass.
        unparsed = ParseFailures('Sessions')
        unparsed.source('Session_13400', 'truncated')
        unparsed.source('Session_13400', 'truncated')
        self.assertEqual(1, unparsed.result(5).unparsed_sources)

    def test_distinct_failures_on_one_source_are_both_counted(self):
        unparsed = ParseFailures('Sessions')
        unparsed.source('Session_13400', 'truncated')
        unparsed.source('Session_13400', 'header unreadable')
        self.assertEqual(2, unparsed.result(5).unparsed_sources)

    def test_a_repeated_failure_is_only_logged_once(self):
        with _LogCapture() as captured:
            unparsed = ParseFailures('Sessions')
            unparsed.source('Session_13400', 'truncated')
            unparsed.source('Session_13400', 'truncated')
        lines = [m for m in captured.messages if 'Unparsed source' in m]
        self.assertEqual(1, len(lines))

    def test_a_clean_parse_is_not_partial(self):
        self.assertFalse(ParseFailures('X').result(10).is_partial)
        self.assertTrue(ParseFailures('X').result(10)._replace(unparsed_records=1).is_partial)


class TestDeliveryReconciliation(unittest.TestCase):
    """A count alone cannot reveal that the records behind it were dropped.

    The count is derived from a list the parser built; the records reach output through
    a separate `extend`. When a misplaced return skipped the extend, the reported number
    stayed correct while 18k records never reached the output -- invisible, because the
    count was right.
    """

    def _driver(self):
        browser = WebBrowser('fixture-profile', 'Chrome')
        browser.display_version = '999'
        driver = ProcessingDisplay(browser, ['Group'])
        driver.console = rich.console.Console(file=io.StringIO(), width=110)
        return driver

    def _run(self, parser):
        driver = self._driver()
        with _LogCapture() as captured:
            with driver:
                driver.group('Group')
                driver.run('Extension State', 'Extension State', parser,
                           display_value='Extension State records',
                           artifact='extension-storage')
        return driver, captured

    def test_a_count_with_no_delivered_records_is_reported(self):
        # The exact shape of the bug: parse, count, drop.
        driver, captured = self._run(lambda: 15978)
        errors = [m for m in captured.messages if 'contributed none' in m]
        self.assertEqual(1, len(errors), captured.messages)
        self.assertIn('15978', errors[0])

    def test_a_parser_that_delivers_records_is_not_flagged(self):
        driver = self._driver()

        def parser():
            driver.browser.parsed_extension_data.extend([object(), object()])
            return 2

        with _LogCapture() as captured:
            with driver:
                driver.group('Group')
                driver.run('Extension State', 'Extension State', parser,
                           display_value='Extension State records',
                           artifact='extension-storage')
        self.assertEqual([], [m for m in captured.messages if 'contributed none' in m])

    def test_a_zero_count_is_not_flagged(self):
        # Parsing nothing and delivering nothing is consistent, not a bug.
        _, captured = self._run(lambda: 0)
        self.assertEqual([], [m for m in captured.messages if 'contributed none' in m])

    def test_a_failed_parse_is_not_flagged(self):
        _, captured = self._run(lambda: None)
        self.assertEqual([], [m for m in captured.messages if 'contributed none' in m])

    def test_delivery_into_any_collection_counts(self):
        # Parsers deliver into different collections; growth in any of them satisfies
        # the invariant (chrome's get_extensions contributes to neither parsed_artifacts
        # nor parsed_storage, for instance).
        from pyhindsight.browsers.webbrowser import RESULT_COLLECTIONS
        self.assertIn('parsed_artifacts', RESULT_COLLECTIONS)
        self.assertIn('parsed_storage', RESULT_COLLECTIONS)
        self.assertIn('parsed_extension_data', RESULT_COLLECTIONS)
        self.assertIn('installed_extensions', RESULT_COLLECTIONS)

    def test_collection_sizes_handles_dict_shaped_collections(self):
        browser = WebBrowser('p', 'Chrome')
        browser.installed_extensions = {'data': [1, 2, 3], 'presentation': {}}
        self.assertEqual(3, browser.collection_sizes()['installed_extensions'])


class TestDriverRecordsPartials(unittest.TestCase):

    def _driver(self):
        browser = WebBrowser('fixture-profile', 'Chrome')
        browser.display_version = '999'
        driver = ProcessingDisplay(browser, ['Group'])
        driver.console = rich.console.Console(file=io.StringIO(), width=110)
        return driver

    def _run(self, returned):
        driver = self._driver()
        with driver:
            driver.group('Group')
            driver.run('Local Storage', 'Local Storage', lambda: returned,
                       display_value='Local Storage records', artifact='local-storage')
        return driver

    def test_a_plain_int_is_a_clean_count(self):
        driver = self._run(412)
        result = driver.browser.artifact_results['Local Storage']
        self.assertEqual(412, result.count)
        self.assertIsNone(result.status)
        self.assertFalse(result.is_partial)

    def test_a_partial_result_records_both_tiers(self):
        driver = self._run(ParseResult(412, 3, 5))
        result = driver.browser.artifact_results['Local Storage']
        self.assertEqual(412, result.count)
        self.assertEqual(3, result.unparsed_sources)
        self.assertEqual(5, result.unparsed_records)
        self.assertEqual(ARTIFACT_STATUS_PARTIAL, result.status)

    def test_a_partial_result_still_reports_its_count(self):
        # Unlike a failure, a partial parse produced records; the count is real and
        # must survive, with the caveat attached rather than replacing it.
        driver = self._run(ParseResult(412, 3, 0))
        self.assertEqual({'Local Storage': 412}, driver.browser.artifacts_counts)

    def test_a_parse_result_with_no_losses_is_not_marked_partial(self):
        driver = self._run(ParseResult(412))
        result = driver.browser.artifact_results['Local Storage']
        self.assertIsNone(result.status)

    def test_the_logged_summary_matches_the_recorded_result(self):
        # The driver builds the summary from the record it just wrote, so the totals
        # in the log are by construction the totals rendered on screen.
        with _LogCapture() as captured:
            driver = self._run(ParseResult(412, 3, 5))
        result = driver.browser.artifact_results['Local Storage']
        summaries = [m for m in captured.messages if 'parsed' in m and 'unparsed' in m]
        self.assertEqual(1, len(summaries), captured.messages)
        found = re.search(r'parsed (\d+); (.+)', summaries[0])
        self.assertEqual(str(result.count), found.group(1))
        self.assertEqual(result.describe_unparsed(), found.group(2))

    def test_the_rendered_note_matches_the_recorded_result(self):
        driver = self._run(ParseResult(412, 3, 5))
        note = driver.output_groups['Group'][0][2]
        self.assertEqual('3 sources, 5 records', note.plain)

    def test_only_the_tiers_that_lost_something_are_named(self):
        self.assertEqual(
            '5 records', self._run(ParseResult(412, 0, 5)).output_groups['Group'][0][2].plain)
        self.assertEqual(
            '3 sources', self._run(ParseResult(412, 3, 0)).output_groups['Group'][0][2].plain)

    def test_sources_are_named_before_records(self):
        # A source that would not open could have held anything, so it is the finding
        # that stops the count being usable as a total; it leads.
        note = self._run(ParseResult(412, 3, 5)).output_groups['Group'][0][2].plain
        self.assertLess(note.index('source'), note.index('record'))

    def test_unparsed_is_not_written_as_a_subtraction(self):
        # "412" and "5 records" are two facts about the artifact. A leading minus read
        # as arithmetic -- as though 5 had been taken off the 412 that was parsed.
        note = self._run(ParseResult(412, 3, 5)).output_groups['Group'][0][2].plain
        self.assertFalse(note.startswith('-'), note)
        self.assertNotIn('-', note)

    def test_a_clean_artifact_has_an_empty_unparsed_cell(self):
        driver = self._run(412)
        self.assertIsNone(driver.output_groups['Group'][0][2])

    def test_each_artifact_stays_on_one_row(self):
        # The unparsed tally rides beside the count instead of adding a row, so an
        # incomplete artifact doesn't read as two artifacts.
        driver = self._run(ParseResult(412, 3, 5))
        lines = [l for l in driver.console.file.getvalue().splitlines()
                 if 'Local Storage records' in l]
        self.assertEqual(1, len(lines))
        self.assertIn('412', lines[0])
        self.assertIn('3 sources', lines[0])
        self.assertIn('5 records', lines[0])

    def test_the_unparsed_column_appears_only_when_something_went_unparsed(self):
        # Present or absent for the whole run, never per group: a column on some groups
        # and not others gives the tables different widths and they stop lining up.
        self.assertNotIn('Unparsed', self._run(412).console.file.getvalue())
        self.assertIn('Unparsed', self._run(ParseResult(412, 3, 5)).console.file.getvalue())
        # And the parsed column is labelled as such in both cases.
        self.assertIn('Parsed', self._run(412).console.file.getvalue())


class TestDisplayTeardownNeverMasksTheRealError(unittest.TestCase):
    """A failure closing the display must not stand in for the exception underneath.

    rich flushes buffered output when the live display exits. With stdout redirected
    on Windows that write can raise UnicodeEncodeError on the spinner's Braille
    glyphs, and it used to replace whatever was already propagating. A run that died
    on a parse error reported a bogus encoding error instead, which matters most in
    CI, where stdout is always redirected and the log is all anyone sees.
    """

    class _ExplodingLive:
        """Stands in for rich's Live once the console can no longer be written to."""

        def __exit__(self, *exc_info):
            raise UnicodeEncodeError(
                'charmap', '⠦', 0, 1, 'character maps to <undefined>')

    def _driver(self):
        browser = WebBrowser('fixture-profile', 'Chrome')
        browser.display_version = '999'
        driver = ProcessingDisplay(browser, ['Group'])
        driver.console = rich.console.Console(file=io.StringIO(), width=110)
        return driver

    def test_the_real_exception_survives_a_failing_teardown(self):
        driver = self._driver()
        with self.assertRaises(ValueError) as caught:
            with driver:
                driver._live = self._ExplodingLive()
                raise ValueError('the parse failure that actually stopped the run')
        self.assertIn('actually stopped the run', str(caught.exception))

    def test_a_failing_teardown_alone_does_not_raise(self):
        driver = self._driver()
        with driver:
            driver._live = self._ExplodingLive()

    def test_a_clean_exit_does_not_swallow_an_exception(self):
        driver = self._driver()
        with self.assertRaises(ValueError):
            with driver:
                raise ValueError('must not be suppressed')


if __name__ == '__main__':
    unittest.main()
