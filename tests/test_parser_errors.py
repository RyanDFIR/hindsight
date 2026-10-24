import io
import logging
import unittest

import rich.console

from pyhindsight.browsers.webbrowser import (
    ARTIFACT_STATUS_FAILED,
    ARTIFACT_STATUS_PARTIAL,
    ProcessingDisplay,
    WebBrowser,
)


class TestAParserThatRaisesDoesNotEndTheRun(unittest.TestCase):
    """An exception from one parser is recorded against its artifact (issue #374).

    Before, it propagated out of the driver and ended the whole run without a report,
    so a single damaged file cost the analyst every other artifact as well.
    """

    def _driver(self):
        browser = WebBrowser('fixture-profile', 'Chrome')
        browser.display_version = '999'
        driver = ProcessingDisplay(browser, ['Group'])
        driver.console = rich.console.Console(file=io.StringIO(), width=110)
        return driver

    def _run(self, driver, func, key='Local Storage'):
        driver.run(key, key, func, display_value=f'{key} records', artifact='local-storage')
        return driver.browser.artifact_results[key]

    def test_the_artifact_is_failed_and_the_next_one_still_runs(self):
        def broken():
            raise ValueError('bad block')

        driver = self._driver()
        with self.assertLogs('pyhindsight.browsers.webbrowser', logging.ERROR) as logs, driver:
            driver.group('Group')
            failed = self._run(driver, broken)
            following = self._run(driver, lambda: 3, key='Session Storage')

        self.assertEqual(ARTIFACT_STATUS_FAILED, failed.status)
        self.assertEqual('parser error (ValueError: bad block)', failed.detail)
        self.assertIsNone(failed.count)
        self.assertEqual(3, following.count)
        # The traceback is in the log for whoever fixes the parser.
        self.assertIn('Traceback', '\n'.join(logs.output))

    def test_records_delivered_before_the_error_are_kept_as_partial(self):
        driver = self._driver()

        def partly_read():
            driver.browser.parsed_artifacts.extend(['first', 'second'])
            raise IndexError('index out of range')

        with self.assertLogs('pyhindsight.browsers.webbrowser', logging.ERROR), driver:
            driver.group('Group')
            result = self._run(driver, partly_read)

        self.assertEqual(ARTIFACT_STATUS_PARTIAL, result.status)
        self.assertEqual(2, result.count)
        self.assertEqual(1, result.unparsed_sources)
        self.assertEqual(['first', 'second'], driver.browser.parsed_artifacts)

    def test_an_exception_without_a_message_is_named(self):
        # ccl_leveldb raises a bare ValueError() for an unknown log block type.
        def broken():
            raise ValueError()

        driver = self._driver()
        with self.assertLogs('pyhindsight.browsers.webbrowser', logging.ERROR), driver:
            driver.group('Group')
            result = self._run(driver, broken)

        self.assertEqual('parser error (ValueError)', result.detail)

    def test_keyboard_interrupt_still_stops_the_run(self):
        def interrupted():
            raise KeyboardInterrupt

        driver = self._driver()
        with self.assertRaises(KeyboardInterrupt), driver:
            driver.group('Group')
            self._run(driver, interrupted)


if __name__ == '__main__':
    unittest.main()
