"""The progress display must never cost us records.

On a cp1252 stdout, rich's Braille spinner raises when it renders, and because it renders
from inside a running parser, that parser's `except` reports its artifact as unreadable.
Three of nine test profiles lost their Session Storage this way, 954 records.

Two defences: an encodable spinner (`spinner_name`), and stdout degrading unencodable
characters (`utils.make_stdout_resilient`), which is the only one that covers writes
from inside third-party code.
"""

import io
import os
import subprocess
import sys
import tempfile
import unittest

import rich.console

from pyhindsight.browsers.webbrowser import (
    ProcessingDisplay,
    WebBrowser,
    spinner_name,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME_FIXTURE = os.path.join('tests', 'fixtures', 'profiles', '60')

# One frame of rich's "dots" spinner. Outside cp1252, which is the whole problem.
BRAILLE = '\u280b'


def cp1252_console(**kwargs):
    """A console writing to a strict cp1252 stream, as a redirected run on Windows does."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding='cp1252', errors='strict')
    return rich.console.Console(file=stream, width=110, **kwargs)


class TestSpinnerRespectsTheStreamEncoding(unittest.TestCase):

    def test_a_stream_that_cannot_carry_braille_gets_an_ascii_spinner(self):
        self.assertEqual('line', spinner_name(cp1252_console()))

    def test_a_utf8_stream_keeps_the_braille_spinner(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        self.assertEqual('dots', spinner_name(rich.console.Console(file=stream, width=110)))

    def test_the_chosen_spinner_is_always_encodable(self):
        # The property that actually matters, independent of which spinner is picked.
        from rich._spinners import SPINNERS
        console = cp1252_console()
        for frame in SPINNERS[spinner_name(console)]['frames']:
            frame.encode(console.encoding)


class TestTheDisplaySurvivesACp1252Stream(unittest.TestCase):
    """Rendering a running parser's row must not raise on a cp1252 stream.

    Before the fix the spinner row rendered Braille and the write raised inside
    `driver.run()`, taking the parser's count with it.
    """

    def _driver(self):
        browser = WebBrowser('fixture-profile', 'Chrome')
        browser.display_version = '999'
        driver = ProcessingDisplay(browser, ['Group'])
        driver.console = cp1252_console()
        return driver

    def test_the_live_view_renders_without_raising(self):
        driver = self._driver()
        with driver:
            driver.group('Group')
            # Put a spinner row on the table, then force the render that used to raise.
            driver.output_groups.setdefault('Group', []).append(
                ('Session Storage records', _spinner_marker(), None))
            driver.console.print(driver._build_live_view())


def _spinner_marker():
    from pyhindsight.browsers import webbrowser
    return webbrowser._SPINNER


class TestTheFullChainOnACp1252Stdout(unittest.TestCase):
    """The production path, end to end, out of process.

    `ccl_chromium_sessionstorage` reports undecodable records with a bare `print()`, and
    rich proxies stdout while the display is up, so that print renders into the cp1252
    stream from inside the parser. Out of process because the guard mutates the real
    `sys.stdout`, which pytest replaces.
    """

    SCRIPT = (
        'import sys, io, json\n'
        'sys.stdout = io.TextIOWrapper(open(sys.argv[1], "wb"), '
        'encoding="cp1252", errors="strict")\n'
        'from pyhindsight.utils import make_stdout_resilient\n'
        'if sys.argv[2] == "guard":\n'
        '    make_stdout_resilient()\n'
        'from pyhindsight.browsers.webbrowser import ProcessingDisplay, WebBrowser\n'
        'browser = WebBrowser("fixture-profile", "Chrome")\n'
        'browser.display_version = "999"\n'
        'driver = ProcessingDisplay(browser, ["Group"])\n'
        'def parser():\n'
        '    print("Invalid namespace key: \\u280b")  # what the ccl reader does\n'
        '    return 678\n'
        'with driver:\n'
        '    driver.group("Group")\n'
        '    driver.run("Session Storage", "Session Storage", parser,\n'
        '               display_value="Session Storage records",\n'
        '               artifact="session-storage")\n'
        'sys.stdout.flush()\n'
        'sys.stderr.write(json.dumps(browser.artifacts_counts.get("Session Storage")))\n'
    )

    def _run(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            return subprocess.run(
                [sys.executable, '-c', self.SCRIPT, os.path.join(tmp, 'out.txt'), mode],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)

    def test_the_parsers_records_survive_a_librarys_stray_print(self):
        result = self._run('guard')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('678', result.stderr.strip().splitlines()[-1])

    def test_without_the_guard_the_same_run_loses_the_artifact(self):
        # Pins the bug itself, so the fix cannot be quietly removed. Without the guard
        # the write raises inside the parser and the count never reaches the browser.
        result = self._run('no-guard')
        survived = (result.returncode == 0
                    and result.stderr.strip().endswith('678'))
        self.assertFalse(
            survived,
            'A stray unencodable print no longer breaks the parse even without the '
            'stdout guard. If rich or the parser changed, re-check whether '
            'make_stdout_resilient() is still load-bearing before deleting this test.')


class TestStdoutIsResilient(unittest.TestCase):

    def test_the_guard_makes_an_unencodable_write_survivable(self):
        # Run it out of process: the guard mutates the real sys.stdout, and pytest
        # replaces stdout with an object that has no reconfigure().
        script = (
            'import sys, io\n'
            'sys.stdout = io.TextIOWrapper(open(sys.argv[1], "wb"), '
            'encoding="cp1252", errors="strict")\n'
            'from pyhindsight.utils import make_stdout_resilient\n'
            'make_stdout_resilient()\n'
            'sys.stdout.write("\\u280b")\n'
            'sys.stdout.flush()\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'out.txt')
            result = subprocess.run([sys.executable, '-c', script, out],
                                    cwd=REPO_ROOT, capture_output=True, text=True,
                                    timeout=120)
            self.assertEqual(0, result.returncode, result.stderr)
            with open(out, 'rb') as f:
                # backslashreplace, so the character is described rather than dropped.
                self.assertEqual(rb'\u280b', f.read())

    def test_the_guard_reports_failure_instead_of_raising(self):
        from pyhindsight import utils
        original = sys.stdout
        try:
            sys.stdout = object()  # no reconfigure, as under pytest capture
            self.assertFalse(utils.make_stdout_resilient())
        finally:
            sys.stdout = original

    def test_a_cli_run_completes_on_a_cp1252_stdout(self):
        env = dict(os.environ, PYTHONIOENCODING='cp1252')
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, 'hindsight.py', '-i', CHROME_FIXTURE,
                 '-o', os.path.join(tmp, 'out'), '-f', 'jsonl',
                 '-l', os.path.join(tmp, 'hindsight.log'),
                 '--temp_dir', os.path.join(tmp, 'temp')],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, env=env)
            self.assertEqual(0, result.returncode,
                             f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
            self.assertNotIn('UnicodeEncodeError', result.stdout + result.stderr)
            self.assertTrue(os.path.exists(os.path.join(tmp, 'out.jsonl')))


if __name__ == '__main__':
    unittest.main()
