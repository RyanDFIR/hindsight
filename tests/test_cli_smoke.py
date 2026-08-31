import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join('tests', 'fixtures', 'firefox')


CHROME_FIXTURE = os.path.join('tests', 'fixtures', 'profiles', '60')


def run_hindsight(*args, output_dir, profile=FIXTURE):
    """Run the CLI the way a user does."""
    return subprocess.run(
        [sys.executable, 'hindsight.py', '-i', profile,
         '-o', os.path.join(output_dir, 'out'),
         '-l', os.path.join(output_dir, 'hindsight.log'),
         '--temp_dir', os.path.join(output_dir, 'temp'), *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)


class TestCommandLineRuns(unittest.TestCase):
    """End-to-end smoke tests for the CLI itself.

    The unit tests exercise AnalysisSession and the browsers directly, so nothing
    covered `hindsight.py` -- and a rename of one AnalysisSession method got all the
    way through a green suite and a real parse before dying at the very last step, in
    the output summary. Anything that reaches the user through the CLI needs at least
    one test that actually starts the CLI.
    """

    def test_a_plain_run_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', output_dir=tmp)
            self.assertEqual(0, result.returncode,
                             f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
            self.assertNotIn('Traceback', result.stdout + result.stderr)
            out = os.path.join(tmp, 'out.jsonl')
            self.assertTrue(os.path.exists(out))
            with open(out, encoding='utf-8') as f:
                records = [json.loads(line) for line in f if line.strip()]
            self.assertTrue(records)

    def test_every_output_format_completes(self):
        for fmt in ('jsonl', 'sqlite', 'xlsx'):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as tmp:
                result = run_hindsight('-f', fmt, output_dir=tmp)
                self.assertEqual(0, result.returncode,
                                 f'{fmt} stderr:\n{result.stderr}')
                self.assertTrue(os.path.exists(os.path.join(tmp, f'out.{fmt}')))

    def test_a_run_with_unparsed_artifacts_completes(self):
        # The summary row for unparsed artifacts is only built when something went
        # unparsed, so a clean run never reaches that code. Skipping an artifact is the
        # cheapest way to make the run report one.
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', '--skip', 'cookies', output_dir=tmp)
            self.assertEqual(0, result.returncode,
                             f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
            self.assertNotIn('Traceback', result.stdout + result.stderr)

    def test_artifact_selection_reaches_the_output(self):
        # Run against a Chrome profile: Firefox history and downloads never reach JSONL
        # at all (HindsightEncoder has no branch for their classes), which is a separate
        # known gap and would mask what this test is actually checking.
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', '--only', 'history',
                                   output_dir=tmp, profile=CHROME_FIXTURE)
            self.assertEqual(0, result.returncode, result.stderr)
            with open(os.path.join(tmp, 'out.jsonl'), encoding='utf-8') as f:
                types = {json.loads(line).get('data_type') for line in f if line.strip()}
            self.assertTrue(types, 'no records written')
            self.assertTrue(all('history' in t for t in types), types)

    def test_list_artifacts_needs_no_input_and_exits_cleanly(self):
        result = subprocess.run(
            [sys.executable, 'hindsight.py', '--list-artifacts'],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('history', result.stdout)

    def test_an_unknown_artifact_name_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('--only', 'notanartifact', output_dir=tmp)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Unknown artifact', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
