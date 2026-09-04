"""End-to-end parses of real browser profiles, compared to committed baselines.

Every other test in this suite builds its own fixture. That catches logic errors and
misses the thing real profiles are full of: schemas from 2018, half-written LevelDBs,
databases missing a column the query names. The checks that have actually caught
regressions here were whole-profile parses diffed by hand, and this is that procedure
written down.

Needs a corpus, so it skips unless HINDSIGHT_TEST_CORPUS points at one:

    HINDSIGHT_TEST_CORPUS=D:/hindsight/github-test-data pytest tests/test_corpus_e2e.py

Skipping rather than failing is deliberate: the corpus is several GB and cannot be
committed, so the ordinary `pytest tests/` a contributor runs must stay green without
it. What must not happen is CI thinking it ran these and quietly running nothing, which
`test_the_corpus_is_complete` exists to prevent.

Baselines live in tests/corpus/baselines/ and are regenerated with
tests/corpus/generate_baselines.py. See that file before regenerating anything.
"""

import os
import pathlib
import unittest

from tests.corpus.runner import diff, load_baseline, run_root

CORPUS = os.environ.get('HINDSIGHT_TEST_CORPUS')
BASELINE_DIR = pathlib.Path(__file__).resolve().parent / 'corpus' / 'baselines'

# CI shards one root per job, so each job holds only the root it is testing. Without
# this the completeness check would fail every shard for the five roots it was never
# given. Unset means "every baseline", which is what a local run wants.
SELECTED = [r.strip() for r in os.environ.get('HINDSIGHT_TEST_CORPUS_ROOTS', '').split(',')
            if r.strip()]


def baselines():
    found = sorted(BASELINE_DIR.glob('*.json'))
    if SELECTED:
        found = [p for p in found if p.stem in SELECTED]
    return found


@unittest.skipUnless(CORPUS, 'set HINDSIGHT_TEST_CORPUS to a corpus directory')
class TestCorpusParses(unittest.TestCase):
    """A parse of each corpus root still produces what it produced before.

    A failure here is not automatically a bug: a parser improvement moves these numbers
    too. It means output changed and someone has to say which of the two it was.
    """

    @classmethod
    def setUpClass(cls):
        cls.corpus = pathlib.Path(CORPUS)
        if not cls.corpus.is_dir():
            raise unittest.SkipTest(f'HINDSIGHT_TEST_CORPUS is not a directory: {CORPUS}')
        if not baselines():
            raise unittest.SkipTest(f'no baselines in {BASELINE_DIR}')

    def test_the_corpus_is_complete(self):
        """Every baseline has its data present.

        Without this, a corpus that failed to download leaves every root skipped and the
        job green, which is the worst outcome available: it reports that end-to-end
        parses passed when none ran.
        """
        missing = [p.stem for p in baselines() if not (self.corpus / p.stem).is_dir()]
        self.assertEqual([], missing,
                         f'baselines exist for roots not in {self.corpus}: {missing}')
        unknown = sorted(set(SELECTED) - {p.stem for p in BASELINE_DIR.glob('*.json')})
        self.assertEqual([], unknown,
                         f'HINDSIGHT_TEST_CORPUS_ROOTS names roots with no baseline: '
                         f'{unknown}')

    def test_each_root_matches_its_baseline(self):
        for path in baselines():
            root = self.corpus / path.stem
            with self.subTest(root=path.stem):
                if not root.is_dir():
                    self.skipTest(f'{path.stem} not in the corpus')
                problems = diff(load_baseline(path), run_root(root))
                self.assertEqual(
                    [], problems,
                    f'\n{path.stem} no longer parses to its baseline:\n  '
                    + '\n  '.join(problems)
                    + f'\n\nIf this is an intended parser change, regenerate with:\n'
                      f'  python tests/corpus/generate_baselines.py {path.stem}\n'
                      f'and say in the commit message what moved and why.')


class TestBaselinesAreUsable(unittest.TestCase):
    """Checks on the baseline files themselves, which need no corpus."""

    def test_baselines_exist(self):
        self.assertTrue(baselines(), f'no baseline files in {BASELINE_DIR}')

    def test_every_baseline_has_the_expected_shape(self):
        for path in baselines():
            with self.subTest(baseline=path.name):
                baseline = load_baseline(path)
                self.assertEqual(path.stem, baseline['root'])
                self.assertGreater(baseline['total_records'], 0)
                self.assertTrue(baseline['data_types'])
                self.assertTrue(baseline['profiles'])
                self.assertEqual(
                    baseline['total_records'], sum(baseline['data_types'].values()),
                    'total_records disagrees with the sum of its data_types')

    def test_profile_keys_are_portable(self):
        # A baseline generated on Windows has to compare on a Linux runner, so no drive
        # letters and no backslashes.
        for path in baselines():
            baseline = load_baseline(path)
            for profile in baseline['profiles']:
                with self.subTest(baseline=path.name, profile=profile):
                    self.assertNotIn('\\', profile)
                    self.assertNotIn(':', profile)
                    self.assertFalse(profile.startswith('/'))


if __name__ == '__main__':
    unittest.main()
