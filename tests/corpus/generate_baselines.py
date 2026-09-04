"""Regenerate the corpus baselines.

    python tests/corpus/generate_baselines.py --corpus D:/hindsight/github-test-data

Run this deliberately, never to make a red build green. A baseline changing means real
parse output changed: either a parser improved (regenerate, and say what moved in the
commit message) or something broke (do not regenerate). The whole value of these files
is that they make that difference visible, and regenerating on autopilot throws it away.

With no root names it does every root the corpus holds. Name roots to do a subset:

    python tests/corpus/generate_baselines.py magnet.ctf_2019
"""

import argparse
import os
import pathlib
import sys
import time

# Run as a script, so the repo root is not on the path yet; both pyhindsight and the
# tests package are imported from there.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import pyhindsight
from tests.corpus.runner import run_root, write_baseline

BASELINE_DIR = pathlib.Path(__file__).resolve().parent / 'baselines'


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('roots', nargs='*',
                        help='root directory names; default is every root present')
    parser.add_argument('--corpus', default=os.environ.get('HINDSIGHT_TEST_CORPUS'),
                        help='corpus directory (default: $HINDSIGHT_TEST_CORPUS)')
    args = parser.parse_args()

    if not args.corpus:
        parser.error('no corpus path; pass --corpus or set HINDSIGHT_TEST_CORPUS')
    corpus = pathlib.Path(args.corpus)
    if not corpus.is_dir():
        parser.error(f'corpus directory does not exist: {corpus}')

    names = args.roots or sorted(p.name for p in corpus.iterdir() if p.is_dir())
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)

    total_started = time.time()
    for name in names:
        root = corpus / name
        if not root.is_dir():
            print(f'  {name}: not in the corpus, skipped')
            continue
        started = time.time()
        baseline = run_root(root)
        destination = BASELINE_DIR / f'{name}.json'
        write_baseline(baseline, destination, pyhindsight.__version__)
        print(f'  {name}: {baseline["total_records"]} records, '
              f'{len(baseline["profiles"])} profiles, '
              f'{len(baseline["data_types"])} data types, '
              f'{time.time() - started:.0f}s -> {destination.name}')
    print(f'total {time.time() - total_started:.0f}s')


if __name__ == '__main__':
    main()
