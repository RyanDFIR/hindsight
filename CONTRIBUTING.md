# Contributing to Hindsight

Thanks for helping. This file covers how to get set up, how to run the tests, and one
thing that is easy to miss: Hindsight has two test suites, and the second one runs
against several gigabytes of real browser profiles that are not in this repository.

## Getting set up

Python 3.11 or newer. The floor is 3.11 because `pyhindsight.utils` uses
`datetime.UTC`, which does not exist before it.

```
git clone https://github.com/RyanDFIR/hindsight.git
cd hindsight
pip install -r requirements.txt --group test
```

## The two test suites

**Unit tests** are fast, self-contained and need no setup. No network, no platform
guards, and every fixture is committed under `tests/fixtures`:

```
pytest tests/
```

**Corpus tests** parse whole browser profiles end to end and compare the result to
committed baselines. They are the ones that catch schemas from 2018, half-written
LevelDBs, and databases missing a column the query names. They need the corpus, and
without it they skip:

```
pytest tests/test_corpus_e2e.py
...
SKIPPED [1] set HINDSIGHT_TEST_CORPUS to a corpus directory
3 passed, 2 skipped
```

That skip is deliberate, so that `pytest tests/` stays green for someone who has not
downloaded 6 GB of profiles. The trap is that a green local run does not mean the corpus
tests passed, because they never ran. CI runs them on every pull request, including from
forks, so a change that moves a baseline shows up there whether or not you saw it
locally.

## Getting the corpus

The corpus is published as release assets on a public repository, so there is no token
and no secret involved and nothing to ask for:

<https://github.com/RyanDFIR/data-sets/releases/tag/corpus-v1>

Six roots, one `.tar.gz` each, about 3 GB to download and 5.9 GB extracted:

| Root | Profiles |
| --- | --- |
| `bf4sa_2025_bob-1` | 2 Chrome |
| `bf4sa_2026_bob-2` | 2 Chrome |
| `magnet.ctf_2018` | 2 Chrome, 2 Firefox |
| `magnet.ctf_2019` | 2 Chrome |
| `magnet.ctf_2020` | 1 Chrome |
| `magnet.ctf_2023` | 4 Chrome, 1 Edge |

The `bf4sa` roots are a synthetic persona built for training material. The `magnet` roots
are Magnet Forensics CTF images. Saved passwords and cookie values in them are
DPAPI-encrypted and bound to the machine that created them, so they cannot be read out of
these archives.

Extract every root you want into one directory. You do not need all six; the suite tests
whichever baselines match the roots it finds.

```
mkdir corpus
curl -L -o magnet.ctf_2018.tar.gz \
  https://github.com/RyanDFIR/data-sets/releases/download/corpus-v1/magnet.ctf_2018.tar.gz
tar -xzf magnet.ctf_2018.tar.gz -C corpus
```

`SHA256SUMS` in the same release lists the checksums. `tar` and `curl` ship with Windows
10 and later, so the commands above work in PowerShell as written.

Then point the suite at the directory holding the roots:

```
HINDSIGHT_TEST_CORPUS=/path/to/corpus pytest tests/test_corpus_e2e.py
```

PowerShell:

```
$env:HINDSIGHT_TEST_CORPUS = "D:\path\to\corpus"; pytest tests/test_corpus_e2e.py
```

To run a single root, because you only downloaded one or because you are narrowing a
failure. One root takes a few seconds where all six take a few minutes:

```
HINDSIGHT_TEST_CORPUS=/path/to/corpus HINDSIGHT_TEST_CORPUS_ROOTS=magnet.ctf_2018 \
  pytest tests/test_corpus_e2e.py
```

## When your change moves a baseline

A corpus failure is not automatically a bug. It says parse output changed, and someone
has to say which of the two it was:

```
magnet.ctf_2018 no longer parses to its baseline:
  ...Default: Extensions count 3 -> 4
  ...Default: Extensions status partial -> None
```

If the change is what you intended, because you fixed a parser and it now recovers
records it used to miss, regenerate the baseline for that root and commit it alongside
the code:

```
python tests/corpus/generate_baselines.py magnet.ctf_2018
```

Then say in the commit message what moved and why. The whole value of these files is that
they make an unintended change visible, so regenerating on autopilot to turn a build green
throws away the thing they are for. If a baseline moved and you cannot explain why, that
is the bug.

If you would rather not download several gigabytes, that is fine. Say in the pull request
that you did not run the corpus tests, and a maintainer will regenerate any baseline your
change moves.

## Opening a pull request

A few things that make review quick:

* One issue per pull request.
* A test that fails without your fix. If the fix is a pin for behaviour that already
  works, say so rather than implying it caught something.
* Say what you verified and what you did not. "I could not run the corpus" is useful
  information, and no one will hold it against you.
* Plain prose in the description. Say what was wrong, what you changed, and how you
  checked it. Headings and tables are rarely needed for a change of a few dozen lines.
