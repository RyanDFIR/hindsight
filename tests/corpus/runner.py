"""Run Hindsight over a corpus root and reduce the result to a comparable baseline.

The manual procedure this replaces: parse a set of real profiles before and after a
change, then diff the counts, labels and statuses. That has caught things no unit test
did (a whole Session Storage artifact vanishing on Windows, four parsers silently
dropping stores), and it existed only as something a human remembered to do.

Shared by `generate_baselines.py` and `tests/test_corpus_e2e.py`, so the numbers a
baseline records and the numbers a test compares are produced by the same code.

Plugins are deliberately not run. They add `interpretation` values, and at least one
makes an outbound network call, so including them would make the baseline depend on a
third party being up and unchanged.
"""

import collections
import datetime
import json
import os
import pathlib
import tempfile
import zoneinfo

from pyhindsight.analysis import AnalysisSession
from pyhindsight.artifact_filter import ArtifactFilter


def _relative_profile(profile_path, root):
    """Profile path as a stable, portable key.

    `artifact_results` is keyed by the absolute path the run was given, which differs on
    every machine and between operating systems. Baselines have to survive that, so the
    key becomes a forward-slashed path relative to the corpus root.
    """
    normalized = str(profile_path).replace('\\', '/')
    root = str(root).replace('\\', '/').rstrip('/')
    if normalized.startswith(root):
        normalized = normalized[len(root):]
    return normalized.strip('/')


def run_root(root, temp_dir=None):
    """Parse one corpus root and return its baseline as a plain dict.

    `root` is a directory Hindsight is pointed at; it finds the profiles beneath it. One
    root can hold several profiles and more than one browser, which is the point: it
    exercises recursive discovery and mixed-browser dispatch as well as the parsers.
    """
    root = pathlib.Path(root)
    session = AnalysisSession()
    session.input_path = str(root)
    session.selected_output_format = 'jsonl'
    session.artifact_filter = ArtifactFilter.from_selectors(None, None)
    session.browser_type = None
    session.timezone = zoneinfo.ZoneInfo('UTC')
    session.no_copy = False

    with tempfile.TemporaryDirectory(dir=temp_dir) as scratch:
        session.temp_dir = os.path.join(scratch, 'temp')
        session.log_path = os.path.join(scratch, 'hindsight.log')
        session.output_name = os.path.join(scratch, 'out')

        if not session.run():
            raise RuntimeError(f'{root.name}: run failed ({session.fatal_error})')

        # data_type is assigned by the JSONL encoder rather than carried on the item, so
        # counting it means writing the output. Per-data_type counts are what caught the
        # Session Storage regression: the total alone moved by less than 2%.
        jsonl_path = os.path.join(scratch, 'out.jsonl')
        session.generate_jsonl(jsonl_path)
        data_types = collections.Counter()
        total = 0
        with open(jsonl_path, encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    data_types[json.loads(line).get('data_type', '<none>')] += 1
                    total += 1

    profiles = {}
    for profile_path, results in session.artifact_results.items():
        key = _relative_profile(profile_path, root)
        profiles[key] = {
            'browser': session.detected_profile_families.get(profile_path),
            'artifacts': {
                name: {
                    'count': result.count,
                    'status': result.status,
                    'unparsed_sources': result.unparsed_sources,
                    'unparsed_records': result.unparsed_records,
                }
                for name, result in sorted(results.items())
            },
        }

    return {
        'root': root.name,
        'total_records': total,
        'data_types': dict(sorted(data_types.items())),
        'profiles': dict(sorted(profiles.items())),
    }


def diff(expected, actual):
    """Return a list of human-readable differences, empty when the two agree.

    Deliberately verbose about *what* moved rather than dumping both dicts: the useful
    output of a failure is "chrome:session_storage:entry 678 -> 0", which names the
    artifact to go and look at.
    """
    problems = []

    if expected['total_records'] != actual['total_records']:
        problems.append(
            f"total records {expected['total_records']} -> {actual['total_records']}")

    exp_types, act_types = expected['data_types'], actual['data_types']
    for name in sorted(set(exp_types) | set(act_types)):
        before, after = exp_types.get(name, 0), act_types.get(name, 0)
        if before != after:
            problems.append(f'{name} {before} -> {after}')

    exp_profiles, act_profiles = expected['profiles'], actual['profiles']
    for missing in sorted(set(exp_profiles) - set(act_profiles)):
        problems.append(f'profile no longer found: {missing}')
    for added in sorted(set(act_profiles) - set(exp_profiles)):
        problems.append(f'unexpected profile: {added}')

    for name in sorted(set(exp_profiles) & set(act_profiles)):
        before, after = exp_profiles[name], act_profiles[name]
        if before['browser'] != after['browser']:
            problems.append(
                f"{name}: detected as {before['browser']} -> {after['browser']}")
        exp_art, act_art = before['artifacts'], after['artifacts']
        for gone in sorted(set(exp_art) - set(act_art)):
            problems.append(f'{name}: artifact no longer reported: {gone}')
        for new in sorted(set(act_art) - set(exp_art)):
            problems.append(f'{name}: new artifact reported: {new}')
        for artifact in sorted(set(exp_art) & set(act_art)):
            for field in ('count', 'status', 'unparsed_sources', 'unparsed_records'):
                b, a = exp_art[artifact][field], act_art[artifact][field]
                if b != a:
                    problems.append(f'{name}: {artifact} {field} {b} -> {a}')

    return problems


def write_baseline(baseline, path, hindsight_version):
    """Write a baseline, stamped with what produced it.

    The version and date are provenance for a human reading a diff; `diff()` never
    compares them, because a version bump is not a regression.
    """
    payload = dict(baseline)
    payload['generated_by'] = {
        'hindsight_version': hindsight_version,
        'generated_utc': datetime.datetime.now(datetime.timezone.utc)
                                 .strftime('%Y-%m-%dT%H:%M:%SZ'),
    }
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write('\n')


def load_baseline(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)
