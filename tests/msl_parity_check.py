"""Measure MSL plugin parity: Hindsight's adapter against a real ChromiumProfileFolder.

Not a unit test, and deliberately not named test_*: it needs a mister-skinnylegs
checkout and a real browser profile, and a full run takes minutes. Run it by hand when
changing pyhindsight/msl_adapter.py or after a parser change that could move what the
plugins see.

    python tests/msl_parity_check.py --msl D:/github/mister-skinnylegs \
                                     --input P:/bf4sa_2025_bob-1 \
                                     --profile Default

Every MSL artifact runs twice, once against a ChromiumProfileFolder opened on the
profile folder and once against HindsightProfileAdapter over the parsed rows. It
compares row counts *and* column sets, because the interesting failure is silent: four
plugins gate optional fields on isinstance(profile, ChromiumProfileFolder), so a profile
that only satisfies the protocol structurally returns the right number of rows with
columns quietly missing.

Last measured on bf4sa_2025_bob-1/Default:
    identical: 27   column-loss: 0   row-count-diff: 1   adapter-errors: 0
The remaining difference is Sessionstorage, where the adapter is correct: ccl's
iter_all_records yields orphans without honouring include_deletions.
"""

import argparse
import contextlib
import io
import logging
import pathlib
import sys
import types


def load_msl(msl_path):
    """Import mister-skinnylegs, stubbing the Mozilla reader Hindsight does not ship.

    mister_skinnylegs/__init__.py imports .mister_skinnylegs, which imports
    ccl_mozilla_reader at module scope, so importing any submodule pulls it in. Any real
    integration has to vendor MSL's util package or take on that dependency.
    """
    sys.path.insert(0, str(msl_path))
    try:
        import ccl_mozilla_reader  # noqa: F401
    except ImportError:
        stub = types.ModuleType('ccl_mozilla_reader')
        stub.MozillaProfileFolder = type('MozillaProfileFolder', (), {})
        sys.modules['ccl_mozilla_reader'] = stub

    from mister_skinnylegs.util.plugin_loader import PluginLoader
    return PluginLoader(msl_path / 'mister_skinnylegs' / 'plugins')


def make_null_storage(msl_path):
    """An ArtifactStorage that counts writes instead of performing them.

    Four plugins write binary side-files. Hindsight produces a single output file and
    has no side-directory concept, so a real integration needs a decision here; for a
    parity measurement, discarding the bytes is enough.
    """
    from mister_skinnylegs.util.artifact_utils import (
        ArtifactStorage, ArtifactStorageBinaryStream)

    class NullStream(ArtifactStorageBinaryStream):
        def __init__(self, name, source_file):
            super().__init__(source_file)
            self.name = name

        def write(self, data):
            return len(data)

        def close(self):
            pass

        def get_file_location_reference(self):
            return f'<discarded>/{self.name}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class NullStorage(ArtifactStorage):
        def __init__(self):
            self.files = []

        def get_binary_stream(self, file_name, source_file):
            stream = NullStream(file_name, source_file)
            self.files.append(stream)
            return stream

        get_text_stream = get_binary_stream

    return NullStorage


def run_artifacts(loader, profile, storage_cls):
    results = {}
    for spec, _ in loader.artifacts:
        try:
            outcome = spec.function(profile, lambda message: None, storage_cls())
            rows = outcome.result if isinstance(outcome.result, list) else []
            columns = []
            for row in rows:
                if isinstance(row, dict):
                    for key in row:
                        if key not in columns:
                            columns.append(key)
            results[spec.name] = (len(rows), tuple(columns), None)
        except Exception as exc:
            results[spec.name] = (None, (), f'{type(exc).__name__}: {exc}')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--msl', required=True, type=pathlib.Path,
                        help='path to a mister-skinnylegs checkout')
    parser.add_argument('--input', required=True,
                        help='path Hindsight should analyse')
    parser.add_argument('--profile', default='Default',
                        help='which discovered profile to compare (suffix match)')
    args = parser.parse_args()

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    logging.basicConfig(level=logging.ERROR)

    import ccl_chromium_reader
    loader = load_msl(args.msl)
    storage_cls = make_null_storage(args.msl)
    print(f'{len(loader)} MSL artifacts loaded from {args.msl}')

    from pyhindsight.analysis import AnalysisSession
    from pyhindsight.msl_adapter import HindsightProfileAdapter

    session = AnalysisSession(
        input_path=args.input, no_copy=True, timezone='UTC',
        available_output_formats=['xlsx'], selected_output_format='xlsx',
        available_input_types=['Chrome'], selected_decrypts=[])
    session.profile_paths = session.find_browser_profiles(args.input)
    matching = [p for p in session.profile_paths if p.endswith(args.profile)]
    if not matching:
        sys.exit(f'no profile ending in {args.profile!r} among {session.profile_paths}')
    profile_path = matching[0]

    print(f'running MSL against a real ChromiumProfileFolder on {profile_path}')
    with ccl_chromium_reader.ChromiumProfileFolder(
            pathlib.Path(profile_path), missing_data_ok=True) as profile:
        direct = run_artifacts(loader, profile, storage_cls)

    print('running Hindsight, then MSL against the adapter')
    with contextlib.redirect_stdout(io.StringIO()):
        session.run()
    adapted = run_artifacts(
        loader, HindsightProfileAdapter(session, profile_path), storage_cls)

    print()
    print('%-38s %10s %10s  %s' % ('artifact', 'direct', 'adapter', 'delta'))
    print('-' * 96)
    tally = {'identical': 0, 'column-loss': 0, 'row-count-diff': 0, 'adapter-errors': 0}
    for name in sorted(direct):
        direct_rows, direct_cols, direct_err = direct[name]
        adapted_rows, adapted_cols, adapted_err = adapted[name]
        lost = [c for c in direct_cols if c not in adapted_cols]
        gained = [c for c in adapted_cols if c not in direct_cols]

        if adapted_err:
            note = f'ADAPTER ERROR: {adapted_err}'
            tally['adapter-errors'] += 1
        elif direct_err:
            note = f'direct error: {direct_err}'
        elif direct_rows != adapted_rows:
            note = 'ROW COUNT DIFFERS'
            tally['row-count-diff'] += 1
        elif lost:
            note = 'COLUMNS LOST: ' + ', '.join(lost)
            tally['column-loss'] += 1
        else:
            note = ''
            tally['identical'] += 1
        if gained:
            note += ' | gained: ' + ', '.join(gained)
        print('%-38s %10s %10s  %s' % (name[:38], direct_rows, adapted_rows, note))

    print('-' * 96)
    print('   '.join(f'{k}: {v}' for k, v in tally.items()) + f'   (of {len(direct)})')


if __name__ == '__main__':
    main()
