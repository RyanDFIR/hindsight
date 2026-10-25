"""Copy ccl_chromium_reader and ccl_simplesnappy into pyhindsight/lib/ at a given commit.

Hindsight bundles both libraries rather than installing them, so a pip install works and
the version that parsed a report is the one in this repository. The source is Hindsight's
fork of ccl_chromium_reader, whose 'hindsight' branch is upstream plus any fixes Hindsight
needs before upstream merges them.

    python tools/vendor_ccl.py <ccl commit>                    # replace the bundled copies
    python tools/vendor_ccl.py <ccl commit> --snappy <commit>  # also move ccl_simplesnappy
    python tools/vendor_ccl.py --check                         # exit 1 if they were edited

The copies are not edited by hand. A fix goes to a branch in the fork (and upstream as a
pull request), is merged into the fork's 'hindsight' branch, and arrives here by running
this script on the new commit. That keeps "what differs from upstream" answerable from
the fork's history.

The only change made while copying is to the imports. Upstream imports its own package
and ccl_simplesnappy by their installed names; those become relative imports so the
bundled copies load from pyhindsight/lib/ and never from whatever else is installed.
--check repeats the copy from the commits recorded in VENDORED.md and compares.

Needs git and network access.
"""
import argparse
import ast
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

LIB = pathlib.Path(__file__).resolve().parent.parent / 'pyhindsight' / 'lib'

CCL_REPO = 'https://github.com/hindsight-foundry/ccl_chromium_reader.git'
CCL_UPSTREAM = 'https://github.com/cclgroupltd/ccl_chromium_reader'
SNAPPY_REPO = 'https://github.com/cclgroupltd/ccl_simplesnappy.git'

# ccl_simplesnappy rarely changes, so it is not forked. This is the commit ccl's own
# dependency on it resolved to when it was first bundled.
SNAPPY_COMMIT = '3d085230baa8c46cf2090ebba29bf6e8eab31087'

PACKAGES = ('ccl_chromium_reader', 'ccl_simplesnappy')
VENDORED_RE = re.compile(r'^Commit: `([0-9a-f]{40})`$', re.MULTILINE)


def checkout(repo, commit, into):
    """Clone repo into a new directory and check out commit; returns the full hash."""
    # autocrlf off, so the copies hold the bytes that are in the repository.
    git = ['git', '-c', 'core.autocrlf=false', '-c', 'advice.detachedHead=false']
    subprocess.run(git + ['clone', '--quiet', '--no-checkout', repo, str(into)], check=True)
    subprocess.run(git + ['-C', str(into), 'checkout', '--quiet', commit], check=True)
    return subprocess.run(['git', '-C', str(into), 'rev-parse', 'HEAD'],
                          check=True, capture_output=True, text=True).stdout.strip()


def rewrite_imports(text, depth):
    """Make a module's imports of the two bundled packages relative.

    depth is how many directories below the ccl_chromium_reader package root the module
    sits, so ccl_chromium_reader/storage_formats/ccl_leveldb.py has depth 1.
    """
    own = '.' * (depth + 1)   # ccl_chromium_reader's root, from this module
    lib = '.' * (depth + 2)   # pyhindsight/lib, where ccl_simplesnappy sits

    def own_package(match):
        indent, submodule = match.group(1), match.group(2)
        return f'{indent}from {own}{submodule.lstrip(".")} import '

    text = re.sub(r'(?m)^([ \t]*)from ccl_chromium_reader((?:\.\w+)*) import ', own_package, text)
    text = re.sub(r'(?m)^([ \t]*)import ccl_simplesnappy[ \t]*$', rf'\1from {lib} import ccl_simplesnappy', text)
    return text


def absolute_imports(path, text):
    """Imports of either bundled package by its installed name that are left in a module."""
    found = []
    for node in ast.walk(ast.parse(text, filename=str(path))):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            names = [node.module or '']
        else:
            continue
        found += [f'{path}:{node.lineno}: {name}' for name in names if name.split('.')[0] in PACKAGES]
    return found


def copy_package(source_root, name, out_root):
    """Copy one package's .py files and the repository LICENSE, rewriting imports."""
    source = source_root / name
    target = out_root / name
    leftovers = []
    for path in sorted(source.rglob('*')):
        if path.is_dir() or '__pycache__' in path.parts:
            continue
        relative = path.relative_to(source)
        if path.suffix != '.py':
            # MANIFEST.in only ships .py and LICENSE files from pyhindsight/lib, so a data
            # file would be silently missing from the sdist. Decide what to do with it.
            sys.exit(f'{name} has a file that is not Python: {relative}')
        # Upstream mixes LF and CRLF files; write LF throughout, as git stores them.
        text = path.read_text(encoding='utf-8').replace('\r\n', '\n')
        text = rewrite_imports(text, depth=len(relative.parts) - 1)
        leftovers += absolute_imports(relative, text)
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text(text, encoding='utf-8', newline='\n')
    if leftovers:
        # An import this script does not know how to rewrite. Loading it would pick up an
        # installed copy, or fail on machines without one.
        sys.exit(f'{name} still imports a bundled package by its installed name:\n  ' + '\n  '.join(leftovers))
    shutil.copyfile(source_root / 'LICENSE', target / 'LICENSE')
    return target


def write_record(target, name, repo, commit, upstream=None):
    lines = [
        f'# Bundled {name}',
        '',
        f'This is a copy of {name}, not code written for Hindsight. Do not edit it here:',
        'tools/vendor_ccl.py replaces this directory, and its --check fails on any difference.',
        '',
        f'Source: {repo.removesuffix(".git")}',
        f'Commit: `{commit}`',
    ]
    if upstream:
        lines += [
            f'Upstream: {upstream}',
            '',
            "The source is Hindsight's fork. Its 'hindsight' branch is upstream plus fixes that are",
            'waiting for upstream to merge them; compare the commit above with upstream to list them.',
        ]
    lines += [
        '',
        'The only change from the source is to imports: imports of ccl_chromium_reader and',
        'ccl_simplesnappy by their installed names are made relative, so this copy is the one',
        'that loads. LICENSE is the source repository\'s license.',
        '',
    ]
    (target / 'VENDORED.md').write_text('\n'.join(lines), encoding='utf-8', newline='\n')


def vendor(ccl_commit, snappy_commit, out_root):
    with tempfile.TemporaryDirectory() as work:
        work = pathlib.Path(work)
        ccl_hash = checkout(CCL_REPO, ccl_commit, work / 'ccl')
        snappy_hash = checkout(SNAPPY_REPO, snappy_commit, work / 'snappy')
        for name in PACKAGES:
            shutil.rmtree(out_root / name, ignore_errors=True)
        write_record(copy_package(work / 'ccl', 'ccl_chromium_reader', out_root),
                     'ccl_chromium_reader', CCL_REPO, ccl_hash, upstream=CCL_UPSTREAM)
        write_record(copy_package(work / 'snappy', 'ccl_simplesnappy', out_root),
                     'ccl_simplesnappy', SNAPPY_REPO, snappy_hash)
    return ccl_hash, snappy_hash


def recorded_commit(name):
    record = LIB / name / 'VENDORED.md'
    match = VENDORED_RE.search(record.read_text(encoding='utf-8')) if record.exists() else None
    if not match:
        sys.exit(f'No commit recorded in {record}')
    return match.group(1)


def tree(root):
    """Every file under root, with line endings normalized so a CRLF checkout compares equal."""
    return {path.relative_to(root).as_posix(): path.read_bytes().replace(b'\r\n', b'\n')
            for path in root.rglob('*') if path.is_file() and '__pycache__' not in path.parts}


def check():
    with tempfile.TemporaryDirectory() as fresh:
        fresh = pathlib.Path(fresh)
        vendor(recorded_commit('ccl_chromium_reader'), recorded_commit('ccl_simplesnappy'), fresh)
        differences = []
        for name in PACKAGES:
            expected, actual = tree(fresh / name), tree(LIB / name)
            for path in sorted(expected.keys() | actual.keys()):
                if expected.get(path) != actual.get(path):
                    state = 'missing' if path not in actual else 'added' if path not in expected else 'edited'
                    differences.append(f'{name}/{path} ({state})')
    if differences:
        print('The bundled copies differ from the commits in VENDORED.md:\n  ' + '\n  '.join(differences))
        print('Make the change in the fork and re-run this script on the new commit.')
        return 1
    print('The bundled copies match the commits in VENDORED.md.')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('commit', nargs='?', help="ccl_chromium_reader commit in Hindsight's fork")
    parser.add_argument('--snappy', help='ccl_simplesnappy commit (default: the one already bundled)')
    parser.add_argument('--check', action='store_true', help='compare the bundled copies with their recorded commits')
    args = parser.parse_args()

    if args.check:
        return check()
    if not args.commit:
        parser.error('give the ccl_chromium_reader commit to bundle, or --check')
    snappy = args.snappy
    if not snappy:
        snappy = recorded_commit('ccl_simplesnappy') if (LIB / 'ccl_simplesnappy').exists() else SNAPPY_COMMIT
    ccl_hash, snappy_hash = vendor(args.commit, snappy, LIB)
    print(f'Bundled ccl_chromium_reader {ccl_hash} and ccl_simplesnappy {snappy_hash} into {LIB}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
