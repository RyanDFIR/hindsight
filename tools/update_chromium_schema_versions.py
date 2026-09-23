"""Refresh pyhindsight/browsers/chromium_schema_versions.py from Chromium's release tags.

Chrome records each SQLite database's schema version in that database's meta table
(the 'version' row). Hindsight maps the number back to the Chrome versions that write
it, which pins down the Chrome version that last opened the profile. This script builds
that map by reading each database's schema version constant from the Chromium source as
of each Chrome version's last release.

    python tools/update_chromium_schema_versions.py          # read new releases, rewrite the data
    python tools/update_chromium_schema_versions.py --check  # exit 1 if the data is out of date
    python tools/update_chromium_schema_versions.py --full   # re-read every release

Tags never change, so a refresh only reads Chrome versions that are new, or that have a
newer release, since the data was last written. A full run makes about a thousand
requests and takes a few minutes.

When Chromium moves a source file, this script can no longer find that database's
version in the newest releases. It says which database and exits 1. Find the file's new
path, add it to DATABASES below, and rerun; releases that are missing a database found
in older ones are always read again.

The source is GitHub's mirror of chromium/src. chromium.googlesource.com has the same
tags, but it started refusing requests (HTTP 429) partway through a full run.

Needs git (for listing tags) and network access.
"""
import argparse
import ast
import concurrent.futures
import datetime
import email.utils
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPOSITORY = 'https://github.com/chromium/chromium'
RAW_FILES = 'https://raw.githubusercontent.com/chromium/chromium'
DATA_MODULE = pathlib.Path(__file__).resolve().parent.parent / 'pyhindsight' / 'browsers' / 'chromium_schema_versions.py'

# Where each database's schema version constant has lived, newest location first. At
# each release the first of these that exists and defines the constant is used. Keys
# are the database file names, as Hindsight's version detection refers to them.
DATABASES = {
    'History': [
        'components/history/core/browser/history_database.cc',
        'chrome/browser/history/history_database.cc',
    ],
    'Web Data': [
        'components/webdata/common/web_database.h',
        'components/webdata/common/web_database.cc',
        'chrome/browser/webdata/web_database.cc',
    ],
    'Cookies': [
        'net/extras/sqlite/sqlite_persistent_cookie_store.cc',
        'content/browser/net/sqlite_persistent_cookie_store.cc',
        'chrome/browser/net/sqlite_persistent_cookie_store.cc',
    ],
    'Login Data': [
        'components/password_manager/core/browser/password_store/login_database.cc',
        'components/password_manager/core/browser/login_database.cc',
        'chrome/browser/password_manager/login_database.cc',
    ],
    # Chromium renamed DIPS to BTM (bounce tracking mitigations); the file is still "DIPS".
    'DIPS': [
        'content/browser/btm/btm_database.h',
        'content/browser/dips/dips_database.h',
        'chrome/browser/dips/dips_database.h',
        'chrome/browser/dips/dips_database.cc',
    ],
}

# kCurrentVersionNumber in most files; kLatestSchemaVersion in the DIPS/BTM database.
# kCompatibleVersionNumber and kMinCompatibleSchemaVersion are the oldest schema a
# release can read, not the one it writes, and don't match.
VERSION_RE = re.compile(r'\bk(?:Current|Latest)(?:Schema)?Version(?:Number)?\s*=\s*(\d+)\s*;')
RELEASE_TAG_RE = re.compile(r'\d+\.\d+\.\d+\.\d+')

RETRY_STATUS = (429, 500, 502, 503, 504)
ATTEMPTS = 8


def list_release_tags():
    """Every Chrome build tag, as (major, minor, build, patch) tuples."""
    out = subprocess.run(['git', 'ls-remote', '--tags', '--refs', REPOSITORY],
                         capture_output=True, text=True, check=True).stdout
    tags = []
    for line in out.splitlines():
        name = line.rsplit('refs/tags/', 1)[-1]
        if RELEASE_TAG_RE.fullmatch(name):
            tags.append(tuple(int(part) for part in name.split('.')))
    return tags


def pick_release_tags(tags):
    """{Chrome version: the tag of its last release}.

    A release branch is the one build number that gets patch releases (M.0.B.1,
    M.0.B.2, ...), so the tag with the highest patch number is the last release. Sorting
    on the patch number first matters for old releases, where builds numbered for the
    next release were still tagged with the previous major version (5.0.396.0 came after
    the last Chrome 5 release, 5.0.375.127). A version with no release branch yet has
    only canary tags, and gets its newest build.
    """
    def release_order(tag):
        major, minor, build, patch = tag
        return patch, build, minor

    last = {}
    for tag in tags:
        if tag[0] not in last or release_order(tag) > release_order(last[tag[0]]):
            last[tag[0]] = tag
    return {major: '.'.join(map(str, tag)) for major, tag in last.items()}


def schema_version_in(source):
    """The schema version constant defined in a source file, or None if there isn't exactly one."""
    # Drop // comments, so an old value quoted in a comment can't be mistaken for the constant.
    code = re.sub(r'//.*', '', source)
    values = set(VERSION_RE.findall(code))
    if len(values) != 1:
        return None
    return int(values.pop())


def retry_delay(error, attempt):
    """Seconds to wait before retrying: the server's Retry-After if it sent one."""
    retry_after = error.headers.get('Retry-After') if isinstance(error, urllib.error.HTTPError) else None
    if retry_after:
        if retry_after.isdigit():
            return int(retry_after)
        when = email.utils.parsedate_to_datetime(retry_after)
        if when:
            return max(0, (when - datetime.datetime.now(when.tzinfo)).total_seconds())
    return min(2 ** attempt, 60)


def fetch(tag, path):
    """A file from chromium/src as of a tag, or None if it doesn't exist there."""
    url = f'{RAW_FILES}/{tag}/{path}'
    for attempt in range(ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                return response.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code not in RETRY_STATUS or attempt == ATTEMPTS - 1:
                raise
            time.sleep(retry_delay(e, attempt))
        except urllib.error.URLError as e:
            if attempt == ATTEMPTS - 1:
                raise
            time.sleep(retry_delay(e, attempt))


def read_schema_version(tag, paths, likely_path):
    """(schema version, path it came from) at a tag, or (None, None) if no candidate path has it.

    'likely_path' (where the previous release read had it) is tried first, since files rarely move.
    """
    if likely_path:
        paths = [likely_path] + [p for p in paths if p != likely_path]
    for path in paths:
        source = fetch(tag, path)
        if source is None:
            continue
        version = schema_version_in(source)
        if version is not None:
            return version, path
    return None, None


def load_data(path=DATA_MODULE):
    """The data module's dicts, read without importing it."""
    data = {'RELEASE_TAGS': {}, 'SCHEMA_VERSIONS': {}, 'SOURCE_PATHS': {}}
    if not path.exists():
        return data
    for node in ast.parse(path.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                isinstance(node.targets[0], ast.Name) and node.targets[0].id in data:
            data[node.targets[0].id] = ast.literal_eval(node.value)
    return data


def known_results(data):
    """{(tag, database): schema version, or None if it isn't there} for what the data settles.

    A database missing from a release older than the oldest one it was found in didn't
    exist yet, and tags never change, so that absence is kept. A database missing from a
    release newer than one it was found in is left out, so it gets read again: that is
    the gap a moved source file leaves, and the path added for it may now fill it.
    """
    oldest = {}
    for version, row in data['SCHEMA_VERSIONS'].items():
        for database in row:
            oldest[database] = min(oldest.get(database, version), version)
    known = {}
    for version, tag in data['RELEASE_TAGS'].items():
        row = data['SCHEMA_VERSIONS'].get(version, {})
        for database in DATABASES:
            if database in row:
                known[(tag, database)] = row[database]
            elif database not in oldest or version < oldest[database]:
                known[(tag, database)] = None
    return known


def collect(release_tags, known, progress):
    """Read every database's schema version at each release tag not already known.

    Each database is read from the newest release back, and once it has been found, the
    first release without it is taken as where it began: older releases aren't read.

    Returns (schema_versions, source_paths, unresolved). unresolved maps a database to
    the newest Chrome versions it's missing from even though older ones have it, or to
    every Chrome version if it wasn't found anywhere.
    """
    def one_database(database):
        paths = DATABASES[database]
        found, used, missing = {}, {}, []
        likely_path = None
        for version in sorted(release_tags, reverse=True):
            tag = release_tags[version]
            if (tag, database) in known:
                value = known[(tag, database)]
            else:
                value, path = read_schema_version(tag, paths, likely_path)
                progress()
                if path:
                    likely_path = path
                    first, last = used.get(path, (version, version))
                    used[path] = (min(first, version), max(last, version))
            if value is None:
                if found:
                    break
                missing.append(version)
            else:
                found[version] = value
        return database, found, used, (missing if found else sorted(release_tags))

    schema_versions, source_paths, unresolved = {}, {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DATABASES)) as pool:
        for database, found, used, missing in pool.map(one_database, DATABASES):
            for version, value in found.items():
                schema_versions.setdefault(version, {})[database] = value
            source_paths[database] = used
            if missing:
                unresolved[database] = sorted(missing)
    return schema_versions, source_paths, unresolved


def merge_source_paths(old, new):
    """Widen each path's recorded span of Chrome versions with this run's findings."""
    merged = {database: dict(paths) for database, paths in old.items()}
    for database, paths in new.items():
        for path, (first, last) in paths.items():
            if path in merged.setdefault(database, {}):
                old_first, old_last = merged[database][path]
                first, last = min(first, old_first), max(last, old_last)
            merged[database][path] = (first, last)
    return merged


def render(release_tags, schema_versions, source_paths):
    """The data module's source."""
    lines = [
        '# Generated by tools/update_chromium_schema_versions.py. Do not edit by hand;',
        '# rerun the script to refresh it.',
        '"""The schema version each Chrome release writes to its databases\' meta tables.',
        '',
        'Read from the Chromium source at each Chrome version\'s last release.',
        'chrome_versions_for_schema in chrome.py maps a database\'s meta.version back to',
        'the Chrome versions listed here.',
        '"""',
        '',
        f'GENERATED = {datetime.date.today().isoformat()!r}',
        '',
        '# {Chrome version: the tag its schema versions were read from}',
        'RELEASE_TAGS = {',
    ]
    lines += [f'    {version}: {tag!r},' for version, tag in sorted(release_tags.items())]
    lines += [
        '}',
        '',
        '# {Chrome version: {database: schema version}}. A database is absent from Chrome',
        '# versions that don\'t have it.',
        'SCHEMA_VERSIONS = {',
    ]
    for version in sorted(schema_versions):
        row = schema_versions[version]
        cells = ', '.join(f'{database!r}: {row[database]!r}' for database in DATABASES if database in row)
        lines.append(f'    {version}: {{{cells}}},')
    lines += [
        '}',
        '',
        '# {database: {source path: (oldest, newest Chrome version its constant was read from)}}',
        'SOURCE_PATHS = {',
    ]
    for database in DATABASES:
        lines.append(f'    {database!r}: {{')
        for path, span in sorted(source_paths.get(database, {}).items(), key=lambda item: item[1]):
            lines.append(f'        {path!r}: {span!r},')
        lines.append('    },')
    lines += ['}', '']
    return '\n'.join(lines)


def describe_changes(old, release_tags, schema_versions):
    """Lines saying which Chrome versions were added or changed."""
    changes = []
    for version in sorted(release_tags):
        before = old['SCHEMA_VERSIONS'].get(version, {})
        after = schema_versions.get(version, {})
        if version not in old['RELEASE_TAGS']:
            changes.append(f'  Chrome {version} ({release_tags[version]}): added {after}')
        elif before != after:
            changes.append(f'  Chrome {version} ({release_tags[version]}): {before} -> {after}')
        elif old['RELEASE_TAGS'][version] != release_tags[version]:
            changes.append(f'  Chrome {version}: newer release {release_tags[version]}, schema versions unchanged')
    return changes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--check', action='store_true',
                        help="don't write anything; exit 1 if the data is out of date")
    parser.add_argument('--full', action='store_true',
                        help='ignore the existing data and read every release again')
    args = parser.parse_args(argv)

    old = load_data()
    release_tags = pick_release_tags(list_release_tags())
    known = {} if args.full else known_results(old)

    to_read = sum(1 for tag in release_tags.values() for database in DATABASES if (tag, database) not in known)
    print(f'{len(release_tags)} Chrome versions ({min(release_tags)}-{max(release_tags)}); '
          f'up to {to_read} release/database pairs to read', flush=True)
    done = [0]

    def progress():
        done[0] += 1
        if done[0] % 100 == 0:
            print(f'  {done[0]} read', flush=True)

    schema_versions, source_paths, unresolved = collect(release_tags, known, progress)
    if not args.full:
        source_paths = merge_source_paths(old['SOURCE_PATHS'], source_paths)

    changes = describe_changes(old, release_tags, schema_versions)
    print('\n'.join(changes) if changes else 'No changes.')

    status = 0
    for database, versions in unresolved.items():
        status = 1
        if len(versions) == len(release_tags):
            print(f'{database}: no schema version found in any release. Check its paths in DATABASES.')
        else:
            print(f'{database}: no schema version found for Chrome {", ".join(map(str, versions))}, though '
                  f'older releases have one. Its source file has probably moved; find the new path and '
                  f'add it to DATABASES in {pathlib.Path(__file__).name}.')

    if args.check:
        return 1 if changes else status
    if changes or args.full:
        DATA_MODULE.write_text(render(release_tags, schema_versions, source_paths), encoding='utf-8')
        print(f'Wrote {DATA_MODULE}')
    return status


if __name__ == '__main__':
    sys.exit(main())
