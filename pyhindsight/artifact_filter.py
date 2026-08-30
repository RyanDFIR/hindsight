"""Selection of which artifacts Hindsight parses.

Hindsight normally parses every artifact it finds in a profile. Some
investigations only want a slice of that: just history and downloads for a
quick triage, or everything except the cache when the cache is enormous and
the question at hand doesn't involve it. This module defines the artifact
names a user selects with ``--only`` / ``--skip`` and the filter that
``ProcessingDisplay.run()`` consults before calling each parser.

The names are deliberately browser-neutral. ``history`` selects Chrome's
``History`` URL records and Firefox's ``places.sqlite`` URL records, so the
same command works against either profile type without the user needing to
know which file holds what. Group names (``user-activity``, ``caches``, ...)
are accepted anywhere an artifact name is, and expand to their members.

Anything the filter excludes is recorded rather than silently dropped: a
report that omits the cache must be distinguishable from a profile that had
no cache, so skipped names are surfaced in the live display, the log, and on
the AnalysisSession.
"""

import collections
import difflib
import logging
import re

log = logging.getLogger(__name__)


class UnknownArtifactError(ValueError):
    """Raised when a user-supplied artifact selector matches nothing in the catalog."""


ArtifactSpec = collections.namedtuple('ArtifactSpec', ['name', 'group', 'description', 'aliases'])

# Group names, in the order they're displayed by --list-artifacts. These mirror the
# group headings the browsers already use in their processing display, so what a user
# sees on screen during a run is what they can name on the command line.
USER_ACTIVITY = 'user-activity'
WEBSITE_STORAGE = 'website-storage'
BROWSER_EXTENSIONS = 'browser-extensions'
CONFIGURATION = 'configuration'

GROUP_ORDER = [USER_ACTIVITY, WEBSITE_STORAGE, BROWSER_EXTENSIONS, CONFIGURATION]

# The catalog of selectable artifacts. Every driver.run() call in a browser's
# process() passes one of these names as `artifact=`; a call with no name is always
# parsed (see ArtifactFilter.should_parse), so forgetting to tag a new parser makes it
# unfilterable rather than invisible.
CATALOG = [
    # -- User Activity --
    ArtifactSpec('history', USER_ACTIVITY,
                 'Visited URLs (Chrome History, Firefox places.sqlite)',
                 ('urls', 'url', 'visits', 'visit')),
    ArtifactSpec('downloads', USER_ACTIVITY,
                 'Downloaded files, including Chrome shared_proto_db downloads',
                 ('download',)),
    ArtifactSpec('archived-history', USER_ACTIVITY,
                 'Chrome Archived History URL records',
                 ()),
    ArtifactSpec('media-history', USER_ACTIVITY,
                 'Chrome Media History playback records',
                 ('media',)),
    ArtifactSpec('autofill', USER_ACTIVITY,
                 'Form values typed into pages (Chrome Web Data, Firefox formhistory)',
                 ('form-history', 'forms')),
    ArtifactSpec('logins', USER_ACTIVITY,
                 'Saved credentials metadata (Chrome Login Data, Firefox logins.json)',
                 ('login', 'login-data', 'passwords')),
    ArtifactSpec('bookmarks', USER_ACTIVITY,
                 'Bookmarks and bookmark folders',
                 ('bookmark',)),
    ArtifactSpec('bookmark-backups', USER_ACTIVITY,
                 'Firefox bookmarkbackups snapshots',
                 ()),
    ArtifactSpec('sessions', USER_ACTIVITY,
                 'Open/restored tabs (Chrome SNSS, Firefox sessionstore)',
                 ('session', 'tabs')),
    ArtifactSpec('favicons', USER_ACTIVITY,
                 'Firefox favicon-derived URL records',
                 ('favicon',)),

    # -- Website Storage --
    ArtifactSpec('cookies', WEBSITE_STORAGE,
                 'Cookies (excludes extension cookies; see extension-cookies)',
                 ('cookie',)),
    ArtifactSpec('cache', WEBSITE_STORAGE,
                 'Main HTTP cache; usually the slowest artifact to parse',
                 ()),
    ArtifactSpec('gpu-cache', WEBSITE_STORAGE,
                 'Chrome GPUCache entries',
                 ('gpucache',)),
    ArtifactSpec('media-cache', WEBSITE_STORAGE,
                 'Chrome Media Cache entries',
                 ()),
    ArtifactSpec('dawn-cache', WEBSITE_STORAGE,
                 'Chrome DawnCache / DawnWebGPUCache / DawnGraphiteCache entries',
                 ('dawncache',)),
    ArtifactSpec('cache-api', WEBSITE_STORAGE,
                 'Firefox Cache API (service worker managed) entries',
                 ()),
    ArtifactSpec('local-storage', WEBSITE_STORAGE,
                 'localStorage key/value pairs',
                 ('localstorage',)),
    ArtifactSpec('session-storage', WEBSITE_STORAGE,
                 'sessionStorage key/value pairs',
                 ('sessionstorage',)),
    ArtifactSpec('indexeddb', WEBSITE_STORAGE,
                 'IndexedDB records',
                 ('idb', 'indexed-db')),
    ArtifactSpec('file-system', WEBSITE_STORAGE,
                 'File System API entries',
                 ('filesystem',)),
    ArtifactSpec('notifications', WEBSITE_STORAGE,
                 'Chrome Platform Notifications',
                 ('platform-notifications',)),
    ArtifactSpec('service-workers', WEBSITE_STORAGE,
                 'Service Worker registrations',
                 ('service-worker', 'sw')),

    # -- Browser Extensions --
    ArtifactSpec('extensions', BROWSER_EXTENSIONS,
                 'Installed extensions and their manifests',
                 ('extension',)),
    ArtifactSpec('extension-settings', BROWSER_EXTENSIONS,
                 'Extension settings from Chrome Secure Preferences',
                 ('secure-preferences',)),
    ArtifactSpec('extension-cookies', BROWSER_EXTENSIONS,
                 'Chrome Extension Cookies database',
                 ()),
    ArtifactSpec('extension-storage', BROWSER_EXTENSIONS,
                 'Extension State/Rules/Scripts and chrome.storage.* LevelDBs',
                 ('extension-state', 'extension-rules', 'extension-scripts')),
    ArtifactSpec('dnr-rules', BROWSER_EXTENSIONS,
                 'Declarative Net Request extension rules',
                 ('dnr', 'dnr-extension-rules')),

    # -- Configuration & Supporting Data --
    ArtifactSpec('preferences', CONFIGURATION,
                 'Profile preferences (Chrome Preferences, Firefox prefs.js)',
                 ('prefs', 'preference')),
    ArtifactSpec('site-characteristics', CONFIGURATION,
                 'Chrome Site Characteristics Database',
                 ()),
    ArtifactSpec('sync-data', CONFIGURATION,
                 'Chrome Sync Data records',
                 ('sync',)),
    ArtifactSpec('hsts', CONFIGURATION,
                 'HSTS / TransportSecurity records',
                 ('transport-security',)),
    ArtifactSpec('dips', CONFIGURATION,
                 'Chrome DIPS (Bounce Tracking Mitigation) records and popups',
                 ()),
    ArtifactSpec('permissions', CONFIGURATION,
                 'Firefox per-site permissions',
                 ('permission',)),
    ArtifactSpec('bounce-tracking', CONFIGURATION,
                 'Firefox bounce-tracking protection records',
                 ()),
    ArtifactSpec('content-blocking', CONFIGURATION,
                 'Firefox content-blocking (protections.sqlite) events',
                 ()),
]

ARTIFACT_NAMES = [spec.name for spec in CATALOG]
_SPECS_BY_NAME = {spec.name: spec for spec in CATALOG}

# Extra groups that don't correspond to a display heading but that users reach for.
# 'caches' exists because "skip the caches" is a single intent even though the caches
# are separate artifacts; naming only 'cache' skips just the main HTTP cache.
_EXTRA_GROUPS = {
    'caches': ('cache', 'gpu-cache', 'media-cache', 'dawn-cache', 'cache-api'),
    'all': tuple(ARTIFACT_NAMES),
}


def _build_group_members():
    members = {group: [] for group in GROUP_ORDER}
    for spec in CATALOG:
        members[spec.group].append(spec.name)
    for group, names in _EXTRA_GROUPS.items():
        members[group] = list(names)
    return members


GROUP_MEMBERS = _build_group_members()


def _normalize(token):
    """Fold a user-supplied token to catalog form.

    Users type ``Local Storage``, ``local_storage``, and ``local-storage``
    interchangeably, and copy names straight out of the on-screen display, so
    case and space/underscore/hyphen differences are all treated as equal.
    """
    return re.sub(r'[\s_]+', '-', token.strip().lower())


def _build_selector_index():
    """Map every accepted spelling to the canonical names it selects."""
    index = {}
    for spec in CATALOG:
        index[spec.name] = (spec.name,)
        for alias in spec.aliases:
            index[_normalize(alias)] = (spec.name,)
    for group, names in GROUP_MEMBERS.items():
        index[group] = tuple(names)
    return index


_SELECTOR_INDEX = _build_selector_index()


def resolve_selector(token):
    """Resolve one user-supplied token to the set of canonical artifact names it selects.

    Raises UnknownArtifactError (with close-match suggestions) rather than
    silently ignoring a token: a typo in ``--only`` would otherwise produce an
    empty report that looks exactly like a profile with no artifacts in it.
    """
    normalized = _normalize(token)
    if not normalized:
        raise UnknownArtifactError('Empty artifact name.')

    matched = _SELECTOR_INDEX.get(normalized)
    if matched:
        return set(matched)

    suggestions = difflib.get_close_matches(normalized, sorted(_SELECTOR_INDEX), n=3, cutoff=0.6)
    message = f"Unknown artifact '{token}'."
    if suggestions:
        message += ' Did you mean: ' + ', '.join(suggestions) + '?'
    message += ' Run with --list-artifacts to see every name.'
    raise UnknownArtifactError(message)


def parse_selectors(tokens):
    """Resolve an iterable of comma-separated selector strings to canonical names.

    Comma is the only separator. Whitespace can't also separate, because names
    are accepted in the spaced form users read off the screen ("Local Storage",
    "media history"); splitting on spaces would silently turn one such name into
    two unrelated ones.
    """
    resolved = set()
    for token in tokens or []:
        for piece in token.split(','):
            if piece.strip():
                resolved |= resolve_selector(piece)
    return resolved


class ArtifactFilter:
    """Decides whether a given artifact should be parsed.

    ``only`` restricts parsing to the named artifacts; ``skip`` removes names from
    whatever would otherwise be parsed. The two compose, so
    ``--only browser-extensions --skip extension-cookies`` is meaningful.
    """

    def __init__(self, only=None, skip=None):
        self.only = set(only) if only else None
        self.skip = set(skip) if skip else set()
        # Populated as the run proceeds, so output can report what was actually
        # present-but-excluded rather than what was merely named on the command line.
        self.skipped_artifacts = set()

    @classmethod
    def from_selectors(cls, only_tokens=None, skip_tokens=None):
        """Build a filter from raw CLI strings, validating every token."""
        only = None
        if only_tokens:
            only = parse_selectors(only_tokens)
            if not only:
                # e.g. `--only ,` -- tokens were given but named nothing. Treating that
                # as "no filter" would parse everything under a flag that asked for a
                # subset, which is the opposite of what was typed.
                raise UnknownArtifactError(
                    '--only was given but names no artifacts. '
                    'Run with --list-artifacts to see every name.')
        skip = parse_selectors(skip_tokens) if skip_tokens else set()
        return cls(only=only, skip=skip)

    @property
    def is_active(self):
        return self.only is not None or bool(self.skip)

    def should_parse(self, artifact):
        """Return True if `artifact` should be parsed.

        An untagged call (``artifact`` is None) always parses. Failing open matters:
        a parser that hasn't been given a catalog name should show up in the report,
        not vanish because nobody could name it.
        """
        if artifact is None:
            return True
        if artifact in self.skip:
            return False
        if self.only is not None and artifact not in self.only:
            return False
        return True

    def note_skipped(self, artifact):
        """Record that `artifact` was present in the profile but excluded by this filter."""
        if artifact:
            self.skipped_artifacts.add(artifact)

    def describe(self):
        """One-line summary of the active selection, for the log and the run banner."""
        parts = []
        if self.only is not None:
            parts.append('only: ' + (', '.join(sorted(self.only)) or '<none>'))
        if self.skip:
            parts.append('skip: ' + ', '.join(sorted(self.skip)))
        return '; '.join(parts) if parts else 'all artifacts'


def format_catalog():
    """Render the catalog for --list-artifacts."""
    lines = ['Artifact names accepted by --only and --skip:', '']
    for group in GROUP_ORDER:
        lines.append(f'  {group}')
        for name in GROUP_MEMBERS[group]:
            spec = _SPECS_BY_NAME[name]
            lines.append(f'    {spec.name:<22}{spec.description}')
            if spec.aliases:
                lines.append(f'    {"":<22}  aliases: {", ".join(spec.aliases)}')
        lines.append('')
    lines.append('  Group names select every artifact under them, and may be used')
    lines.append('  anywhere an artifact name can: ' + ', '.join(GROUP_ORDER))
    lines.append('  Additional groups: ' + ', '.join(sorted(_EXTRA_GROUPS)))
    lines.append('')
    lines.append('  Names are case-insensitive; spaces, underscores, and hyphens are equivalent.')
    lines.append('  Artifacts not present in a profile are simply absent, filtered or not.')
    return '\n'.join(lines)
