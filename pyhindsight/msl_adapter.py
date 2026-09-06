"""Run mister-skinnylegs plugins against data Hindsight has already parsed.

mister-skinnylegs (https://github.com/cclgroupltd/mister-skinnylegs, MIT) is CCL's
plugin framework for website and webapp artifacts. A plugin is a function

    fn(profile: BrowserProfileProtocol, log_func, storage: ArtifactStorage) -> ArtifactResult

returning a list of dicts. Both projects sit on the same substrate: Hindsight already
depends on ``ccl_chromium_reader``, and ``BrowserProfileProtocol`` is what its
``ChromiumProfileFolder`` implements. So the plugins can run unmodified.

The obvious way to do that is to hand each plugin a fresh ``ChromiumProfileFolder``, but
that re-reads the profile Hindsight has just finished reading, and the plugins then see
none of Hindsight's work: no deleted-record recovery, no decryption, no artifact
filtering, no profile attribution. This module takes the other route and implements the
protocol *over* ``AnalysisSession.parsed_artifacts`` and ``parsed_storage``, so a plugin
reads Hindsight's rows.

Measured parity against a real ChromiumProfileFolder on ``bf4sa_2025_bob-1`` (28 MSL
artifacts, every one run both ways, comparing row counts *and* column sets):

    identical: 27   column-loss: 0   row-count-diff: 1   adapter-errors: 0

The single difference is Sessionstorage, 213 through the adapter against 540 direct,
where the adapter is the correct one: ``ccl_chromium_sessionstorage.iter_all_records``
yields orphan records without honouring ``include_deletions``, leaking 327 deleted,
null-valued records into the direct path.

See ``tests/msl_parity_check.py`` to re-measure, and the "Finish the mister-skinnylegs
plugin integration" entry in ``documentation/future_work.md`` for what remains.
"""

import datetime
import pathlib

from ccl_chromium_reader import ChromiumProfileFolder
from ccl_chromium_reader.ccl_chromium_history import PageTransition
from ccl_chromium_reader.common import is_keysearch_hit


def _naive_utc(value):
    """Drop tzinfo, normalising to UTC first.

    Hindsight converts every timestamp to the session timezone and keeps it aware. MSL
    assumes naive UTC throughout and compares against naive literals, so handing a
    plugin an aware datetime raises "can't compare offset-naive and offset-aware
    datetimes" the moment it sorts. Results come back naive; a caller that stores them
    on Hindsight rows has to re-attach tzinfo.
    """
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def _hit(search, value):
    """Apply one MSL KeySearch, treating a missing value as no match."""
    if search is None:
        return True
    return value is not None and is_keysearch_hit(search, value)


class RecordLocation:
    """Stands in for ccl's ArtifactLocation.

    Hindsight flattens a record's provenance into a single string as it parses, so the
    separate metadata and data locations ccl exposes cannot be recovered. Plugins print
    this rather than navigate it, so a single source string is enough for every current
    plugin, but it is a real loss of fidelity worth knowing about.
    """

    def __init__(self, source_file, offset=None):
        self.source_file = str(source_file) if source_file is not None else ''
        self.offset = offset

    @property
    def friendly_string(self):
        return self.source_file

    def __str__(self):
        return self.friendly_string


class CacheRecord:
    def __init__(self, item):
        # Hindsight keeps ccl's own key, metadata and body objects on the row, so these
        # need no translation at all.
        self.key = item.key
        self.metadata = item.metadata
        self.data = item.data
        # Both point at the same string: see RecordLocation.
        self.data_location = RecordLocation(item.locations)
        self.metadata_location = RecordLocation(item.locations)
        # Not retained by Hindsight. No current plugin reads it.
        self.was_decompressed = False


class HistoryRecord:
    def __init__(self, item):
        self.url = item.url
        self.title = item.title
        self.visit_time = _naive_utc(item.visit_time)
        self.rec_id = item.visit_id
        self.parent_visit_id = item.from_visit
        self.has_parent = bool(item.from_visit)
        # Hindsight keeps the raw History-DB integer, which reconstructs the structured
        # form losslessly. Plugins read .transition.core.name and .transition.qualifier.
        self.transition = (PageTransition.from_int(item.transition)
                           if item.transition is not None else None)
        self.record_location = RecordLocation(item.source_item or 'History')


class LocalStorageRecord:
    def __init__(self, item):
        self.storage_key = item.origin
        self.script_key = item.key
        self.value = item.value
        self.record_location = RecordLocation(item.source_path)


class SessionStorageRecord:
    def __init__(self, item):
        self.host = item.origin
        self.key = item.key
        self.value = item.value
        self.record_location = RecordLocation(item.source_path)


class IndexedDbKey:
    def __init__(self, value, raw_key):
        self.value = value
        self.raw_key = raw_key


class IndexedDbRecord:
    def __init__(self, item):
        self.key = IndexedDbKey(
            item.key, bytes.fromhex(item.key_raw) if item.key_raw else b'')
        # The deserialized object, not a rendering of it. Plugins subscript this
        # (the Reddit plugin walks rec.value["roomsData"]["join"]), which was impossible
        # while Hindsight stringified IndexedDB values at parse time.
        self.value = item.value_obj
        self.record_location = RecordLocation(item.source_path)


class DownloadRecord:
    def __init__(self, item):
        self.url = item.url
        self.tab_url = item.tab_url
        self.start_time = _naive_utc(item.start_time)
        self.end_time = _naive_utc(item.end_time)
        self.target_path = item.target_path
        self.file_size = item.total_bytes
        self.hash = item.hash
        # ccl always hands back an iterable and MSL joins this without guarding;
        # Hindsight stores None for a single-hop download.
        self.url_chain = item.url_chain or []
        self.record_location = RecordLocation(item.source_item or 'History')


class HindsightProfileAdapter(ChromiumProfileFolder):
    """Serves MSL's BrowserProfileProtocol from one profile's already-parsed rows.

    Subclasses ChromiumProfileFolder rather than merely satisfying the protocol
    structurally. Four MSL plugins gate their Chromium-specific fields on
    ``isinstance(profile, ChromiumProfileFolder)``, so a duck-typed profile silently
    drops columns instead of failing: History came back with the right row count and
    three fewer columns. The parent ``__init__`` is deliberately not called, because
    there is no profile folder to open; every method the protocol names is overridden
    below.

    One adapter serves one profile, matching MSL's model, so a multi-profile
    AnalysisSession needs one per profile path.
    """

    def __init__(self, session, profile_path):
        self._path = pathlib.Path(profile_path)
        artifacts = [a for a in session.parsed_artifacts
                     if getattr(a, 'profile', None) == profile_path]
        storage = [s for s in session.parsed_storage
                   if getattr(s, 'profile', None) == profile_path]

        # Only row_type 'cache' carries ccl's key/metadata/data objects. The Cache API
        # and service-worker cache parsers produce rows whose key is a plain string with
        # metadata and data of None, so they cannot serve iterate_cache; including them
        # raises AttributeError on key.url. ccl's own iterate_cache covers the HTTP cache
        # only, so excluding them costs no parity.
        self._cache = [a for a in artifacts if a.row_type == 'cache']
        self._history = [a for a in artifacts if a.row_type == 'url']
        self._downloads = [a for a in artifacts if a.row_type == 'download']
        self._local_storage = [s for s in storage if s.row_type == 'local storage']
        self._session_storage = [s for s in storage if s.row_type == 'session storage']
        self._indexeddb = [s for s in storage if s.row_type == 'indexeddb']

    # -- lifecycle -------------------------------------------------------------------

    def close(self):
        """Nothing is held open; the rows outlive the readers that produced them."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    @property
    def path(self):
        return self._path

    @property
    def browser_type(self):
        return 'Chromium'

    # -- protocol --------------------------------------------------------------------

    def iterate_cache(self, url=None, *, decompress=True, omit_cached_data=False, **kwargs):
        for item in self._cache:
            if not getattr(item, 'key', None) or not _hit(url, item.key.url):
                continue
            if not self._header_match(item, kwargs):
                continue
            yield CacheRecord(item)

    @staticmethod
    def _header_match(item, header_filters):
        """Apply MSL's header keyword filters (content_encoding -> content-encoding)."""
        for field, wanted in header_filters.items():
            found = (item.metadata.get_attribute(field.replace('_', '-'))
                     if item.metadata else None)
            if isinstance(wanted, bool):
                if bool(found) != wanted:
                    return False
            elif not found or not any(_hit(wanted, value) for value in found):
                return False
        return True

    def iterate_history_records(self, url=None, *, earliest=None, latest=None):
        for item in self._history:
            if not _hit(url, item.url):
                continue
            if earliest and item.visit_time and item.visit_time < earliest:
                continue
            if latest and item.visit_time and item.visit_time > latest:
                continue
            yield HistoryRecord(item)

    def iter_downloads(self, *, download_url=None, tab_url=None):
        for item in self._downloads:
            if _hit(download_url, item.url) and _hit(tab_url, item.tab_url):
                yield DownloadRecord(item)

    def iter_local_storage(self, storage_key=None, script_key=None, *,
                           include_deletions=False, raise_on_no_result=False):
        for item in self._local_storage:
            # Hindsight recovers deleted records that ccl's default iteration omits
            # (4,066 local storage rows against ccl's 1,390 on one profile), so mapping
            # state onto include_deletions is what keeps the two comparable, and lets a
            # plugin opt into the recovery without knowing it exists.
            if not include_deletions and item.state != 'Live':
                continue
            if _hit(storage_key, item.origin) and _hit(script_key, item.key):
                yield LocalStorageRecord(item)

    def iter_session_storage(self, host=None, key=None, *,
                             include_deletions=False, raise_on_no_result=False):
        for item in self._session_storage:
            if not include_deletions and item.state != 'Live':
                continue
            if _hit(host, item.origin) and _hit(key, item.key):
                yield SessionStorageRecord(item)

    def iter_indexeddb_records(self, host_id=None, database_name=None,
                               object_store_name=None, **kwargs):
        for item in self._indexeddb:
            if (_hit(host_id, item.origin)
                    and _hit(database_name, item.database)
                    and _hit(object_store_name, item.object_store)):
                yield IndexedDbRecord(item)

    def iter_local_storage_hosts(self):
        yield from sorted({i.origin for i in self._local_storage if i.origin})

    def iter_session_storage_hosts(self):
        yield from sorted({i.origin for i in self._session_storage if i.origin})

    def iter_indexeddb_hosts(self):
        yield from sorted({i.origin for i in self._indexeddb if i.origin})

    # -- unsupported ------------------------------------------------------------------
    # These hand out live reader objects. Hindsight has already closed its readers by the
    # time plugins run, and no current plugin calls them. Raising names the reason rather
    # than returning something that fails further away.

    def get_indexeddb(self, host):
        raise NotImplementedError(
            'Hindsight closes its IndexedDB readers after parsing; use '
            'iter_indexeddb_records, which serves the parsed rows.')

    @property
    def local_storage(self):
        raise NotImplementedError('Use iter_local_storage.')

    @property
    def session_storage(self):
        raise NotImplementedError('Use iter_session_storage.')

    @property
    def cache(self):
        raise NotImplementedError('Use iterate_cache.')

    @property
    def history(self):
        raise NotImplementedError('Use iterate_history_records.')
