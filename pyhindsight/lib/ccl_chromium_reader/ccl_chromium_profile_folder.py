"""
Copyright 2024, CCL Forensics
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import dataclasses
import datetime
import typing
import pathlib
import collections.abc as col_abc

import gzip
import zlib
import brotli
import zstd

from . import ccl_chromium_localstorage
from . import ccl_chromium_sessionstorage
from . import ccl_chromium_indexeddb
from . import ccl_chromium_history
from . import ccl_chromium_cache
from . import ccl_shared_proto_db_downloads

from .common import KeySearch, is_keysearch_hit

__version__ = "0.8.0"
__description__ = "Module to consolidate and simplify access to data stores in the chrom(e|ium) profile folder"
__contact__ = "Alex Caithness"

# TODO: code currently assumes that lazy-loaded stores are present - they might not be, need some kind of guard object?
# TODO: paths are currently based around an assumption of a desktop layout. Mobile (and MacOS) will differ (e.g., the
#  cache location).

SESSION_STORAGE_FOLDER_PATH = pathlib.Path("Session Storage")
LOCAL_STORAGE_FOLDER_PATH = pathlib.Path("Local Storage", "leveldb")
INDEXEDDB_FOLDER_PATH = pathlib.Path("IndexedDB")
HISTORY_DB_PATH = pathlib.Path("History")
CACHE_PATH = pathlib.Path("Cache", "Cache_Data")
SHARED_PROTO_DB_FOLDER_PATH = pathlib.Path("shared_proto_db")


@dataclasses.dataclass(frozen=True, repr=False)
class CacheResult:
    key: ccl_chromium_cache.CacheKey = dataclasses.field(repr=True)
    metadata: ccl_chromium_cache.CachedMetadata
    data: bytes
    metadata_location: ccl_chromium_cache.CacheFileLocation
    data_location: ccl_chromium_cache.CacheFileLocation
    was_decompressed: bool
    duplicate_key_index: int


class ChromiumProfileFolder:
    """
    A class representing a Chrom(e|ium) profile folder with programmatic access to various different data stores.
    Where appropriate, resources are loaded on demand.
    """

    def __init__(
            self, path: pathlib.Path, *, cache_folder: typing.Optional[pathlib.Path]=None, missing_data_ok: bool=False):
        """
        Constructor

        :param path: Path to the profile folder (usually named Default, Profile 1, Profile 2, etc.)
        :param cache_folder: optionally a path to a cache folder, for platforms (such as Android) which
                             place the cache data outside the profile folder.
        :param missing_data_ok: if True, if a data store cannot be located (e.g., the History database is not present)
                                then trying to access that data yields no results. If False, an exception will be
                                raised.
        """
        if not path.is_dir():
            raise NotADirectoryError(f"Could not find the folder: {path}")

        self._path = path
        self._missing_data_ok = missing_data_ok

        # Cache
        self._cache: typing.Optional[ccl_chromium_cache.ChromiumCache] = None
        self._external_cache_folder = cache_folder

        if not self.cache_present and not self._missing_data_ok:
            raise NotADirectoryError(f"Could not find the cache folder:")

        # Data stores are populated lazily where appropriate
        # Webstorage
        self._local_storage: typing.Optional[ccl_chromium_localstorage.LocalStoreDb] = None
        self._session_storage: typing.Optional[ccl_chromium_sessionstorage.SessionStoreDb] = None
        if not self.localstorage_present and not self._missing_data_ok:
            raise NotADirectoryError(f"Could not find the localstorage folder")
        if not self.sessionstorage_present and not self._missing_data_ok:
            raise NotADirectoryError(f"Could not find the localstorage folder")

        # IndexedDb
        # Dictionary which when first populated will initially contain the domains as keys with None as the value for
        #  each. This will be initially populated on demand.
        self._indexeddb_databases: typing.Optional[dict[str, typing.Optional[ccl_chromium_indexeddb.WrappedIndexDB]]] = None
        if not self._missing_data_ok and not self.indexeddb_present:
            raise NotADirectoryError(f"Could not find the indexeddb folder")

        self._lazy_populate_indexeddb_list()

        # History
        self._history: typing.Optional[ccl_chromium_history.HistoryDatabase] = None
        if not self._missing_data_ok and not self.history_present:
            raise FileNotFoundError("could not find the history database")

    def close(self):
        """
        Closes any resources currently open in this profile folder.
        """
        if self._local_storage is not None:
            self._local_storage.close()
        if self._session_storage is not None:
            self._session_storage.close()
        for idb in (self._indexeddb_databases or {}).values():
            if idb is not None:
                idb.close()

    @property
    def localstorage_present(self) -> bool:
        return (self._path / LOCAL_STORAGE_FOLDER_PATH).is_dir()

    def _lazy_load_localstorage(self):
        if not self.localstorage_present and self._missing_data_ok:
            return
        if self._local_storage is None:
            self._local_storage = ccl_chromium_localstorage.LocalStoreDb(self._path / LOCAL_STORAGE_FOLDER_PATH)

    @property
    def sessionstorage_present(self) -> bool:
        return (self._path / SESSION_STORAGE_FOLDER_PATH).is_dir()

    def _lazy_load_sessionstorage(self):
        if not self.sessionstorage_present and self._missing_data_ok:
            return
        if self._session_storage is None:
            self._session_storage = ccl_chromium_sessionstorage.SessionStoreDb(self._path / SESSION_STORAGE_FOLDER_PATH)

    @property
    def indexeddb_present(self) -> bool:
        return (self._path / INDEXEDDB_FOLDER_PATH).is_dir()

    def _lazy_populate_indexeddb_list(self):
        if not self.indexeddb_present and self._missing_data_ok:
            return
        if self._indexeddb_databases is None:
            self._indexeddb_databases = {}
            for ldb_folder in (self._path / INDEXEDDB_FOLDER_PATH).glob("*.indexeddb.leveldb"):
                if ldb_folder.is_dir():
                    idb_id = ldb_folder.name[0:-18]
                    self._indexeddb_databases[idb_id] = None

    def _lazy_load_indexeddb(self, host: str):
        if not self.indexeddb_present and self._missing_data_ok:
            return

        self._lazy_populate_indexeddb_list()
        if host not in self._indexeddb_databases:
            raise KeyError(host)

        if self._indexeddb_databases[host] is None:
            ldb_path = self._path / INDEXEDDB_FOLDER_PATH / (host + ".indexeddb.leveldb")
            blob_path = self._path / INDEXEDDB_FOLDER_PATH / (host + ".indexeddb.blob")
            blob_path = blob_path if blob_path.exists() else None
            self._indexeddb_databases[host] = ccl_chromium_indexeddb.WrappedIndexDB(ldb_path, blob_path)

    @property
    def history_present(self) -> bool:
        return (self._path / HISTORY_DB_PATH).is_file()

    def _lazy_load_history(self):
        if not self.history_present and self._missing_data_ok:
            return
        if self._history is None:
            self._history = ccl_chromium_history.HistoryDatabase(self._path / HISTORY_DB_PATH)

    @property
    def cache_present(self):
        return ((self._external_cache_folder is not None and self._external_cache_folder.is_dir())
                or (self._path / CACHE_PATH).is_dir())

    def _lazy_load_cache(self):
        if not self.cache_present and self._missing_data_ok:
            return
        if self._cache is None:
            if self._external_cache_folder:
                cache_path = self._external_cache_folder
            else:
                cache_path = self._path / CACHE_PATH
            cache_class = ccl_chromium_cache.guess_cache_class(cache_path)
            if cache_class is None:
                raise ValueError(f"Data under {cache_path} could not be identified as a known cache type")
            self._cache = cache_class(cache_path)

    def iter_local_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates the hosts in this profile's local storage
        """
        if not self.localstorage_present and self._missing_data_ok:
            return
        self._lazy_load_localstorage()
        yield from self._local_storage.iter_storage_keys()

    def iter_local_storage(
            self, storage_key: typing.Optional[KeySearch]=None, script_key: typing.Optional[KeySearch]=None, *,
            include_deletions=False, raise_on_no_result=False
    ) -> col_abc.Iterable[ccl_chromium_localstorage.LocalStorageRecord]:
        """
        Iterates this profile's local storage records

        :param storage_key: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param script_key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param include_deletions: if True, records related to deletions will be included
        :param raise_on_no_result: if True (the default) if no matching storage keys are found, raise a KeyError
        (these will have None as values).
        :return: iterable of LocalStorageRecords
        """
        if not self.localstorage_present and self._missing_data_ok:
            return

        self._lazy_load_localstorage()
        if storage_key is None and script_key is None:
            yield from self._local_storage.iter_all_records(include_deletions=include_deletions)
        elif storage_key is None:
            results = (
                x for x in self._local_storage.iter_all_records(include_deletions=include_deletions)
                if is_keysearch_hit(script_key, x.script_key))
            yielded = False
            for result in results:
                yield result
                yielded = True
            if not yielded and raise_on_no_result:
                raise KeyError(script_key)
        elif script_key is None:
            yield from self._local_storage.iter_records_for_storage_key(
                storage_key, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)
        else:
            yield from self._local_storage.iter_records_for_script_key(
                storage_key, script_key, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)

    def iter_local_storage_with_batches(
            self, storage_key: typing.Optional[KeySearch]=None, script_key: typing.Optional[KeySearch]=None, *,
            include_deletions=False, raise_on_no_result=False
    ) -> col_abc.Iterable[tuple[ccl_chromium_localstorage.LocalStorageRecord, ccl_chromium_localstorage.LocalStorageBatch]]:
        """
        Iterates this profile's local storage records with associated batches where possible.

        :param storage_key: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool; or
        None (the default) in which case all hosts are considered.
        :param script_key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool; or
        None (the default) in which case all keys are considered.
        :param include_deletions: if True, records related to deletions will be included
        :param raise_on_no_result: if True (the default) if no matching storage keys are found, raise a KeyError
        (these will have None as values).
        :return: iterable of tuples or (LocalStorageRecords, LocalStorageBatch)
        """
        if not self.localstorage_present and self._missing_data_ok:
            return

        # iter_local_storage lazy loads the localstorage, so we don't need to check ahead of time.
        for rec in self.iter_local_storage(storage_key, script_key,
                                           include_deletions=include_deletions,
                                           raise_on_no_result=raise_on_no_result):
            batch = self._local_storage.find_batch(rec.leveldb_seq_number)
            yield rec, batch

    def iter_session_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates this profile's session storage hosts
        """
        if not self.sessionstorage_present and self._missing_data_ok:
            return
        self._lazy_load_sessionstorage()
        yield from self._session_storage.iter_hosts()

    def iter_session_storage(
            self, host: typing.Optional[KeySearch]=None, key: typing.Optional[KeySearch]=None, *,
            include_deletions=False, raise_on_no_result=False
    ) -> col_abc.Iterable[ccl_chromium_sessionstorage.SessionStoreValue]:
        """
        Iterates this profile's session storage records

        :param host: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and
        returns a bool; or None (the default) in which case all hosts are considered.
        :param key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool; or
        None (the default) in which case all keys are considered.
        :param include_deletions: if True, records related to deletions will be included (these will have None as
        values).
        :param raise_on_no_result: if True, if no matching storage keys are found, raise a KeyError

        :return: iterable of SessionStoreValue
        """
        if not self.sessionstorage_present and self._missing_data_ok:
            return

        self._lazy_load_sessionstorage()
        if host is None and key is None:
            yield from self._session_storage.iter_all_records(include_deletions=include_deletions, include_orphans=True)
        elif host is None:
            results = (
                rec for
                rec in self._session_storage.iter_all_records(
                include_deletions=include_deletions, include_orphans=True)
                if is_keysearch_hit(key, rec.key)
            )
            yielded = False
            for result in results:
                yield result
                yielded = True
            if not yielded and raise_on_no_result:
                raise KeyError(key)
        elif key is None:
            yield from self._session_storage.iter_records_for_host(
                host, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)
        else:
            yield from self._session_storage.iter_records_for_session_storage_key(
                host, key, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)

    def iter_indexeddb_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates the hosts present in the Indexed DB folder. These values are what should be used to load the databases
        directly.
        """
        if not self.indexeddb_present and self._missing_data_ok:
            return
        self._lazy_populate_indexeddb_list()
        yield from self._indexeddb_databases.keys()

    def get_indexeddb(self, host: str) -> ccl_chromium_indexeddb.WrappedIndexDB:
        """
        Returns the database with the host provided. Should be one of the values returned by
        :func:`~iter_indexeddb_hosts`. The database will be opened on-demand if it hasn't previously been opened.

        :param host: the host to get
        """
        if host not in self._indexeddb_databases:
            raise KeyError(host)

        self._lazy_load_indexeddb(host)
        return self._indexeddb_databases[host]

    def iter_indexeddb_records(
            self, host_id: typing.Optional[KeySearch], database_name: typing.Optional[KeySearch]=None,
            object_store_name: typing.Optional[KeySearch]=None, *,
            raise_on_no_result=False, include_deletions=False,
            bad_deserializer_data_handler: typing.Callable[[ccl_chromium_indexeddb.IdbKey, bytes], typing.Any] = None):
        """
        Iterates indexeddb records in this profile.

        :param host_id: the host for the records, relates to the host-named folder in the IndexedDB folder. The
        possible values for this profile are returned by :func:`~iter_indexeddb_hosts`. This can be one of:
        a single string; a collection of strings; a regex pattern; a function that takes a string (each host) and
        returns a bool; or None in which case all hosts are considered. Be cautious with supplying a parameter
        which will lead to unnecessary databases being opened as this has a set-up time for the first time it
        is opened.
        :param database_name: the database name for the records. This can be one of: a single string; a collection
        of strings; a regex pattern; a function that takes a string (each host) and returns a bool; or None (the
        default) in which case all hosts are considered.
        :param object_store_name: the object store name of the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and returns a bool;
        or None (the default) in which case all hosts are considered.
        :param raise_on_no_result: if True, if no matching storage keys are found, raise a KeyError
        :param include_deletions: if True, records related to deletions will be included (these will have None as
        values).
        :param bad_deserializer_data_handler: a callback function which will be executed by the underlying
        indexeddb reader if invalid data is encountered during reading a record, rather than raising an exception.
        The function should take two arguments: an IdbKey object (which is the key of the bad record) and a bytes
        object (which is the raw data). The return value of the callback is ignored by the calling code. If this is
        None (the default) then any bad data will cause an exception to be raised.

        """
        if not self.indexeddb_present and self._missing_data_ok:
            return

        self._lazy_populate_indexeddb_list()

        # probably not optimal performance, but we only do it once per call, and it's a lot neater.
        if host_id is None:
            found_hosts = list(self.iter_indexeddb_hosts())
        else:
            found_hosts = [x for x in self._indexeddb_databases.keys() if is_keysearch_hit(host_id, x)]

        if not found_hosts and raise_on_no_result:
            raise KeyError((host_id, database_name, object_store_name))

        yielded = False
        for found_host in found_hosts:
            idb = self.get_indexeddb(found_host)
            for idb_db_id in idb.database_ids:
                if database_name is None or is_keysearch_hit(database_name, idb_db_id.name):
                    idb_db = idb[idb_db_id]
                    for idb_db_objstore_name in idb_db.object_store_names:
                        if object_store_name is None or is_keysearch_hit(object_store_name,  idb_db_objstore_name):
                            idb_db_objstore = idb_db.get_object_store_by_name(idb_db_objstore_name)
                            for rec in idb_db_objstore.iterate_records(
                                    live_only=not include_deletions,
                                    bad_deserializer_data_handler=bad_deserializer_data_handler):
                                yield rec
                                yielded = True

        if not yielded and raise_on_no_result:
            raise KeyError((host_id, database_name, object_store_name))

    def iterate_history_records(
            self, url: typing.Optional[KeySearch]=None, *,
            earliest: typing.Optional[datetime.datetime]=None, latest: typing.Optional[datetime.datetime]=None):
        """
        Iterates history records for this profile.

        :param url: a URL to search for. This can be one of: a single string; a collection of strings;
        a regex pattern; a function that takes a string (each host) and returns a bool; or None (the
        default) in which case all hosts are considered.
        :param earliest: an optional datetime which will be used to exclude records before this date.
        NB the date should be UTC to match the database. If None, no lower limit will be placed on
        timestamps.
        :param latest: an optional datetime which will be used to exclude records after this date.
        NB the date should be UTC to match the database. If None, no upper limit will be placed on
        timestamps.
        """
        if not self.history_present and self._missing_data_ok:
            return
        self._lazy_load_history()
        yield from self._history.iter_history_records(url, earliest=earliest, latest=latest)

    @staticmethod
    def _decompress_cache_data(data, content_encoding) -> tuple[bool, bytes]:
        try:
            if content_encoding.strip() == "gzip":
                return True, gzip.decompress(data)
            elif content_encoding.strip() == "br":
                return True, brotli.decompress(data)
            elif content_encoding.strip() == "deflate":
                return True, zlib.decompress(data, -zlib.MAX_WBITS)  # suppress trying to read a header
            elif content_encoding.strip() == "zstd":
                return True, zstd.decompress(data)
        except (EOFError, gzip.BadGzipFile, brotli.error, zlib.error, zstd.Error):
            return False, data

        return False, data

    def _yield_cache_record(self, key: ccl_chromium_cache.CacheKey, decompress, omit_data):
        metas = self._cache.get_metadata(key)
        if not omit_data:
            datas = self._cache.get_cachefile(key)
        else:
            datas = [None] * len(metas)
        meta_locations = self._cache.get_location_for_metadata(key)
        data_locations = self._cache.get_location_for_cachefile(key)

        if not (len(metas) == len(datas) == len(meta_locations) == len(data_locations)):
            raise ValueError("Data and metadata counts do not match")

        for idx, (meta, data, meta_location, data_location) in enumerate(
                zip(metas, datas, meta_locations, data_locations)):
            if decompress and data is not None and meta is not None:
                content_encoding = (meta.get_attribute("content-encoding") or [""])[0]
                was_decompressed, data = self._decompress_cache_data(data, content_encoding)
            else:
                was_decompressed = False
            yield CacheResult(key, meta, data, meta_location, data_location, was_decompressed, idx)

    def iterate_cache(
            self,
            url: typing.Optional[KeySearch]=None, *, decompress=True, omit_cached_data=False,
            **kwargs: typing.Union[bool, KeySearch]) -> col_abc.Iterable[CacheResult]:
        """
        Iterates cache records for this profile.

        :param url: a URL to search for. This can be one of: a single string; a collection of strings;
        a regex pattern; a function that takes a string (each host) and returns a bool; or None (the
        default) in which case all records are considered.
        :param decompress: if True (the default), data from the cache which is compressed (as per the
        content-encoding header field) will be decompressed when read if the compression format is
        supported (currently deflate, gzip and brotli are supported).
        :param omit_cached_data: does not collect the cached data and omits it from each `CacheResult`
        object. Should be faster in cases when only metadata recovery is required.
        :param kwargs: further keyword arguments are used to search based upon header fields. The
        keyword should be the header field name, with underscores replacing hyphens (e.g.,
        content-encoding, becomes content_encoding). The value should be one of: a Boolean (in which
        case only records with this field present will be included if True, and vice versa); a single
        string; a collection of strings; a regex pattern; a function that takes a string (the value)
        and returns a bool.
        """
        if not self.cache_present and self._missing_data_ok:
            return
        self._lazy_load_cache()
        if url is None and not kwargs:
            for key in self._cache.cache_keys():
                yield from self._yield_cache_record(key, decompress, omit_cached_data)
        else:
            for key in self._cache.cache_keys():
                if url is not None and not is_keysearch_hit(url, key.url):
                    # Fail condition: URL doesn't match
                    continue
                if not kwargs:
                    # No metadata keyword arguments to check
                    yield from self._yield_cache_record(key, decompress, omit_cached_data)
                else:
                    metas = self._cache.get_metadata(key)
                    if not metas or all(x is None for x in metas):
                        # Fail condition: we had metadata to check, but no metadata to check against
                        continue
                    else:
                        meta_hit_indices = []
                        for meta_idx, meta in enumerate(metas):
                            hit = True
                            for attribute_name, attribute_check in kwargs.items():
                                attribute_name = attribute_name.replace("_", "-")
                                if isinstance(attribute_check, bool):
                                    if (attribute_check == True and
                                            not meta.has_declaration(attribute_name) and
                                            not meta.get_attribute(attribute_name)):
                                        hit = False
                                        break
                                    if (attribute_check == False and
                                            (meta.has_declaration(attribute_name) or
                                             meta.get_attribute(attribute_name))):
                                        hit = False
                                        break
                                else:
                                    attribute = meta.get_attribute(attribute_name)
                                    if not any(is_keysearch_hit(attribute_check, x) for x in attribute):
                                        hit = False
                                        break

                            if hit:
                                meta_hit_indices.append(meta_idx)

                        if meta_hit_indices:
                            if not omit_cached_data:
                                datas = self._cache.get_cachefile(key)
                            else:
                                datas = [None] * len(metas)
                            metadata_locations = self._cache.get_location_for_metadata(key)
                            data_locations = self._cache.get_location_for_cachefile(key)

                            if not (len(metas) == len(datas) == len(metadata_locations) == len(data_locations)):
                                raise ValueError("Data and metadata counts do not match")

                            for i in meta_hit_indices:
                                meta = metas[i]
                                data = datas[i]
                                metadata_location = metadata_locations[i]
                                data_location = data_locations[i]

                                if decompress and data is not None:
                                    content_encoding = (meta.get_attribute("content-encoding") or [""])[0]
                                    was_decompressed, data = self._decompress_cache_data(data, content_encoding)
                                else:
                                    was_decompressed = False

                                yield CacheResult(
                                    key, meta, data, metadata_location, data_location, was_decompressed, i)

    def iter_downloads(
            self, *, download_url: typing.Optional[KeySearch]=None, tab_url: typing.Optional[KeySearch]=None):
        """
        Iterates download records for this profile

        :param download_url: A URL related to the downloaded resource. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and returns a bool;
        or None (the default) in which case all records are considered.
        :param tab_url: A URL related to the page the user was accessing when this download was started.
        This can be one of: a single string; a collection of strings; a regex pattern; a function that takes
        a string (each host) and returns a bool; or None (the default) in which case all records are considered.
        """
        if (self._path / SHARED_PROTO_DB_FOLDER_PATH).is_dir():
            for download in ccl_shared_proto_db_downloads.read_downloads(self._path / SHARED_PROTO_DB_FOLDER_PATH):
                if ((download_url is None or any(is_keysearch_hit(download_url, url) for url in download.url_chain))
                    and
                    (tab_url is None
                        or is_keysearch_hit(tab_url, download.tab_url or "")
                        or is_keysearch_hit(tab_url, download.tab_referrer_url or ""))):
                    yield download
        elif not self._missing_data_ok:
            raise NotADirectoryError("could not find shared proto db for downloads")

        if not self.history_present and self._missing_data_ok:
            return

        self._lazy_load_history()
        for download in self._history.iter_downloads(download_url=download_url, tab_url=tab_url):
            yield download

    def __enter__(self) -> "ChromiumProfileFolder":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def path(self):
        """The input path of this profile folder"""
        return self._path

    @property
    def local_storage(self) -> ccl_chromium_localstorage.LocalStoreDb:
        """The local storage object for this profile folder"""
        self._lazy_load_localstorage()
        return self._local_storage

    @property
    def session_storage(self) -> ccl_chromium_sessionstorage.SessionStoreDb:
        """The session storage object for this profile folder"""
        self._lazy_load_sessionstorage()
        return self._session_storage

    @property
    def cache(self) -> ccl_chromium_cache.ChromiumCache:
        """The cache for this profile folder"""
        self._lazy_load_cache()
        return self._cache

    @property
    def history(self) -> ccl_chromium_history.HistoryDatabase:
        """The history for this profile folder"""
        self._lazy_load_history()
        return self._history

    @property
    def browser_type(self) -> str:
        return "Chromium"
