import datetime
import pathlib
import typing
import collections.abc as col_abc

from .common import KeySearch


class ArtifactLocationProtocol(typing.Protocol):
    @property
    def source_file(self) -> str:
        raise NotImplementedError()

    @property
    def offset(self) -> typing.Optional[int]:
        raise NotImplementedError()

    @property
    def friendly_string(self) -> str:
        raise NotImplementedError()


class HasRecordLocationProtocol(typing.Protocol):
    @property
    def record_location(self) -> ArtifactLocationProtocol:
        raise NotImplementedError()


@typing.runtime_checkable
class LocalStorageRecordProtocol(HasRecordLocationProtocol, typing.Protocol):
    @property
    def storage_key(self) -> str:
        raise NotImplementedError()

    @property
    def script_key(self) -> str:
        raise NotImplementedError()

    @property
    def value(self) -> str:
        raise NotImplementedError()


@typing.runtime_checkable
class SessionStorageRecordProtocol(HasRecordLocationProtocol, typing.Protocol):
    host: typing.Optional[str]
    key: str
    value: str


@typing.runtime_checkable
class HistoryRecordProtocol(HasRecordLocationProtocol, typing.Protocol):
    url: str
    title: str
    visit_time: datetime.datetime
    # TODO: Assess whether the parent/child visits can be part of the protocol


@typing.runtime_checkable
class IdbKeyProtocol(typing.Protocol):
    raw_key: bytes
    value: typing.Any


@typing.runtime_checkable
class IndexedDbRecordProtocol(HasRecordLocationProtocol, typing.Protocol):
    key: IdbKeyProtocol
    value: typing.Any


class CacheMetadataProtocol(typing.Protocol):
    request_time: datetime.datetime
    http_header_attributes: typing.Iterable[tuple[str, str]]

    def get_attribute(self, attribute: str) -> list[str]:
        raise NotImplementedError()


class CacheKeyProtocol(typing.Protocol):
    raw_key: str
    url: str


class CacheRecordProtocol(typing.Protocol):
    key: CacheKeyProtocol
    metadata: CacheMetadataProtocol
    data: bytes
    metadata_location: ArtifactLocationProtocol
    data_location: ArtifactLocationProtocol
    was_decompressed: bool


class DownloadRecordProtocol(HasRecordLocationProtocol, typing.Protocol):
    url: str
    start_time: typing.Optional[datetime.datetime]
    end_time: typing.Optional[datetime.datetime]
    target_path: typing.Optional[str]
    file_size: int


@typing.runtime_checkable
class BrowserProfileProtocol(typing.Protocol):
    def close(self):
        raise NotImplementedError()

    def iter_local_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates the hosts in this profile's local storage
        """
        raise NotImplementedError()

    def iter_local_storage(
            self, storage_key: typing.Optional[KeySearch] = None, script_key: typing.Optional[KeySearch] = None, *,
            include_deletions=False, raise_on_no_result=False) -> col_abc.Iterable[LocalStorageRecordProtocol]:
        """
        Iterates this profile's local storage records

        :param storage_key: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param script_key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param include_deletions: if True, records related to deletions will be included
        :param raise_on_no_result: if True (the default) if no matching storage keys are found, raise a KeyError
        (these will have None as values).
        :return:
        """
        raise NotImplementedError()

    def iter_session_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates this profile's session storage hosts
        """
        raise NotImplementedError()

    def iter_session_storage(
            self, host: typing.Optional[KeySearch] = None, key: typing.Optional[KeySearch] = None, *,
            include_deletions=False, raise_on_no_result=False) -> col_abc.Iterable[SessionStorageRecordProtocol]:
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
        raise NotImplementedError()

    def iter_indexeddb_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates the hosts present in the Indexed DB folder. These values are what should be used to load the databases
        directly.
        """
        raise NotImplementedError()

    def get_indexeddb(self, host: str):
        """
        Returns the database with the host provided. Should be one of the values returned by
        :func:`~iter_indexeddb_hosts`. The database will be opened on-demand if it hasn't previously been opened.

        :param host: the host to get
        """
        # TODO typehint return type once it's also abstracted
        raise NotImplementedError()

    def iter_indexeddb_records(
            self, host_id: typing.Optional[KeySearch], database_name: typing.Optional[KeySearch] = None,
            object_store_name: typing.Optional[KeySearch] = None, *,
            raise_on_no_result=False, include_deletions=False,
            bad_deserializer_data_handler=None) -> col_abc.Iterable[IndexedDbRecordProtocol]:
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
        raise NotImplementedError()

    def iterate_history_records(
            self, url: typing.Optional[KeySearch]=None, *,
            earliest: typing.Optional[datetime.datetime]=None,
            latest: typing.Optional[datetime.datetime]=None) -> col_abc.Iterable[HistoryRecordProtocol]:
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
        # TODO typehint return type once it's also abstracted
        raise NotImplementedError()

    def iterate_cache(
            self,
            url: typing.Optional[KeySearch]=None, *, decompress=True, omit_cached_data=False,
            **kwargs: typing.Union[bool, KeySearch]) -> col_abc.Iterable[CacheRecordProtocol]:
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
        raise NotImplementedError()

    def iter_downloads(
            self, *, download_url: typing.Optional[KeySearch]=None,
            tab_url: typing.Optional[KeySearch]=None) -> col_abc.Iterable[DownloadRecordProtocol]:
        """
        Iterates download records for this profile

        :param download_url: A URL related to the downloaded resource. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and returns a bool;
        or None (the default) in which case all records are considered.
        :param tab_url: A URL related to the page the user was accessing when this download was started.
        This can be one of: a single string; a collection of strings; a regex pattern; a function that takes
        a string (each host) and returns a bool; or None (the default) in which case all records are considered.
        """
        raise NotImplementedError()

    @property
    def path(self) -> pathlib.Path:
        """The input path of this browser profile"""
        raise NotImplementedError()

    @property
    def local_storage(self):
        """The local storage object for this browser profile"""
        raise NotImplementedError()

    @property
    def session_storage(self):
        """The session storage object for this browser profile"""
        raise NotImplementedError()

    @property
    def cache(self):
        """The cache for this browser profile"""
        raise NotImplementedError()

    @property
    def history(self):
        """The history for this browser profile"""
        raise NotImplementedError()

    @property
    def browser_type(self) -> str:
        """The name of the browser type for this profile"""
        raise NotImplementedError()
