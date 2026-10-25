"""
Copyright 2022-2025, CCL Forensics

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


import abc
import dataclasses
import io
import logging
import os
import re
import sys
import types
import typing
import pathlib
import datetime
import struct
import enum
import zlib

__version__ = "0.24"
__description__ = "Library for reading Chrome/Chromium Cache (both blockfile and simple format)"
__contact__ = "Alex Caithness"

from .structures import ArtifactLocation
from .profile_folder_protocols import ArtifactLocationProtocol

log = logging.getLogger(__name__)

_CHROME_EPOCH = datetime.datetime(1601, 1, 1)
EIGHT_BYTE_PICKLE_ALIGNMENT = True  # switch this if you get errors about the EOF magic when doing a Simple Cache
SIMPLE_EOF_SIZE = 24 if EIGHT_BYTE_PICKLE_ALIGNMENT else 20


def decode_chrome_time(us: int) -> datetime.datetime:
    return _CHROME_EPOCH + datetime.timedelta(microseconds=us)


class BinaryReader:
    """
    Utility class which wraps a BinaryIO and provides reading for a bunch of data types we need to do the cache stuff
    """
    def __init__(self, stream: typing.BinaryIO):
        self._stream = stream
        self._closed = False

    @classmethod
    def from_bytes(cls, buffer: bytes):
        return cls(io.BytesIO(buffer))

    def close(self):
        self._stream.close()
        self._closed = True

    def __enter__(self) -> "BinaryReader":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset: int, whence: int) -> int:
        return self._stream.seek(offset, whence)

    def read_raw(self, count: int) -> bytes:
        start_offset = self._stream.tell()
        result = self._stream.read(count)
        if len(result) != count:
            raise ValueError(
                f"Could not read all of the data starting at {start_offset}. Expected: {count}; got {len(result)}")
        return result

    def read_utf8(self, count: int) -> str:
        return self.read_raw(count).decode("utf-8")

    def read_int16(self) -> int:
        raw = self.read_raw(2)
        return struct.unpack("<h", raw)[0]

    def read_int32(self) -> int:
        raw = self.read_raw(4)
        return struct.unpack("<i", raw)[0]

    def read_int64(self) -> int:
        raw = self.read_raw(8)
        return struct.unpack("<q", raw)[0]

    def read_uint16(self) -> int:
        raw = self.read_raw(2)
        return struct.unpack("<H", raw)[0]

    def read_uint32(self) -> int:
        raw = self.read_raw(4)
        return struct.unpack("<I", raw)[0]

    def read_uint64(self) -> int:
        raw = self.read_raw(8)
        return struct.unpack("<Q", raw)[0]

    def read_addr(self) -> "Addr":
        return Addr.from_int(self.read_uint32())

    def read_datetime(self) -> datetime.datetime:
        return decode_chrome_time(self.read_uint64())

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def is_eof(self) -> bool:
        test = self._stream.read(1)
        if len(test) == 0:
            return True
        self._stream.seek(-1, os.SEEK_CUR)
        return False


class FileType(enum.IntEnum):
    # net/disk_cache/blockfile/disk_format.h
    EXTERNAL = 0
    RANKINGS = 1
    BLOCK_256 = 2
    BLOCK_1K = 3
    BLOCK_4K = 4
    BLOCK_FILES = 5
    BLOCK_ENTRIES = 6
    BLOCK_EVICTED = 7


_BLOCKSIZE_FOR_FILETYPE = {
    FileType.RANKINGS: 36,
    FileType.BLOCK_256: 256,
    FileType.BLOCK_1K: 1024,
    FileType.BLOCK_4K: 4096,
    FileType.BLOCK_FILES: 8,
    FileType.BLOCK_ENTRIES: 104,
    FileType.BLOCK_EVICTED: 48,
    FileType.EXTERNAL: 0
}


_BLOCK_FILE_FILETYPE = {FileType.BLOCK_256, FileType.BLOCK_1K, FileType.BLOCK_4K}


class CacheKey:
    """
    Class representing a parsed Chromium Cache Key.
    """
    # net/http/http_cache.cc GenerateCacheKey
    CRED_UPLOAD_KEY_PREFIX_PATTERN = re.compile(r"^\d+/\d+/")  # 'current' (since Sept '21)
    UPLOAD_ONLY_KEY_PREFIX_PATTERN = re.compile(r"^\d+/")  # prior to Sept '21
    # if neither of the above we assume we only have a URL

    # content/browser/code_cache/generated_code_cache.cc
    # Code Cache keys use the format: "_key" + resource_url [+ "\n" + origin_lock]
    # Keys that are too long are replaced with a hex SHA-256 hash.
    _CODE_CACHE_KEY_PREFIX = "_key"
    _CODE_CACHE_HASH_PATTERN = re.compile(r"^[0-9A-F]{64}$")

    def __init__(self, raw_key: str):
        self._raw_key = raw_key
        self._code_cache_origin = None
        self._is_code_cache_key = False
        self._credential_key = None
        self._upload_data_identifier = None
        self._isolation_key_top_frame_site = None
        self._isolation_key_variable_part = None

        # We have to account for a few different versions of keys, we can do this based on a prefix
        if CacheKey.UPLOAD_ONLY_KEY_PREFIX_PATTERN.match(self._raw_key):
            if CacheKey.CRED_UPLOAD_KEY_PREFIX_PATTERN.match(self._raw_key):
                split_key = self._raw_key.split("/", 2)
                self._credential_key = split_key[0]
                self._upload_data_identifier = int(split_key[1])
            else:
                split_key = self._raw_key.split("/", 1)
                self._credential_key = ""
                self._upload_data_identifier = int(split_key[0])

            if split_key[-1].startswith("_dk_"):
                # consume two kDoubleKeySeparator (a space), the url is after that
                (self._isolation_key_top_frame_site,
                 self._isolation_key_variable_part,
                 self._url) = split_key[-1][4:].split(" ", 2)
                if self._isolation_key_top_frame_site.startswith("s_"):
                    self._isolation_key_top_frame_site = self._isolation_key_top_frame_site[2:]
            else:
                self._url = split_key[-1]
        elif self._raw_key.startswith(CacheKey._CODE_CACHE_KEY_PREFIX):
            # Code Cache key: "_key<resource_url>[\n<origin_lock>]"
            self._is_code_cache_key = True
            key_body = self._raw_key[len(CacheKey._CODE_CACHE_KEY_PREFIX):]
            if "\n" in key_body:
                self._url, self._code_cache_origin = key_body.split("\n", 1)
            else:
                self._url = key_body
        elif CacheKey._CODE_CACHE_HASH_PATTERN.match(self._raw_key):
            # Code Cache hash key (key was too long, replaced with SHA-256 hash)
            self._is_code_cache_key = True
            self._url = self._raw_key
        else:
            # if the prefixes don't hit, this should just be a URL
            self._url = self._raw_key

    @property
    def raw_key(self) -> str:
        return self._raw_key

    @property
    def url(self) -> str:
        return self._url

    @property
    def is_code_cache_key(self) -> bool:
        """Whether this key originates from a Code Cache (JS/WASM compiled code)."""
        return self._is_code_cache_key

    @property
    def code_cache_origin(self) -> typing.Optional[str]:
        """The origin lock for a Code Cache key, or None if not a Code Cache key or no origin lock."""
        return self._code_cache_origin

    @property
    def credential_key(self) -> typing.Optional[str]:
        return self._credential_key

    @property
    def upload_data_identifier(self) -> typing.Optional[int]:
        return self._upload_data_identifier

    @property
    def isolation_key_top_frame_site(self) -> typing.Optional[str]:
        return self._isolation_key_top_frame_site

    @property
    def isolation_key_variable_part(self):
        return self._isolation_key_variable_part

    def __str__(self):
        return self._raw_key

    def __repr__(self):
        if self._is_code_cache_key:
            return (f"<CacheKey (code_cache) url: {self._url}; "
                    f"code_cache_origin: {self._code_cache_origin}>")
        return (f"<CacheKey url: {self._url}; credential_key: {self._credential_key}; "
                f"upload_data_identifier: {self._upload_data_identifier}; "
                f"isolation_key_top_frame_site: {self._isolation_key_top_frame_site}; "
                f"isolation_key_variable_part: {self._isolation_key_variable_part}>")


class Addr:
    # net/disk_cache/blockfile/addr.h
    def __init__(
            self, is_initialized: bool, file_type: FileType, file_number: typing.Optional[int],
            contiguous_blocks: typing.Optional[int], file_selector: typing.Optional[int], block_number: int,
            reserved_bits: typing.Optional[int]):
        self._is_initialized = is_initialized
        self._file_type = file_type
        self._file_number = file_number
        self._contiguous_blocks = contiguous_blocks
        self._file_selector = file_selector
        self._block_number = block_number
        self._reserved_bits = reserved_bits

    def __repr__(self):
        return (f"<Addr: is_initialized: {self._is_initialized}; file_type: {self._file_type.name}; "
                f"file_number: {self._file_number}; contiguous_blocks: {self._contiguous_blocks}; "
                f"file_selector: {self._file_selector}; block_number: {self._block_number}>")

    @classmethod
    def from_int(cls, i: int):
        is_initialized = (i & 0x80000000) > 0
        file_type = FileType((i & 0x70000000) >> 28)

        if file_type == FileType.EXTERNAL:
            file_number = i & 0x0fffffff
            contiguous_blocks = None
            file_selector = None
            block_number = None
            reserved_bits = None
        else:
            file_number = None
            contiguous_blocks = 1 + ((i & 0x03000000) >> 24)
            file_selector = (i & 0x00ff0000) >> 16
            block_number = i & 0x0000ffff
            reserved_bits = i & 0x0c000000

        return Addr(
            is_initialized,
            file_type,
            file_number,
            contiguous_blocks,
            file_selector,
            block_number,
            reserved_bits)

    def sanity_check(self) -> bool:
        # implementation from addr.cc - will hopefully identify invalid data and skip it rather than raising exceptions
        #  we omit the initialized check from that version, as that's to identify a totally empty entry (which is sane
        #  but of no use to us in any context we use it).
        if self._file_type > FileType.BLOCK_4K:
            return False
        if self._file_type != FileType.EXTERNAL and self._reserved_bits != 0:
            return False

        return True

    def sanity_check_for_entry(self) -> bool:
        return self.sanity_check() and self._file_type == FileType.BLOCK_256

    @property
    def is_initialized(self) -> bool:
        return self._is_initialized

    @property
    def file_type(self) -> FileType:
        return self._file_type

    @property
    def contiguous_blocks(self) -> int:
        return self._contiguous_blocks

    @property
    def file_selector(self) -> int:
        return self._file_selector

    @property
    def block_number(self) -> int:
        return self._block_number

    @property
    def external_file_number(self) -> int:
        return self._file_number


@dataclasses.dataclass(frozen=True)
class LruData:
    # net/disk_cache/blockfile/disk_format.h
    filled: int
    sizes: typing.Collection[int]
    heads: typing.Collection[Addr]
    tails: typing.Collection[Addr]
    transactions: Addr
    operation: int
    operation_list: int

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        _ = [reader.read_int32() for x in range(2)]
        filled = reader.read_int32()
        sizes = tuple(reader.read_int32() for _ in range(5))
        heads = tuple(reader.read_addr() for _ in range(5))
        tails = tuple(reader.read_addr() for _ in range(5))
        transaction = reader.read_addr()
        operation = reader.read_int32()
        operation_list = reader.read_int32()
        _ = [reader.read_int32() for x in range(7)]

        return cls(filled, sizes, heads, tails, transaction, operation, operation_list)


@dataclasses.dataclass(frozen=True)
class BlockFileIndexHeader:
    # net/disk_cache/blockfile/disk_format.h
    version: int
    num_entries: int
    num_bytes_v2: int
    last_file: int
    this_id: int
    stats_addr: Addr
    table_length: int
    crash: int
    experiment: int
    create_time: datetime.datetime
    num_bytes_v3: int
    lru: LruData

    _MAGIC: typing.ClassVar[int] = 0xC103CAC3

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint32()
        if magic != BlockFileIndexHeader._MAGIC:
            raise ValueError("invalid magic")
        version = reader.read_uint32()
        num_entries = reader.read_int32()
        old_v2_num_bytes = reader.read_uint32()
        last_file = reader.read_int32()
        this_id = reader.read_int32()
        stats_addr = reader.read_addr()
        table_length = reader.read_int32() or 0x10000
        crash = reader.read_int32()
        experiment = reader.read_int32()
        create_time = reader.read_datetime()
        num_bytes = reader.read_int64()
        _ = [reader.read_int32() for x in range(50)]
        lru = LruData.from_reader(reader)

        return cls(
            version, num_entries, old_v2_num_bytes, last_file, this_id, stats_addr,
            table_length, crash, experiment, create_time, num_bytes, lru)


class BlockFileIndexFile:
    # net/disk_cache/blockfile/disk_format.h
    def __init__(self, file_path: typing.Union[os.PathLike, str]):
        self._input_path = pathlib.Path(file_path)
        with BinaryReader(self._input_path.open("rb")) as reader:
            self._header = BlockFileIndexHeader.from_reader(reader)
            self._entries = tuple(reader.read_addr() for _ in range(self._header.table_length))
            self._entries_initialized = tuple(x for x in self._entries if x.is_initialized)

    @property
    def input_path(self):
        return self._input_path

    @property
    def header(self) -> BlockFileIndexHeader:
        return self._header

    @property
    def index(self) -> typing.Collection[Addr]:
        return self._entries

    @property
    def index_initialized_only(self):
        return self._entries_initialized


class EntryState(enum.IntEnum):
    NORMAL = 0
    EVICTED = 1
    DOOMED = 2


class EntryFlags(enum.IntFlag):
    PARENT_ENTRY = 1 << 0
    CHILD_ENTRY = 1 << 1


@dataclasses.dataclass(frozen=True)
class EntryStore:
    # net/disk_cache/blockfile/disk_format.h
    entry_hash: int
    next_entry: Addr
    rankings_node: Addr
    reuse_count: int
    refetch_count: int
    state: EntryState
    creation_time: datetime.datetime
    key_length: int
    long_key_addr: Addr
    data_sizes: tuple[int, int, int, int]
    data_addrs: tuple[Addr, Addr, Addr, Addr]
    flags: EntryFlags
    self_hash: int
    key: typing.Optional[str]

    @property
    def key_is_external(self) -> bool:
        return self.long_key_addr.is_initialized

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        start = reader.tell()

        entry_hash = reader.read_uint32()
        next_entry = reader.read_addr()
        rankings_node = reader.read_addr()
        reuse_count = reader.read_int32()
        refetch_count = reader.read_int32()
        state = EntryState(reader.read_int32())
        creation_time = reader.read_datetime()
        key_length = reader.read_int32()
        long_key_addr = reader.read_addr()
        data_sizes = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())
        data_addrs = (reader.read_addr(), reader.read_addr(), reader.read_addr(), reader.read_addr())
        flags = EntryFlags(reader.read_uint32())
        _ = [reader.read_int32() for x in range(4)]
        self_hash = reader.read_uint32()

        meta_length = reader.tell() - start

        key = None
        key_is_external = long_key_addr.is_initialized
        if not key_is_external:
            key = reader.read_utf8(key_length)

        return cls(
            entry_hash, next_entry, rankings_node, reuse_count, refetch_count, state, creation_time, key_length,
            long_key_addr, data_sizes, data_addrs, flags, self_hash, key)


@dataclasses.dataclass(frozen=True)
class BlockFileHeader:
    # net/disk_cache/blockfile/disk_format_base.h
    version: int
    this_file: int
    next_file: int
    entry_size: int
    num_entries: int
    max_entries: int
    empty_type_counts: tuple[int, int, int, int]
    hints: tuple[int, int, int, int]
    updating: int
    user: tuple[int, int, int, int, int]
    allocation_map: bytes

    _MAGIC: typing.ClassVar[int] = 0xC104CAC3
    _BLOCK_HEADER_SIZE: typing.ClassVar[int] = 8192
    _MAX_BLOCKS: typing.ClassVar[int] = (_BLOCK_HEADER_SIZE - 80) * 8

    def __post_init__(self):
        if len(self.allocation_map) != self._MAX_BLOCKS // 8:
            raise ValueError("invalid allocation map length")

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint32()
        if magic != cls._MAGIC:
            raise ValueError("invalid magic")
        version = reader.read_uint32()
        this_file = reader.read_int16()
        next_file = reader.read_int16()
        entry_size = reader.read_int32()
        num_entries = reader.read_int32()
        max_entries = reader.read_int32()
        empty = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())
        hints = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())
        updating = reader.read_int32()
        user = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())

        allocation_map = reader.read_raw(cls._MAX_BLOCKS // 8)

        return cls(
            version, this_file, next_file, entry_size, num_entries, max_entries,
            empty, hints, updating, user, allocation_map)


class CachedMetadataFlags(enum.IntFlag):
    # net/http/http_response_info.cc

    RESPONSE_INFO_VERSION = 3
    RESPONSE_INFO_VERSION_MASK = 0xFF

    # This bit is set if the response info has a cert at the end.
    RESPONSE_INFO_HAS_CERT = 1 << 8
    RESPONSE_INFO_HAS_SECURITY_BITS = 1 << 9
    RESPONSE_INFO_HAS_CERT_STATUS = 1 << 10
    RESPONSE_INFO_HAS_VARY_DATA = 1 << 11
    RESPONSE_INFO_TRUNCATED = 1 << 12
    RESPONSE_INFO_WAS_SPDY = 1 << 13
    RESPONSE_INFO_WAS_ALPN = 1 << 14
    RESPONSE_INFO_WAS_PROXY = 1 << 15
    RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS = 1 << 16
    RESPONSE_INFO_HAS_ALPN_NEGOTIATED_PROTOCOL = 1 << 17
    RESPONSE_INFO_HAS_CONNECTION_INFO = 1 << 18
    RESPONSE_INFO_USE_HTTP_AUTHENTICATION = 1 << 19
    RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS = 1 << 20
    RESPONSE_INFO_UNUSED_SINCE_PREFETCH = 1 << 21
    RESPONSE_INFO_HAS_KEY_EXCHANGE_GROUP = 1 << 22
    RESPONSE_INFO_PKP_BYPASSED = 1 << 23
    RESPONSE_INFO_HAS_STALENESS = 1 << 24
    RESPONSE_INFO_HAS_PEER_SIGNATURE_ALGORITHM = 1 << 25
    RESPONSE_INFO_RESTRICTED_PREFETCH = 1 << 26
    RESPONSE_INFO_HAS_DNS_ALIASES = 1 << 27
    RESPONSE_INFO_SINGLE_KEYED_CACHE_ENTRY_UNUSABLE = 1 << 28
    RESPONSE_INFO_ENCRYPTED_CLIENT_HELLO = 1 << 29
    RESPONSE_INFO_BROWSER_RUN_ID = 1 << 30
    RESPONSE_INFO_HAS_EXTRA_FLAGS = 1 << 31  # indicates that we need to read the extra flags after this value


class CachedMetadataExtraFlags(enum.IntFlag):
    RESPONSE_EXTRA_INFO_DID_USE_SHARED_DICTIONARY = 1
    RESPONSE_EXTRA_INFO_HAS_PROXY_CHAIN = 1 << 1
    RESPONSE_EXTRA_INFO_HAS_ORIGINAL_RESPONSE_TIME = 1 << 2


class CachedMetadata:
    # net/http/http_response_info.cc / net/http/http_response_info.h
    def __init__(
            self, header_declarations: set[str], header_attributes: dict[str, list[str]],
            request_time: typing.Optional[datetime.datetime], response_time: datetime.datetime, certs: list[bytes],
            host_address: str, hot_port: int, other_attributes: dict[str, typing.Any]):
        self._declarations = header_declarations.copy()
        self._attributes = types.MappingProxyType(header_attributes.copy())
        self._request_time = request_time
        self._response_time = response_time
        self._certs = certs.copy()
        self._other_attributes = types.MappingProxyType(other_attributes)
        self._host_address = host_address
        self._host_port = hot_port

    @property
    def certs(self) -> typing.Iterable[bytes]:
        yield from self._certs

    @property
    def http_header_declarations(self) -> typing.Iterable[str]:
        yield from self._declarations

    @property
    def request_time(self) -> typing.Optional[datetime.datetime]:
        return self._request_time

    @property
    def response_time(self) -> datetime.datetime:
        return self._response_time

    @property
    def http_header_attributes(self) -> typing.Iterable[tuple[str, str]]:
        for key, vals in self._attributes.items():
            for val in vals:
                yield key, val

    def has_declaration(self, declaration: str) -> bool:
        return declaration in self._declarations

    def get_attribute(self, attribute: str) -> list[str]:
        return self._attributes.get(attribute.lower()) or []

    @property
    def other_cache_attributes(self):
        return self._other_attributes

    @classmethod
    def from_buffer(cls, buffer: bytes):
        # net/http/http_response_info.cc / net/http/http_response_info.h
        # and for the proxy chain:
        # net/base/proxy_chain.cc / net/base/proxy_server.h / net/base/proxy_server.cc
        # This is a pickle, but it's a very simple one so just align manually rather than use a pickle library
        # TODO: this is increasingly not "very simple", so we should move to using ccl_easy_chromium_pickle to tidy
        #  things up.
        reader = BinaryReader.from_bytes(buffer)
        total_length = reader.read_uint32()
        if total_length != len(buffer) - 4:
            raise ValueError("Metadata buffer is not the declared size")

        def align():
            alignment = reader.tell() % 4
            if alignment != 0:
                reader.read_raw(4 - alignment)

        flags = CachedMetadataFlags(reader.read_uint32())
        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_EXTRA_FLAGS:
            extra_flags = CachedMetadataExtraFlags(reader.read_uint32())
        else:
            extra_flags = CachedMetadataExtraFlags(0)

        request_time = reader.read_datetime()
        response_time = reader.read_datetime()

        if extra_flags & CachedMetadataExtraFlags.RESPONSE_EXTRA_INFO_HAS_ORIGINAL_RESPONSE_TIME:
            # not currently reported as the meaning is not clear, but needs to be read if present in the pickle
            original_response_time = reader.read_datetime()

        http_header_length = reader.read_uint32()
        http_header_raw = reader.read_raw(http_header_length)

        header_attributes: dict[str, list[str]] = {}
        header_declarations = set()

        for header_entry in http_header_raw.split(b"\00"):
            if not header_entry:
                continue  # skip empty entries
            parsed_entry = header_entry.decode("latin-1").split(":", 1)
            if len(parsed_entry) == 1:
                header_declarations.add(parsed_entry[0])
            elif len(parsed_entry) == 2:
                header_attributes.setdefault(parsed_entry[0].lower(), [])
                header_attributes[parsed_entry[0].lower()].append(parsed_entry[1].strip())

        other_attributes = {}

        certs = []
        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_CERT:
            # net/cert/x509_certificate.cc CreateFromPickle
            align()
            cert_count = reader.read_uint32()
            for _ in range(cert_count):
                align()
                cert_length = reader.read_uint32()
                certs.append(reader.read_raw(cert_length))

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_CERT_STATUS:
            align()
            other_attributes["cert_status"] = reader.read_uint32()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_SECURITY_BITS:
            align()
            other_attributes["security_bits"] = reader.read_int32()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS:
            align()
            other_attributes["ssl_connection_status"] = reader.read_int32()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS:
            align()
            # these are unused, only here for backwards compatibility
            ts_count = reader.read_int32()
            for _ in range(ts_count):
                # net/cert/signed_certificate_timestamp.cc
                ts_version = reader.read_int32()
                str_len = reader.read_int32()
                ts_log_id = reader.read_raw(str_len)
                align()
                ts_timestamp = reader.read_datetime()
                str_len = reader.read_int32()
                ts_extensions = reader.read_raw(str_len)
                align()
                ts_hash_algo = reader.read_int32()
                ts_sig_algo = reader.read_int32()
                str_len = reader.read_int32()
                ts_sig_data = reader.read_raw(str_len)
                align()
                ts_origin = reader.read_int32()
                str_len = reader.read_int32()
                ts_log_desc = reader.read_raw(str_len)
                align()
                ts_status = reader.read_uint16()
                align()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_VARY_DATA:
            # net/http/http_vary_data.cc InitFromPickle
            align()
            other_attributes["vary_data"] = reader.read_raw(16)

        host, port = None, None
        try:
            align()
            host_length = reader.read_uint32()
            host = reader.read_raw(host_length).decode("latin-1")
            align()
            port = reader.read_uint16()
        except ValueError:
            # bail out at this point if we've hit eof
            return cls(
                header_declarations, header_attributes, request_time, response_time, certs, host, port,
                other_attributes)

        # todo: there are other fields, they don't look too relevant for us in many cases,
        #  but I can return here to review.

        return cls(
            header_declarations, header_attributes, request_time, response_time, certs, host, port, other_attributes)

    @classmethod
    def from_code_cache_buffer(cls, buffer: bytes):
        """Parse metadata from a Code Cache entry (content/browser/code_cache/generated_code_cache.cc).

        Code Cache entries store the response time as a raw 8-byte little-endian Chrome timestamp
        followed by a validation tag. This is distinct from the HTTP response info pickle format
        used in the main browser cache.

        The tag format is:
          [uint32 LE] data_size - size of the compiled code
          For entries where the compiled code is stored in a separate hash-keyed entry:
            [64 bytes ASCII] hex SHA-256 hash key referencing the data entry
            [remaining bytes] optional V8 compilation metadata
          For entries with inline or no compiled code:
            [remaining bytes] binary V8 compilation metadata
        """
        if len(buffer) < 8:
            raise ValueError(f"Code cache metadata buffer too short ({len(buffer)} bytes, need at least 8)")
        reader = BinaryReader.from_bytes(buffer)
        response_time = reader.read_datetime()
        tag = buffer[8:]

        other_attributes: dict[str, typing.Any] = {}
        if tag:
            other_attributes["code_cache_tag"] = tag
            # Parse the tag: first 4 bytes = data size, then possibly an ASCII hex hash reference
            if len(tag) >= 68:
                try:
                    data_ref = tag[4:68].decode("ascii")
                    if re.match(r"^[0-9A-F]{64}$", data_ref):
                        other_attributes["code_cache_data_ref"] = data_ref
                        other_attributes["code_cache_data_size"] = struct.unpack("<I", tag[:4])[0]
                except (UnicodeDecodeError, struct.error):
                    pass

        return cls(
            set(), {},  # no HTTP headers
            None, response_time,  # no request_time for code cache; only response_time
            [], None, None,  # no certs, no host/port
            other_attributes
        )


#@dataclasses.dataclass(frozen=True)
class CacheFileLocation(ArtifactLocationProtocol):
    def __init__(self, file_name: str, offset: int):
        self._file_name = file_name
        self._offset = offset
    # file_name: str
    # offset: int

    @property
    def file_name(self):
        return self._file_name

    @property
    def source_file(self) -> str:
        return self._file_name

    @property
    def offset(self) -> typing.Optional[int]:
        return self._offset

    @property
    def friendly_string(self) -> str:
        return str(self)

    def __repr__(self):
        return f"<CacheFileLocation; file_name: '{self.file_name}'; offset: {self.offset}"

    def __str__(self):
        return f"{self.file_name} @ {self.offset}"


class ChromiumCache(abc.ABC):
    """
    Abstract base class that both forms of concrete cache types inherit from
    """
    def get_metadata(self, key: typing.Union[str, CacheKey]) -> list[typing.Optional[CachedMetadata]]:  # typing.Optional[CachedMetadata]:
        """
        :param key: the cache key for the entry
        :return: a list of CachedMetadata objects for this key. Most often this list will contain only one entry but
            this library can return old versions of records in some cases. The order of metadata should be the same as
            the records returned by get_cachefile
        """
        raise NotImplementedError()

    def get_cachefile(self, key: typing.Union[str, CacheKey]) -> list[bytes]:  # typing.Optional[bytes]:
        """
        :param key: the cache key for the entry
        :return: a list of bytes objects for this key containing the cached resource. Most often this list will contain
            only one entry but this library can return old versions of records in some cases. The order of data should
            be the same as the records returned by get_metadata
        """
        raise NotImplementedError()

    def get_location_for_metadata(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        """
        :param key: the cache key for the entry
        :return: a list of CacheFileLocation objects for this key's metadata. Most often this list will contain only one
            entry but this library can return old versions of records in some cases. The order of metadata should be the
            same as the records returned by get_metadata
        """
        raise NotImplementedError()

    def get_location_for_cachefile(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        """
        :param key: the cache key for the entry
        :return: a list of CacheFileLocation objects for this key's data. Most often this list will contain only one
            entry but this library can return old versions of records in some cases. The order of metadata should be the
            same as the records returned by get_metadata
        """
        raise NotImplementedError()

    def __enter__(self) -> "ChromiumCache":
        raise NotImplementedError()

    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError()

    def keys(self) -> typing.Iterable[str]:
        """
        :return: yields the cache keys for this cache instance
        """
        raise NotImplementedError()

    def cache_keys(self) -> typing.Iterable[CacheKey]:
        """
        :return: yields the cache keys (as CacheKey objects) for this cache instance
        """
        raise NotImplementedError()


class ChromiumBlockFileCache(ChromiumCache):
    def __init__(self, cache_dir: typing.Union[os.PathLike, str]):
        self._in_dir = pathlib.Path(cache_dir)
        self._index_file = BlockFileIndexFile(self._in_dir / "index")
        self._block_files: dict[int, tuple[BlockFileHeader, typing.BinaryIO]] = {}
        self._keys = self._build_keys()

    def _get_block_file(self, block_file_number: int) -> tuple[BlockFileHeader, typing.BinaryIO]:
        if cached := self._block_files.get(block_file_number):
            return cached

        block_file_stream = (self._in_dir / f"data_{block_file_number}").open("rb")
        header = BlockFileHeader.from_bytes(block_file_stream.read(BlockFileHeader._BLOCK_HEADER_SIZE))
        self._block_files[block_file_number] = (header, block_file_stream)
        return header, block_file_stream

    def _build_keys(self):
        result = {}
        for addr in self._index_file.index:
            while addr.is_initialized:
                if not addr.sanity_check_for_entry():
                    log.warning("Addr skipped as it is not sane for an entry: %s", addr)
                    break
                raw = self.get_data_for_addr(addr)
                try:
                    es = EntryStore.from_bytes(raw)
                except (ValueError, OverflowError):
                    log.warning("EntryStore could not be read and is being skipped")
                    log.debug("Bad EntryStore data: %r", raw)
                    break
                if es.key is not None:
                    key = es.key
                else:
                    key = self.get_data_for_addr(es.long_key_addr).decode("utf-8")[0:es.key_length]

                result[key] = es
                addr = es.next_entry

        return result

    def _get_location(self, key: str, stream_number: int):
        es = self._keys[key]
        addr = es.data_addrs[stream_number]
        if addr.file_type in _BLOCK_FILE_FILETYPE:
            file_name = f"data_{addr.file_selector}"
            block_header, stream = self._get_block_file(addr.file_selector)
            offset = BlockFileHeader._BLOCK_HEADER_SIZE + (block_header.entry_size * addr.block_number)
            return CacheFileLocation(file_name, offset)
        elif addr.file_type == FileType.EXTERNAL:
            file_name = f"f_{addr.external_file_number:06x}"
            return CacheFileLocation(file_name, 0)

        raise ValueError("unexpected file type")

    def get_location_for_metadata(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        if isinstance(key, CacheKey):
            key = key.raw_key
        return [self._get_location(key, 0)]

    def get_location_for_cachefile(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        if isinstance(key, CacheKey):
            key = key.raw_key
        return [self._get_location(key, 1)]

    def get_stream_for_addr(self, addr: Addr) -> typing.BinaryIO:
        if not addr.is_initialized:
            raise ValueError("Addr is not initialized")
        if addr.file_type in _BLOCK_FILE_FILETYPE:
            block_header, stream = self._get_block_file(addr.file_selector)
            stream.seek(BlockFileHeader._BLOCK_HEADER_SIZE + (block_header.entry_size * addr.block_number))
            return io.BytesIO(stream.read(block_header.entry_size * addr.contiguous_blocks))  # slow probably
        elif addr.file_type == FileType.EXTERNAL:
            return (self._in_dir / f"f_{addr.external_file_number:06x}").open("rb")

        raise ValueError("unexpected file type")

    def get_data_for_addr(self, addr: Addr) -> typing.Optional[bytes]:
        if not addr.is_initialized:
            raise ValueError("Addr is not initialized")
        if addr.file_type in _BLOCK_FILE_FILETYPE:
            block_header, stream = self._get_block_file(addr.file_selector)
            stream.seek(BlockFileHeader._BLOCK_HEADER_SIZE + (block_header.entry_size * addr.block_number))
            return stream.read(block_header.entry_size * addr.contiguous_blocks)
        elif addr.file_type == FileType.EXTERNAL:
            external_file_path = self._in_dir / f"f_{addr.external_file_number:06x}"
            if not external_file_path.exists():
                log.warning("External cache file %s is referenced in the data but does not exist in the cache folder",
                            external_file_path)
                return None
            with external_file_path.open("rb") as f:
                return f.read()

        raise ValueError("unexpected file type")

    def get_data_buffer(self, key: typing.Union[str, EntryStore, CacheKey], stream_number: int) -> typing.Optional[bytes]:
        if stream_number < 0 or stream_number > 2:
            raise ValueError("invalid stream number")
        if isinstance(key, EntryStore):
            es = key
        elif isinstance(key, CacheKey):
            es = self._keys[key.raw_key]
        else:
            es = self._keys[key]

        addr = es.data_addrs[stream_number]
        if not addr.is_initialized:
            return None

        data = self.get_data_for_addr(addr)
        if data is None:
            return None

        stream_length = es.data_sizes[stream_number]
        if data is not None and len(data) < stream_length:
            log.debug("Incomplete stream data for EntryStore: %s", es)
            raise ValueError(f"Could not get all of the data for stream {stream_number}")
        data = data[0:stream_length]
        return data

    def get_metadata(self, key: typing.Union[str, EntryStore, CacheKey]) -> list[typing.Optional[CachedMetadata]]:
        buffer = self.get_data_buffer(key, 0)
        if not buffer:
            return [None]
        meta = CachedMetadata.from_buffer(buffer)
        return [meta]

    def get_cachefile(self, key: typing.Union[str, EntryStore, CacheKey]) -> list[bytes]:
        return [self.get_data_buffer(key, 1)]

    def __enter__(self) -> "ChromiumBlockFileCache":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def keys(self) -> typing.Iterable[str]:
        yield from self._keys.keys()

    def cache_keys(self) -> typing.Iterable[CacheKey]:
        for k in self._keys.keys():
            yield CacheKey(k)

    def values(self) -> typing.Iterable[EntryStore]:
        yield from self._keys.values()

    def items(self) -> typing.Iterable[tuple[str, EntryStore]]:
        yield from self._keys.items()

    def __contains__(self, item) -> bool:
        if isinstance(item, CacheKey):
            item = item.raw_key
        return item in self._keys

    def __getitem__(self, item) -> EntryStore:
        if isinstance(item, CacheKey):
            item = item.raw_key
        return self._keys[item]

    def close(self):
        for _, stream in self._block_files.values():
            stream.close()


@dataclasses.dataclass(frozen=True)
class SimpleCacheEOF:
    # net/disk_cache/simple/simple_entry_format.h
    flags: int
    data_crc: int
    stream_size: int

    _SIMPLE_FINAL_MAGIC: typing.ClassVar[int] = 0xf4fa6f45970d41d8  # is written little-endian in the file

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint64()
        if magic != SimpleCacheEOF._SIMPLE_FINAL_MAGIC:
            raise ValueError(f"Invalid magic (expected {SimpleCacheEOF._SIMPLE_FINAL_MAGIC}; got {magic}")

        flags = reader.read_uint32()
        data_crc = reader.read_uint32()
        stream_size = reader.read_uint32()

        return cls(flags, data_crc, stream_size)

    @property
    def has_crc(self):
        return self.flags & 1 > 0

    @property
    def has_key_sha256(self):
        return self.flags & 2 > 0


@dataclasses.dataclass(frozen=True)
class SimpleCacheHeader:
    # net/disk_cache/simple/simple_entry_format.h
    version: int
    key_length: int
    key_hash: int

    _SIMPLE_INITIAL_MAGIC: typing.ClassVar[int] = 0xfcfb6d1ba7725c30  # is written little-endian in the file

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint64()
        if magic != SimpleCacheHeader._SIMPLE_INITIAL_MAGIC:
            raise ValueError(f"Invalid magic (expected {SimpleCacheHeader._SIMPLE_INITIAL_MAGIC}; got {magic}")
        version = reader.read_uint32()
        key_length = reader.read_uint32()
        key_hash = reader.read_uint32()

        if EIGHT_BYTE_PICKLE_ALIGNMENT:
            _ = reader.read_uint32()  # need to align to 8 bytes before we get to the key

        return cls(version, key_length, key_hash)


class SimpleCacheFile:
    # net/disk_cache/simple/simple_entry_format.h

    def __init__(self, cache_file: typing.Union[os.PathLike, str]):
        self._path = pathlib.Path(cache_file)
        self._reader = BinaryReader(self._path.open("rb"))
        self._header = SimpleCacheHeader.from_reader(self._reader)
        self._key = self._reader.read_raw(self._header.key_length).decode("latin-1")

        # Peek forwards - are we at EOF? Sometimes (rarely) you only get a URL
        if self._reader.is_eof:
            self._stream_0_eof = None
            self._stream_1_eof = None
            self._stream_0_start_offset_negative = 0
            self._stream_1_start_offset = 0
            self._stream_1_length = 0

            self._has_data = False
            return
        else:
            self._has_data = True

        # get stream 0 EOF
        self._reader.seek(-SIMPLE_EOF_SIZE, os.SEEK_END)
        self._stream_0_eof = SimpleCacheEOF.from_reader(self._reader)
        self._stream_0_start_offset_negative = -SIMPLE_EOF_SIZE - self._stream_0_eof.stream_size
        if self._stream_0_eof.has_key_sha256:
            self._stream_0_start_offset_negative -= 32

        # get stream 1 EOF
        # the size of the stream 0 eof, the size of the stream 1 eof, the size of stream 0, 32 bytes if there's sha256
        self._reader.seek(-SIMPLE_EOF_SIZE - SIMPLE_EOF_SIZE - self._stream_0_eof.stream_size, os.SEEK_END)
        if self._stream_0_eof.has_key_sha256:
            self._reader.seek(-32, os.SEEK_CUR)
        stream_1_end_offset = self._reader.tell()
        # the eof for stream 1 might contain a stream length, but the comments in simple_entry_format.h say it won't?
        self._stream_1_eof = SimpleCacheEOF.from_reader(self._reader)
        self._stream_1_start_offset = SIMPLE_EOF_SIZE + self._header.key_length  # 20 = header length
        self._stream_1_length = stream_1_end_offset - self._stream_1_start_offset

    def __enter__(self) -> "SimpleCacheFile":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_stream_0(self):
        if self._has_data:
            self._reader.seek(self._stream_0_start_offset_negative, os.SEEK_END)
            return self._reader.read_raw(self._stream_0_eof.stream_size)
        return b""

    def get_stream_1(self):
        if self._has_data:
            self._reader.seek(self._stream_1_start_offset, os.SEEK_SET)
            return self._reader.read_raw(self._stream_1_length)
        return b""

    @property
    def data_start_offset(self):
        return self._stream_1_start_offset

    @property
    def metadata_start_offset_negative(self):
        return self._stream_0_start_offset_negative

    @property
    def path(self) -> pathlib.Path:
        return self._path

    @property
    def key(self) -> str:
        return self._key

    @property
    def key_hash(self) -> int:
        return self._header.key_hash

    def close(self):
        self._reader.close()


@dataclasses.dataclass(frozen=True)
class SimpleCacheEntryInfo:
    """Per-entry metadata from a Simple Cache file's headers and EOF records."""
    source_file: str  # the cache file name on disk (e.g. "00083b49fd824415_0")
    header_version: int  # simple cache format version
    key_hash: int  # uint32 hash of the key from the entry header
    data_size: int  # size of stream 1 (the actual cached resource/code data) in bytes
    metadata_size: int  # size of stream 0 (HTTP metadata or Code Cache metadata) in bytes
    stream_0_crc: typing.Optional[int]  # CRC32 of stream 0 data (None if not present)
    stream_1_crc: typing.Optional[int]  # CRC32 of stream 1 data (None if not present)
    has_key_sha256: bool  # whether the entry includes a SHA-256 of the key


class ChromiumSimpleFileCache(ChromiumCache):
    # net/disk_cache/simple/simple_entry_format.h
    _STREAM_0_1_FILENAME_PATTERN = re.compile(r"^[0-9a-f]{16}_0$")

    def __init__(self, cache_dir: typing.Union[os.PathLike, str]):
        self._cache_dir = pathlib.Path(cache_dir)
        self._entry_info: dict[str, list[SimpleCacheEntryInfo]] = {}
        self._file_lookup = types.MappingProxyType(self._build_keys())

    @property
    def cache_dir(self) -> pathlib.Path:
        return self._cache_dir

    def _build_keys(self) -> dict[str, list[pathlib.Path]]:
        # doing it this way is slow, but saves on having a million file handles open
        lookup: dict[str, list[pathlib.Path]] = {}
        for cache_file in self._cache_dir.iterdir():
            if cache_file.is_file() and ChromiumSimpleFileCache._STREAM_0_1_FILENAME_PATTERN.match(cache_file.name):
                with SimpleCacheFile(cache_file) as cf:
                    # if cf.key in lookup:
                    #     raise ValueError(f"{cf.key} already in lookup (please contact developer)")
                    lookup.setdefault(cf.key, [])
                    lookup[cf.key].append(cache_file)

                    info = SimpleCacheEntryInfo(
                        source_file=cache_file.name,
                        header_version=cf._header.version,
                        key_hash=cf._header.key_hash,
                        data_size=cf._stream_1_length if cf._has_data else 0,
                        metadata_size=cf._stream_0_eof.stream_size if cf._has_data else 0,
                        stream_0_crc=cf._stream_0_eof.data_crc if cf._has_data and cf._stream_0_eof.has_crc else None,
                        stream_1_crc=cf._stream_1_eof.data_crc if cf._has_data and cf._stream_1_eof.has_crc else None,
                        has_key_sha256=cf._stream_0_eof.has_key_sha256 if cf._has_data else False,
                    )
                    self._entry_info.setdefault(cf.key, [])
                    self._entry_info[cf.key].append(info)

        return lookup

    def get_location_for_metadata(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            file_length = file.stat().st_size
            with SimpleCacheFile(file) as cf:
                offset = file_length + cf.metadata_start_offset_negative
            result.append(CacheFileLocation(file.name, offset))
        return result

    def get_location_for_cachefile(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cf:
                offset = cf.data_start_offset
            result.append(CacheFileLocation(file.name, offset))
        return result

    def get_metadata(self, key: typing.Union[str, CacheKey]) -> list[typing.Optional[CachedMetadata]]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cf:
                buffer = cf.get_stream_0()
                if buffer:
                    try:
                        result.append(CachedMetadata.from_buffer(buffer))
                    except ValueError:
                        # Not an HTTP response info pickle; try Code Cache format
                        # (content/browser/code_cache/generated_code_cache.cc)
                        try:
                            result.append(CachedMetadata.from_code_cache_buffer(buffer))
                        except ValueError:
                            result.append(None)
                else:
                    result.append(None)
        return result

    def get_cachefile(self, key: typing.Union[str, CacheKey]) -> list[bytes]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cf:
                result.append(cf.get_stream_1())
        return result

    def get_entry_info(self, key: typing.Union[str, CacheKey]) -> list[SimpleCacheEntryInfo]:
        """Get file-level entry info (source file, data size, CRCs, etc.) for a cache key."""
        if isinstance(key, CacheKey):
            key = key.raw_key
        return self._entry_info[key]

    def __enter__(self) -> "ChromiumCache":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def close(self):
        pass

    def keys(self) -> typing.Iterable[str]:
        yield from self._file_lookup.keys()

    def cache_keys(self) -> typing.Iterable[CacheKey]:
        for k in self._file_lookup.keys():
            yield CacheKey(k)

    def get_file_for_key(self, key: typing.Union[str, CacheKey]) -> list[str]:
        if isinstance(key, CacheKey):
            key = key.raw_key
        return [x.name for x in self._file_lookup[key]]


def guess_cache_class(
        cache_dir: typing.Optional[typing.Union[pathlib.Path, os.PathLike]]) \
        -> typing.Optional[typing.Type[typing.Union[ChromiumBlockFileCache, ChromiumSimpleFileCache]]]:
    cache_dir = pathlib.Path(cache_dir)
    data_files = {"data_0", "data_1", "data_2", "data_3"}

    for file in cache_dir.iterdir():
        # multiple tests to we can return as soon as possible
        if file.name == "index-dir":
            return ChromiumSimpleFileCache
        elif file.name in data_files:
            return ChromiumBlockFileCache
        elif re.match(r"f_[0-9a-f]{6}", file.name):
            return ChromiumBlockFileCache
        elif re.match(r"^[0-9a-f]{16}_0$", file.name):
            return ChromiumSimpleFileCache

    return None


def main(args):
    import csv
    import hashlib
    import mimetypes
    import brotli
    import gzip
    import zstd

    in_cache_dir = pathlib.Path(args[0])
    out_dir = pathlib.Path(args[1])
    cache_out_dir = out_dir / "cache_files"

    if not in_cache_dir.is_dir():
        raise ValueError("Input directory is not a directory or does not exist")

    if out_dir.exists():
        raise ValueError("Output directory already exists")

    out_dir.mkdir()
    cache_out_dir.mkdir()

    default_row_headers = ["file_hash", "key", "request_time", "response_time", "date"]
    dynamic_row_headers = set()
    rows: list[dict] = []

    cache_type = guess_cache_class(in_cache_dir)
    if cache_type is None:
        raise ValueError("Could not detect Chrome cache type")

    with cache_type(in_cache_dir) as cache:
        for key in cache.keys():
            out_extension = ""
            content_encoding = ""
            row = {"key": key}
            rows.append(row)

            metas = cache.get_metadata(key)
            datas = cache.get_cachefile(key)

            if len(metas) != len(datas):
                raise ValueError("Metadata records count does not match data records count")

            for meta, data in zip(metas, datas):
                if meta is not None:
                    row["request_time"] = meta.request_time
                    row["response_time"] = meta.response_time
                    for attribute, value in meta.http_header_attributes:
                        dynamic_row_headers.add(attribute)
                        if attribute in row:
                            row[attribute] += f"; {value}"
                        else:
                            row[attribute] = value

                    if mime := meta.get_attribute("content-type"):
                        out_extension = mimetypes.guess_extension(mime[0]) or ""

                    content_encoding = (meta.get_attribute("content-encoding") or [""])[0]

                #data = cache.get_cachefile(key)
                if data is not None:
                    if content_encoding.strip() == "gzip":
                        try:
                            data = gzip.decompress(data)
                        except (EOFError, gzip.BadGzipFile) as ex:
                            print(f"Warning: could not decompress data for key: \"{key}\"; reason: {ex}")
                    elif content_encoding.strip() == "br":
                        try:
                            data = brotli.decompress(data)
                        except brotli.error as ex:
                            print(f"Warning: could not decompress data for key: \"{key}\"; reason: {ex}")
                    elif content_encoding.strip() == "deflate":
                        try:
                            data = zlib.decompress(data, -zlib.MAX_WBITS)  # suppress trying to read a header
                        except zlib.error as ex:
                            print(f"Warning: could not decompress data for key: \"{key}\"; reason: {ex}")
                    elif content_encoding.strip() == "zstd":
                        try:
                            data = zstd.decompress(data)
                        except zstd.Error as ex:
                            print(f"Warning: could not decompress data for key: \"{key}\"; reason: {ex}")
                    elif content_encoding.strip() != "":
                        print(f"Warning: unknown content-encoding: {content_encoding}")

                    h = hashlib.sha256()
                    h.update(data)
                    cache_file_hash = h.hexdigest()
                    row["file_hash"] = cache_file_hash
                    with (cache_out_dir / (cache_file_hash + out_extension)).open("wb") as out:
                        out.write(data)
                else:
                    row["file_hash"] = "<No cache file data>"

    csv_out_f = (out_dir / "cache_report.csv").open("wt", encoding="utf-8", newline="")
    csv_out_f.write("\ufeff")
    csv_out = csv.DictWriter(
        csv_out_f, fieldnames=default_row_headers + sorted(dynamic_row_headers), dialect=csv.excel,
        quoting=csv.QUOTE_ALL, quotechar="\"", escapechar="\\")
    csv_out.writeheader()
    for row in rows:
        csv_out.writerow(row)

    csv_out_f.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <cache input dir> <out dir>")
        exit(1)
    main(sys.argv[1:])
