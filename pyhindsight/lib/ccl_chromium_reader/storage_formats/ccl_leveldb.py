"""
Copyright 2020-2021, CCL Forensics

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

import typing
import struct
import re
import os
import io
import itertools
import logging
import pathlib
import dataclasses
import enum
from collections import namedtuple
from types import MappingProxyType

from ... import ccl_simplesnappy

__version__ = "0.4"
__description__ = "A module for reading LevelDB databases"
__contact__ = "Alex Caithness"

log = logging.getLogger(__name__)


def _read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False) -> typing.Optional[typing.Tuple[int, bytes]]:
    """Read varint from a stream.
    If the read is successful: returns a tuple of the (unsigned) value and the raw bytes making up that varint,
    otherwise returns None.
    Can be switched to limit the varint to 32 bit."""
    # this only outputs unsigned
    i = 0
    result = 0
    underlying_bytes = []
    limit = 5 if is_google_32bit else 10
    while i < limit:
        raw = stream.read(1)
        if len(raw) < 1:
            return None
        tmp, = raw
        underlying_bytes.append(tmp)
        result |= ((tmp & 0x7f) << (i * 7))
        if (tmp & 0x80) == 0:
            break
        i += 1
    return result, bytes(underlying_bytes)


def read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False) -> typing.Optional[int]:
    """Convenience version of _read_le_varint that only returns the value or None"""
    x = _read_le_varint(stream, is_google_32bit=is_google_32bit)
    if x is None:
        return None
    else:
        return x[0]


def read_length_prefixed_blob(stream: typing.BinaryIO) -> bytes:
    """Reads a blob of data which is prefixed with a varint length"""
    length = read_le_varint(stream)
    data = stream.read(length)
    if len(data) != length:
        raise ValueError(f"Could not read all data (expected {length}, got {len(data)}")
    return data


@dataclasses.dataclass(frozen=True)
class BlockHandle:
    """See: https://github.com/google/leveldb/blob/master/doc/table_format.md
    A BlockHandle contains an offset and length of a block in an ldb table file"""
    offset: int
    length: int

    @classmethod
    def from_stream(cls, stream: typing.BinaryIO) -> "BlockHandle":
        return cls(read_le_varint(stream), read_le_varint(stream))

    @classmethod
    def from_bytes(cls, data: bytes) -> "BlockHandle":
        with io.BytesIO(data) as stream:
            return BlockHandle.from_stream(stream)


@dataclasses.dataclass(frozen=True)
class RawBlockEntry:
    """Raw key, value for a record in a LDB file Block, along with the offset within the block from which it came from
    See: https://github.com/google/leveldb/blob/master/doc/table_format.md"""
    key: bytes
    value: bytes
    block_offset: int


class FileType(enum.Enum):
    Ldb = 1
    Log = 2


class KeyState(enum.Enum):
    Deleted = 0
    Live = 1
    Unknown = 2


@dataclasses.dataclass(frozen=True)
class Record:
    """A record from leveldb; includes details of the origin file, state, etc."""

    key: bytes
    value: bytes
    seq: int
    state: KeyState
    file_type: FileType
    origin_file: os.PathLike
    offset: int
    was_compressed: bool

    @property
    def user_key(self) -> bytes:
        """Returns the "userkey" which omits the metadata bytes which may reside at the end of the raw key"""
        if self.file_type == FileType.Ldb:
            if len(self.key) < 8:
                return self.key
            else:
                return self.key[0:-8]
        else:
            return self.key

    @classmethod
    def ldb_record(cls, key: bytes, value: bytes, origin_file: os.PathLike,
                   offset: int, was_compressed: bool) -> "Record":
        seq = (struct.unpack("<Q", key[-8:])[0]) >> 8
        if len(key) > 8:
            state = KeyState.Deleted if key[-8] == 0 else KeyState.Live
        else:
            state = KeyState.Unknown
        return cls(key, value, seq, state, FileType.Ldb, origin_file, offset, was_compressed)

    @classmethod
    def log_record(cls, key: bytes, value: bytes, seq: int, state: KeyState,
                   origin_file: os.PathLike, offset: int) -> "Record":
        return cls(key, value, seq, state, FileType.Log, origin_file, offset, False)


class Block:
    """Block from an .lldb (table) file. See: https://github.com/google/leveldb/blob/master/doc/table_format.md"""
    def __init__(self, raw: bytes, was_compressed: bool, origin: "LdbFile", offset: int):
        self._raw = raw
        self.was_compressed = was_compressed
        self.origin = origin
        self.offset = offset

        self._restart_array_count, = struct.unpack("<I", self._raw[-4:])
        self._restart_array_offset = len(self._raw) - (self._restart_array_count + 1) * 4

    def get_restart_offset(self, index) -> int:
        offset = self._restart_array_offset + (index * 4)
        return struct.unpack("<i", self._raw[offset: offset + 4])[0]

    def get_first_entry_offset(self) -> int:
        return self.get_restart_offset(0)

    def __iter__(self) -> typing.Iterable[RawBlockEntry]:
        offset = self.get_first_entry_offset()
        with io.BytesIO(self._raw) as buff:
            buff.seek(offset)

            key = b""

            while buff.tell() < self._restart_array_offset:
                start_offset = buff.tell()
                shared_length = read_le_varint(buff, is_google_32bit=True)
                non_shared_length = read_le_varint(buff, is_google_32bit=True)
                value_length = read_le_varint(buff, is_google_32bit=True)

                # sense check
                if offset >= self._restart_array_offset:
                    raise ValueError("Reading start of entry past the start of restart array")
                if shared_length > len(key):
                    raise ValueError("Shared key length is larger than the previous key")

                key = key[:shared_length] + buff.read(non_shared_length)
                value = buff.read(value_length)

                yield RawBlockEntry(key, value, start_offset)


class LdbFile:
    """A leveldb table (.ldb or .sst) file."""
    BLOCK_TRAILER_SIZE = 5
    FOOTER_SIZE = 48
    MAGIC = 0xdb4775248b80fb57

    def __init__(self, file: pathlib.Path):
        if not file.exists():
            raise FileNotFoundError(file)

        self.path = file
        self.file_no = int(file.stem, 16)

        self._f = file.open("rb")
        self._f.seek(-LdbFile.FOOTER_SIZE, os.SEEK_END)

        self._meta_index_handle = BlockHandle.from_stream(self._f)
        self._index_handle = BlockHandle.from_stream(self._f)
        self._f.seek(-8, os.SEEK_END)
        magic, = struct.unpack("<Q", self._f.read(8))
        if magic != LdbFile.MAGIC:
            raise ValueError(f"Invalid magic number in {file}")

        self._index = self._read_index()

    def _read_block(self, handle: BlockHandle) -> Block:
        # block is the size in the blockhandle plus the trailer
        # the trailer is 5 bytes long.
        # idx  size  meaning
        # 0    1     CompressionType (0 = none, 1 = snappy)
        # 1    4     CRC32

        self._f.seek(handle.offset)
        raw_block = self._f.read(handle.length)
        trailer = self._f.read(LdbFile.BLOCK_TRAILER_SIZE)

        if len(raw_block) != handle.length or len(trailer) != LdbFile.BLOCK_TRAILER_SIZE:
            raise ValueError(f"Could not read all of the block at offset {handle.offset} in file {self.path}")

        is_compressed = trailer[0] != 0
        if is_compressed:
            with io.BytesIO(raw_block) as buff:
                raw_block = ccl_simplesnappy.decompress(buff)

        return Block(raw_block, is_compressed, self, handle.offset)

    def _read_index(self) -> typing.Tuple[typing.Tuple[bytes, BlockHandle], ...]:
        index_block = self._read_block(self._index_handle)
        # key is earliest key, value is BlockHandle to that data block
        return tuple((entry.key, BlockHandle.from_bytes(entry.value))
                     for entry in index_block)

    def __iter__(self) -> typing.Iterable[Record]:
        """Iterate Records in this Table file"""
        for block_key, handle in self._index:
            block = self._read_block(handle)
            for entry in block:
                yield Record.ldb_record(
                    entry.key, entry.value, self.path,
                    block.offset if block.was_compressed else block.offset + entry.block_offset,
                    block.was_compressed)

    def close(self):
        self._f.close()


class LogEntryType(enum.IntEnum):
    Zero = 0
    Full = 1
    First = 2
    Middle = 3
    Last = 4


@dataclasses.dataclass(frozen=True)
class LogDamage:
    """A stretch of a log or manifest file that could not be read and was skipped"""
    offset: int  # file offset where the skipped data starts
    length: int  # bytes skipped
    reason: str


def _record_damage(damage: typing.List[LogDamage], path: pathlib.Path, offset: int, length: int, reason: str):
    log.warning("Damaged data at offset %d in %s (%d bytes skipped): %s", offset, path, length, reason)
    damage.append(LogDamage(offset, length, reason))


def _read_log_batches(raw_blocks: typing.Iterable[bytes], path: pathlib.Path,
                      damage: typing.List[LogDamage]) -> typing.Iterable[typing.Tuple[int, bytes]]:
    """
    Reassemble the batches in a file in the log format (a .log file or a manifest) from its blocks,
    yielding the file offset of each batch's data and the data.

    This follows leveldb's own reader (db/log_reader.cc): when a block cannot be read, the rest of it
    is skipped and reading resumes at the next block, so damage costs the records it touches rather
    than the rest of the file. Each skip is logged and added to `damage`. As in leveldb, zero-filled
    space (left when a file is preallocated, or when a crash cuts a write short) ends the block
    quietly, and is only counted as damage when it interrupts a record or has data after it.
    See: https://github.com/google/leveldb/blob/main/doc/log_format.md
    """
    def skip(offset, length, reason):
        _record_damage(damage, path, offset, length, reason)

    in_record = False
    record_start = 0  # file offset of the header of the current record's first fragment
    data_offset = 0  # file offset of the current record's data, as yielded
    fragments = []

    def abandon_record(end_offset, reason):
        nonlocal in_record
        if in_record:
            skip(record_start, end_offset - record_start, reason)
            in_record = False

    end_of_file = 0
    for block_offset, block in zip(itertools.count(0, LogFile.LOG_BLOCK_SIZE), raw_blocks):
        end_of_file = block_offset + len(block)
        at_end_of_file = len(block) < LogFile.LOG_BLOCK_SIZE
        pos = 0
        # Fewer than LOG_ENTRY_HEADER_SIZE bytes left in a block are padding.
        while len(block) - pos >= LogFile.LOG_ENTRY_HEADER_SIZE:
            header_offset = block_offset + pos
            crc, length, block_type = struct.unpack_from("<IHB", block, pos)
            data_start = pos + LogFile.LOG_ENTRY_HEADER_SIZE

            if data_start + length > len(block):
                # A fragment never crosses a block boundary, so the header is damaged or, at the end of
                # the file, the write was not finished. Either way nothing more can be read from the block.
                abandon_record(header_offset, "record interrupted by damaged data")
                skip(header_offset, len(block) - pos,
                     "incomplete record at the end of the file" if at_end_of_file
                     else "record length runs past the end of its block")
                break

            if block_type == LogEntryType.Zero and length == 0:
                abandon_record(header_offset, "record interrupted by zero-filled space")
                # leveldb drops the rest of the block without a word. If anything but zeros
                # follows, that is data being skipped, so say so.
                if block[pos:].strip(b"\x00"):
                    skip(header_offset, len(block) - pos, "data after zero-filled space")
                break

            data = block[data_start:data_start + length]
            pos = data_start + length

            if block_type == LogEntryType.Full:
                abandon_record(header_offset, "record without its last fragment")
                yield block_offset + data_start, data
            elif block_type == LogEntryType.First:
                abandon_record(header_offset, "record without its last fragment")
                in_record = True
                record_start = header_offset
                data_offset = block_offset + data_start
                fragments = [data]
            elif block_type in (LogEntryType.Middle, LogEntryType.Last):
                if not in_record:
                    skip(header_offset, LogFile.LOG_ENTRY_HEADER_SIZE + length,
                         "fragment without the start of its record")
                    continue
                fragments.append(data)
                if block_type == LogEntryType.Last:
                    in_record = False
                    yield data_offset, b"".join(fragments)
            else:
                abandon_record(header_offset, "record interrupted by damaged data")
                skip(header_offset, LogFile.LOG_ENTRY_HEADER_SIZE + length, f"unknown record type {block_type}")

    abandon_record(end_of_file, "incomplete record at the end of the file")


class LogFile:
    """A levelDb log (.log) file"""
    LOG_ENTRY_HEADER_SIZE = 7
    LOG_BLOCK_SIZE = 32768

    def __init__(self, file: pathlib.Path):
        if not file.exists():
            raise FileNotFoundError(file)

        self.path = file
        self.file_no = int(file.stem, 16)

        # What the last iteration of this file had to skip; empty if it read cleanly.
        self.damage: typing.List[LogDamage] = []

        self._f = file.open("rb")

    def _get_raw_blocks(self) -> typing.Iterable[bytes]:
        self._f.seek(0)

        while chunk := self._f.read(LogFile.LOG_BLOCK_SIZE):
            yield chunk

    def _get_batches(self) -> typing.Iterable[typing.Tuple[int, bytes]]:
        yield from _read_log_batches(self._get_raw_blocks(), self.path, self.damage)

    @staticmethod
    def _read_batch_entry(buff: typing.BinaryIO) -> typing.Optional[typing.Tuple[KeyState, bytes, bytes]]:
        """Read one entry of a write batch, or return None if the batch ends before it does."""
        raw_state = buff.read(1)
        # leveldb writes only these two tags; anything else means the batch is damaged.
        if len(raw_state) < 1 or raw_state[0] not in (KeyState.Deleted.value, KeyState.Live.value):
            return None
        state = KeyState(raw_state[0])

        key_length = read_le_varint(buff, is_google_32bit=True)
        if key_length is None:
            return None
        key = buff.read(key_length)
        if len(key) < key_length:
            return None

        value = b""
        if state != KeyState.Deleted:
            value_length = read_le_varint(buff, is_google_32bit=True)
            if value_length is None:
                return None
            value = buff.read(value_length)
            if len(value) < value_length:
                return None

        return state, key, value

    def __iter__(self) -> typing.Iterable[Record]:
        """Iterate Records in this Log file. Afterwards, `damage` lists anything that had to be skipped."""
        self.damage.clear()
        for batch_offset, batch in self._get_batches():
            # as per write_batch and write_batch_internal
            # offset       length      description
            # 0            8           (u?)int64 Sequence number
            # 8            4           (u?)int32 Count - the log batch can contain multple entries
            #
            #         Then Count * the following:
            #
            # 12           1           ValueType (KeyState as far as this library is concerned)
            # 13           1-4         VarInt32 length of key
            # ...          ...         Key data
            # ...          1-4         VarInt32 length of value
            # ...          ...         Value data

            with io.BytesIO(batch) as buff:  # it's just easier this way
                header = buff.read(12)
                if len(header) < 12:
                    _record_damage(self.damage, self.path, batch_offset, len(batch),
                                   "write batch shorter than its 12-byte header")
                    continue
                seq, count = struct.unpack("<QI", header)

                for i in range(count):
                    start_offset = batch_offset + buff.tell()
                    entry = self._read_batch_entry(buff)
                    if entry is None:
                        # As in leveldb, the entries before this one stand.
                        _record_damage(self.damage, self.path, start_offset, len(batch) - (start_offset - batch_offset),
                                       f"write batch cut short at entry {i + 1} of {count}")
                        break
                    state, key, value = entry

                    yield Record.log_record(key, value, seq + i, state, self.path, start_offset)

    def close(self):
        self._f.close()


class VersionEditTag(enum.IntEnum):
    """
    See: https://github.com/google/leveldb/blob/master/db/version_edit.cc
    """
    Comparator = 1,
    LogNumber = 2,
    NextFileNumber = 3,
    LastSequence = 4,
    CompactPointer = 5,
    DeletedFile = 6,
    NewFile = 7,
    # 8 was used for large value refs
    PrevLogNumber = 9


@dataclasses.dataclass(frozen=True)
class VersionEdit:
    """
    See:
    https://github.com/google/leveldb/blob/master/db/version_edit.h
    https://github.com/google/leveldb/blob/master/db/version_edit.cc
    """
    comparator: str = None
    log_number: int = None
    prev_log_number: int = None
    last_sequence: int = None
    next_file_number: int = None
    compaction_pointers: typing.Tuple[typing.Any] = tuple()
    deleted_files: typing.Tuple[typing.Any] = tuple()
    new_files: typing.Tuple[typing.Any] = tuple()

    @classmethod
    def from_buffer(cls, buffer: bytes):
        comparator = None
        log_number = None
        prev_log_number = None
        last_sequence = None
        next_file_number = None
        compaction_pointers = []
        deleted_files = []
        new_files = []

        compaction_pointer_nt = namedtuple("CompactionPointer", ["level", "pointer"])
        deleted_file_nt = namedtuple("DeletedFile", ["level", "file_no"])
        new_file_nt = namedtuple("NewFile", ["level", "file_no", "file_size", "smallest_key", "largest_key"])

        with io.BytesIO(buffer) as b:
            while b.tell() < len(buffer) - 1:
                tag = read_le_varint(b, is_google_32bit=True)

                if tag == VersionEditTag.Comparator:
                    comparator = read_length_prefixed_blob(b).decode("utf-8")
                elif tag == VersionEditTag.LogNumber:
                    log_number = read_le_varint(b)
                elif tag == VersionEditTag.PrevLogNumber:
                    prev_log_number = read_le_varint(b)
                elif tag == VersionEditTag.NextFileNumber:
                    next_file_number = read_le_varint(b)
                elif tag == VersionEditTag.LastSequence:
                    last_sequence = read_le_varint(b)
                elif tag == VersionEditTag.CompactPointer:
                    level = read_le_varint(b, is_google_32bit=True)
                    compaction_pointer = read_length_prefixed_blob(b)
                    compaction_pointers.append(compaction_pointer_nt(level, compaction_pointer))
                elif tag == VersionEditTag.DeletedFile:
                    level = read_le_varint(b, is_google_32bit=True)
                    file_no = read_le_varint(b)
                    deleted_files.append(deleted_file_nt(level, file_no))
                elif tag == VersionEditTag.NewFile:
                    level = read_le_varint(b, is_google_32bit=True)
                    file_no = read_le_varint(b)
                    file_size = read_le_varint(b)
                    smallest = read_length_prefixed_blob(b)
                    largest = read_length_prefixed_blob(b)
                    new_files.append(new_file_nt(level, file_no, file_size, smallest, largest))

        return cls(comparator, log_number, prev_log_number, last_sequence, next_file_number, tuple(compaction_pointers),
            tuple(deleted_files), tuple(new_files))


class ManifestFile:
    """
    Represents a manifest file which contains database metadata.
    Manifest files are, at a high level, formatted like a log file in terms of the block and batch format,
    but the data within the batches follow their own format.

    Main use is to identify the level of files, use `file_to_level` property to look up levels based on file no.

    See:
    https://github.com/google/leveldb/blob/master/db/version_edit.h
    https://github.com/google/leveldb/blob/master/db/version_edit.cc
    """

    MANIFEST_FILENAME_PATTERN = "MANIFEST-([0-9A-F]{6})"

    def __init__(self, path: pathlib.Path):
        if match := re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, path.name):
            self.file_no = int(match.group(1))
        else:
            raise ValueError("Invalid name for Manifest")

        self._f = path.open("rb")
        self.path = path

        # What the last iteration of this file had to skip; empty if it read cleanly.
        self.damage: typing.List[LogDamage] = []

        self.file_to_level = {}
        for edit in self:
            if edit.new_files:
                for nf in edit.new_files:
                    self.file_to_level[nf.file_no] = nf.level

        self.file_to_level = MappingProxyType(self.file_to_level)

    def _get_raw_blocks(self) -> typing.Iterable[bytes]:
        self._f.seek(0)

        while chunk := self._f.read(LogFile.LOG_BLOCK_SIZE):
            yield chunk

    def _get_batches(self) -> typing.Iterable[typing.Tuple[int, bytes]]:
        yield from _read_log_batches(self._get_raw_blocks(), self.path, self.damage)

    def __iter__(self):
        self.damage.clear()
        for batch_offset, batch in self._get_batches():
            yield VersionEdit.from_buffer(batch)

    def close(self):
        self._f.close()


class RawLevelDb:
    DATA_FILE_PATTERN = r"[0-9]{6}\.(ldb|log|sst)"

    def __init__(self, in_dir: os.PathLike):

        self._in_dir = pathlib.Path(in_dir)
        if not self._in_dir.is_dir():
            raise ValueError("in_dir is not a directory")

        self._files = []
        latest_manifest = (0, None)
        for file in self._in_dir.iterdir():
            if file.is_file() and re.match(RawLevelDb.DATA_FILE_PATTERN, file.name):
                if file.suffix.lower() == ".log":
                    self._files.append(LogFile(file))
                elif file.suffix.lower() == ".ldb" or file.suffix.lower() == ".sst":
                    self._files.append(LdbFile(file))
            if file.is_file() and re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, file.name):
                manifest_no = int(re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, file.name).group(1), 16)
                if latest_manifest[0] < manifest_no:
                    latest_manifest = (manifest_no, file)

        self.manifest = ManifestFile(latest_manifest[1]) if latest_manifest[1] is not None else None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def in_dir_path(self) -> pathlib.Path:
        return self._in_dir

    def iterate_records_raw(self, *, reverse=False) -> typing.Iterable[Record]:
        for file_containing_records in sorted(self._files, reverse=reverse, key=lambda x: x.file_no):
            yield from file_containing_records

    def close(self):
        for file in self._files:
            file.close()
        if self.manifest:
            self.manifest.close()
