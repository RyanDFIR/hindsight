"""
Copyright 2020-2024, CCL Forensics

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

import sys
import struct
import os
import pathlib
import io
import enum
import datetime
import dataclasses
import types
import typing

from .. import ccl_simplesnappy

from .structures import ArtifactLocation
from .storage_formats import ccl_leveldb
from .serialization_formats import ccl_blink_value_deserializer, ccl_v8_value_deserializer

__version__ = "0.21"
__description__ = "Module for reading Chromium IndexedDB LevelDB databases."
__contact__ = "Alex Caithness"


# TODO: need to go through and ensure that we have endianness right in all cases
#  (it should sit behind a switch for integers, fixed for most other stuff)


def _read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False) -> typing.Optional[tuple[int, bytes]]:
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
    x = _read_le_varint(stream, is_google_32bit=is_google_32bit)
    if x is None:
        return None
    else:
        return x[0]


def _le_varint_from_bytes(data: bytes) -> typing.Optional[tuple[int, bytes]]:
    with io.BytesIO(data) as buff:
        return _read_le_varint(buff)


def le_varint_from_bytes(data: bytes) -> typing.Optional[int]:
    with io.BytesIO(data) as buff:
        return read_le_varint(buff)


def decode_truncated_int(data: bytes) -> int:
    # See: /content/browser/indexed_db/indexed_db_leveldb_coding.h EncodeInt()
    # "// Unlike EncodeVarInt, this is a 'dumb' implementation of a variable int
    # // encoder. It writes, little-endian', until there are no more '1' bits in the
    # // number. The Decoder must know how to calculate the size of the encoded int,
    # // typically by having this reside at the end of the value or key."
    if len(data) == 0:
        raise ValueError("No data to decode")
    result = 0
    for i, b in enumerate(data):
        result |= (b << (i * 8))
    return result


class IdbKeyType(enum.IntEnum):
    Null = 0
    String = 1
    Date = 2
    Number = 3
    Array = 4
    MinKey = 5
    Binary = 6


class IdbKey:
    # See: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_leveldb_coding.cc
    def __init__(self, buffer: bytes):
        self.raw_key = buffer
        self.key_type = IdbKeyType(buffer[0])
        raw_key = buffer[1:]

        if self.key_type == IdbKeyType.Null:
            self.value = None
            self._raw_length = 1
        elif self.key_type == IdbKeyType.String:
            str_len, varint_raw = _le_varint_from_bytes(raw_key)
            self.value = raw_key[len(varint_raw):len(varint_raw) + str_len * 2].decode("utf-16-be")
            self._raw_length = 1 + len(varint_raw) + str_len * 2
        elif self.key_type == IdbKeyType.Date:
            ts, = struct.unpack("<d", raw_key[0:8])
            self.value = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=ts)
            self._raw_length = 9
        elif self.key_type == IdbKeyType.Number:
            self.value = struct.unpack("<d", raw_key[0:8])[0]
            self._raw_length = 9
        elif self.key_type == IdbKeyType.Array:
            array_count, varint_raw = _le_varint_from_bytes(raw_key)
            raw_key = raw_key[len(varint_raw):]
            self.value = []
            self._raw_length = 1 + len(varint_raw)
            for i in range(array_count):
                key = IdbKey(raw_key)
                raw_key = raw_key[key._raw_length:]
                self._raw_length += key._raw_length
                self.value.append(key)
            self.value = tuple(self.value)
        elif self.key_type == IdbKeyType.MinKey:
            # TODO: not sure what this actually implies, the code doesn't store a value
            self.value = None
            self._raw_length = 1
            raise NotImplementedError()
        elif self.key_type == IdbKeyType.Binary:
            bin_len, varint_raw = _le_varint_from_bytes(raw_key)
            self.value = raw_key[len(varint_raw):len(varint_raw) + bin_len]
            self._raw_length = 1 + len(varint_raw) + bin_len
        else:
            raise ValueError()  # Shouldn't happen

        # trim the raw_key in case this is an inner key:
        self.raw_key = self.raw_key[0: self._raw_length]

    def __repr__(self):
        return f"<IdbKey {self.value}>"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if not isinstance(other, IdbKey):
            raise NotImplementedError()
        return self.raw_key == other.raw_key

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return self.raw_key.__hash__()


class IndexedDBExternalObjectType(enum.IntEnum):
    # see: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_external_object.h
    Blob = 0
    File = 1
    NativeFileSystemHandle = 2


class IndexedDBExternalObject:
    # see: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_backing_store.cc
    # for encoding.

    def __init__(self, object_type: IndexedDBExternalObjectType, blob_number: typing.Optional[int],
                 mime_type: typing.Optional[str], size: typing.Optional[int],
                 file_name: typing.Optional[str], last_modified: typing.Optional[datetime.datetime],
                 native_file_token: typing.Optional):
        self.object_type = object_type
        self.blob_number = blob_number
        self.mime_type = mime_type
        self.size = size
        self.file_name = file_name
        self.last_modified = last_modified
        self.native_file_token = native_file_token

    @classmethod
    def from_stream(cls, stream: typing.BinaryIO):
        blob_type = IndexedDBExternalObjectType(stream.read(1)[0])
        if blob_type in (IndexedDBExternalObjectType.Blob, IndexedDBExternalObjectType.File):
            blob_number = read_le_varint(stream)
            mime_type_length = read_le_varint(stream)
            mime_type = stream.read(mime_type_length * 2).decode("utf-16-be")
            data_size = read_le_varint(stream)

            if blob_type == IndexedDBExternalObjectType.File:
                file_name_length = read_le_varint(stream)
                file_name = stream.read(file_name_length * 2).decode("utf-16-be")
                x, x_raw = _read_le_varint(stream)
                last_modified_td = datetime.timedelta(microseconds=x)
                last_modified = datetime.datetime(1601, 1, 1) + last_modified_td
                return cls(blob_type, blob_number, mime_type, data_size, file_name,
                           last_modified, None)
            else:
                return cls(blob_type, blob_number, mime_type, data_size, None, None, None)
        else:
            raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class DatabaseId:
    dbid_no: int
    origin: str
    name: str


class GlobalMetadata:
    def __init__(self, raw_meta_dict: dict):
        # TODO: more of these meta types if required
        self.backing_store_schema_version = None
        if raw_schema_version := raw_meta_dict.get("\x00\x00\x00\x00\x00"):
            self.backing_store_schema_version = le_varint_from_bytes(raw_schema_version)

        self.max_allocated_db_id = None
        if raw_max_db_id := raw_meta_dict.get("\x00\x00\x00\x00\x01"):
            self.max_allocated_db_id = le_varint_from_bytes(raw_max_db_id)

        database_ids_raw = (raw_meta_dict[x] for x in raw_meta_dict
                            if x.startswith(b"\x00\x00\x00\x00\xc9"))

        dbids = []
        for dbid_rec in database_ids_raw:
            with io.BytesIO(dbid_rec.key[5:]) as buff:
                origin_length = read_le_varint(buff)
                origin = buff.read(origin_length * 2).decode("utf-16-be")
                db_name_length = read_le_varint(buff)
                db_name = buff.read(db_name_length * 2).decode("utf-16-be")

            db_id_no = decode_truncated_int(dbid_rec.value)

            dbids.append(DatabaseId(db_id_no, origin, db_name))

        self._db_ids = tuple(dbids)
        self._db_ids_lookup = types.MappingProxyType({x.dbid_no: x for x in self._db_ids})

    @property
    def db_ids(self) -> tuple[DatabaseId, ...]:
        return self._db_ids

    @property
    def db_ids_lookup(self) -> dict[int: DatabaseId]:
        return self._db_ids_lookup


class DatabaseMetadataType(enum.IntEnum):
    OriginName = 0  # String
    DatabaseName = 1  # String
    IdbVersionString = 2  # String (and obsolete)
    MaximumObjectStoreId = 3  # Int
    IdbVersion = 4  # Varint
    BlobNumberGeneratorCurrentNumber = 5  # Varint


class DatabaseMetadata:
    def __init__(self, raw_meta: dict):
        self._metas = types.MappingProxyType(raw_meta)

    def get_meta(self, db_id: int, meta_type: DatabaseMetadataType) -> typing.Optional[typing.Union[str, int]]:
        record = self._metas.get((db_id, meta_type))
        if not record:
            return None

        if meta_type == DatabaseMetadataType.MaximumObjectStoreId:
            return decode_truncated_int(record.value)

        # TODO
        raise NotImplementedError()


class ObjectStoreMetadataType(enum.IntEnum):
    StoreName = 0  # String
    KeyPath = 1  # IDBKeyPath
    AutoIncrementFlag = 2  # Bool
    IsEvictable = 3  # Bool (and obsolete apparently)
    LastVersionNumber = 4  # Int
    MaximumAllocatedIndexId = 5  # Int
    HasKeyPathFlag = 6  # Bool (and obsolete apparently)
    KeygeneratorCurrentNumber = 7  # Int


class ObjectStoreMetadata:
    # All metadata fields are prefaced by a 0x00 byte
    def __init__(self, raw_meta: dict):
        self._metas = types.MappingProxyType(raw_meta)

    def get_meta(self, db_id: int, obj_store_id: int, meta_type: ObjectStoreMetadataType):
        record = self._metas.get((db_id, obj_store_id, meta_type))
        if not record:
            return None

        if meta_type == ObjectStoreMetadataType.StoreName:
            return record.value.decode("utf-16-be")

        # TODO
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class BlinkTrailer:
    # third_party/blink/renderer/bindings/core/v8/serialization/trailer_reader.h
    offset: int
    length: int

    TRAILER_SIZE: typing.ClassVar[int] = 13
    MIN_WIRE_FORMAT_VERSION_FOR_TRAILER: typing.ClassVar[int] = 21

    @classmethod
    def from_buffer(cls, buffer, trailer_offset: int):
        tag, offset, length = struct.unpack(">cQI", buffer[trailer_offset: trailer_offset + BlinkTrailer.TRAILER_SIZE])
        if tag != ccl_blink_value_deserializer.Constants.tag_kTrailerOffsetTag:
            raise ValueError(
                f"Trailer doesn't start with kTrailerOffsetTag "
                f"(expected: 0x{ccl_blink_value_deserializer.Constants.tag_kTrailerOffsetTag.hex()}; "
                f"got: 0x{tag.hex()}")

        return BlinkTrailer(offset, length)


@dataclasses.dataclass(frozen=True)
class IndexedDbRecord:
    owner: "IndexedDb"
    db_id: int
    obj_store_id: int
    key: IdbKey
    value: typing.Any
    is_live: bool
    ldb_seq_no: int
    origin_file: os.PathLike
    external_value_path: typing.Optional[str] = None

    def resolve_blob_index(self, blob_index: ccl_blink_value_deserializer.BlobIndex) -> IndexedDBExternalObject:
        """Resolve a ccl_blink_value_deserializer.BlobIndex to its IndexedDBExternalObject
         to get metadata (file name, timestamps, etc)"""
        return self.owner.get_blob_info(self.db_id, self.obj_store_id, self.key.raw_key, blob_index.index_id)

    def get_blob_stream(self, blob_index: ccl_blink_value_deserializer.BlobIndex) -> typing.BinaryIO:
        """Resolve a ccl_blink_value_deserializer.BlobIndex to a stream of its content"""
        return self.owner.get_blob(self.db_id, self.obj_store_id, self.key.raw_key, blob_index.index_id)

    @property
    def database_name(self):
        return self.owner.global_metadata.db_ids_lookup[self.db_id].name

    @property
    def database_origin(self):
        return self.owner.global_metadata.db_ids_lookup[self.db_id].origin

    @property
    def object_store_name(self):
        return self.owner.get_object_store_metadata(self.db_id, self.obj_store_id, ObjectStoreMetadataType.StoreName)

    @property
    def record_location(self) -> ArtifactLocation:
        return ArtifactLocation(
            str(self.origin_file),
            None,
            f"File: {pathlib.Path(*pathlib.Path(self.origin_file).parts[-2:])} Seq: {self.ldb_seq_no}")


class IndexedDb:
    # This will be informative for a lot of the data below:
    # https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/leveldb_coding_scheme.md

    # Of note, the first byte of the key defines the length of the db_id, obj_store_id and index_id in bytes:
    # 0b xxxyyyzz (x = db_id size - 1, y = obj_store size - 1, z = index_id - 1)

    def __init__(self, leveldb_dir: os.PathLike, leveldb_blob_dir: os.PathLike = None):
        self._db = ccl_leveldb.RawLevelDb(leveldb_dir)
        self._blob_dir = leveldb_blob_dir
        self.global_metadata: typing.Optional[GlobalMetadata] = None
        self.database_metadata: typing.Optional[DatabaseMetadata] = None
        self.object_store_meta: typing.Optional[ObjectStoreMetadata] = None
        self._cache_records()
        self._fetch_meta_data()
        self._blob_lookup_cache = {}

    def _cache_records(self):
        self._fetched_records = []
        # Fetch the records only once
        for record in self._db.iterate_records_raw():
            self._fetched_records.append(record)

    def _fetch_meta_data(self):
        global_metadata_raw = self._get_raw_global_metadata()
        self.global_metadata = GlobalMetadata(global_metadata_raw)
        database_metadata_raw = self._get_raw_database_metadata()
        self.database_metadata = DatabaseMetadata(database_metadata_raw)
        objectstore_metadata_raw = self._get_raw_object_store_metadata()
        self.object_store_meta = ObjectStoreMetadata(objectstore_metadata_raw)

    @staticmethod
    def make_prefix(
            db_id: int, obj_store_id: int, index_id: int, end: typing.Optional[typing.Sequence[int]]=None) -> bytes:
        if end is None:
            end = []

        def count_bytes(val):
            if val == 0:
                return 1
            i = 0
            while val > 0:
                i += 1
                val = val >> 8
            return i

        def yield_le_bytes(val):
            if val == 0:
                yield 0
            if val < 0:
                raise ValueError
            while val > 0:
                yield val & 0xff
                val = val >> 8

        db_id_size = count_bytes(db_id)
        obj_store_id_size = count_bytes(obj_store_id)
        index_id_size = count_bytes(index_id)

        if db_id_size > 8 or obj_store_id_size > 8 or index_id_size > 4:
            raise ValueError("id sizes are too big")

        byte_one = ((db_id_size - 1) << 5) | ((obj_store_id_size - 1) << 2) | (index_id_size - 1)
        # print([byte_one, *yield_le_bytes(db_id), *yield_le_bytes(obj_store_id), *yield_le_bytes(index_id), *end])
        return bytes([byte_one, *yield_le_bytes(db_id), *yield_le_bytes(obj_store_id), *yield_le_bytes(index_id), *end])

    @staticmethod
    def read_prefix(stream: typing.BinaryIO) -> tuple[int, int, int, int]:
        """
        :param stream: file-like to read the prefix from
        :return: a tuple of db_id, object_store_id, index_id, length of the prefix
        """
        lengths_bytes = stream.read(1)
        if not lengths_bytes:
            raise ValueError("Couldn't get enough data when reading prefix length")
        lengths = lengths_bytes[0]
        db_id_size = ((lengths >> 5) & 0x07) + 1
        object_store_size = ((lengths >> 2) & 0x07) + 1
        index_size = (lengths & 0x03) + 1

        db_id_raw = stream.read(db_id_size)
        object_store_raw = stream.read(object_store_size)
        index_raw = stream.read(index_size)

        if (len(db_id_raw) != db_id_size or
                len(object_store_raw) != object_store_size or
                len(index_raw) != index_size):
            raise ValueError("Couldn't read enough bytes for the prefix")

        db_id = int.from_bytes(db_id_raw, "little")
        object_store_id = int.from_bytes(object_store_raw, "little")
        index_id = int.from_bytes(index_raw, "little")

        return db_id, object_store_id, index_id, (db_id_size + object_store_size + index_size + 1)

    def get_database_metadata(self, db_id: int, meta_type: DatabaseMetadataType):
        return self.database_metadata.get_meta(db_id, meta_type)

    def get_object_store_metadata(self, db_id: int, obj_store_id: int, meta_type: ObjectStoreMetadataType):
        return self.object_store_meta.get_meta(db_id, obj_store_id, meta_type)

    def _get_raw_global_metadata(self, live_only=True) -> typing.Dict[bytes, ccl_leveldb.Record]:
        # Global metadata always has the prefix 0 0 0 0
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")
        meta = {}
        for record in reversed(self._fetched_records):
            if record.key.startswith(b"\x00\x00\x00\x00") and record.state == ccl_leveldb.KeyState.Live:
                # we only want live keys and the newest version thereof (highest seq)
                if record.key not in meta or meta[record.key].seq < record.seq:
                    meta[record.key] = record

        return meta

    def _get_raw_database_metadata(self, live_only=True):
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")

        db_meta = {}

        for db_id in self.global_metadata.db_ids:

            prefix = IndexedDb.make_prefix(db_id.dbid_no, 0, 0)
            for record in reversed(self._fetched_records):
                if record.key.startswith(prefix) and record.state == ccl_leveldb.KeyState.Live:
                    # we only want live keys and the newest version thereof (highest seq)
                    meta_type = record.key[len(prefix)]
                    old_version = db_meta.get((db_id.dbid_no, meta_type))
                    if old_version is None or old_version.seq < record.seq:
                        db_meta[(db_id.dbid_no, meta_type)] = record

        return db_meta

    def _get_raw_object_store_metadata(self, live_only=True):
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")

        os_meta = {}

        for db_id in self.global_metadata.db_ids:

            prefix = IndexedDb.make_prefix(db_id.dbid_no, 0, 0, [50])

            for record in reversed(self._fetched_records):
                if record.key.startswith(prefix) and record.state == ccl_leveldb.KeyState.Live:
                    # we only want live keys and the newest version thereof (highest seq)
                    objstore_id, varint_raw = _le_varint_from_bytes(record.key[len(prefix):])
                    meta_type = record.key[len(prefix) + len(varint_raw)]

                    old_version = os_meta.get((db_id.dbid_no, objstore_id, meta_type))

                    if old_version is None or old_version.seq < record.seq:
                        os_meta[(db_id.dbid_no, objstore_id, meta_type)] = record

        return os_meta

    def read_record_precursor(
            self, key: IdbKey, db_id: int, store_id: int, buffer: bytes,
            bad_deserializer_data_handler: typing.Callable[[IdbKey, bytes], typing.Any],
            external_data_path: typing.Optional[str] = None):
        val_idx = 0
        trailer = None
        blink_type_tag = buffer[val_idx]
        if blink_type_tag != 0xff:
            # TODO: probably don't want to fail hard here long term...
            if bad_deserializer_data_handler is not None:
                bad_deserializer_data_handler(key, buffer)
                return None
            else:
                raise ValueError("Blink type tag not present")

        val_idx += 1

        blink_version, varint_raw = _le_varint_from_bytes(buffer[val_idx:])

        val_idx += len(varint_raw)

        # third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.cc
        # Peek the next byte to work out if the data is held externally or compressed:
        if blink_version == 0x11:
            if buffer[val_idx] == 0x01:  # kReplaceWithBlob
                val_idx += 1
                externally_serialized_blob_size, varint_raw = _le_varint_from_bytes(buffer[val_idx:])
                val_idx += len(varint_raw)
                externally_serialized_blob_index, varint_raw = _le_varint_from_bytes(buffer[val_idx:])
                val_idx += len(varint_raw)

                try:
                    info = self.get_blob_info(db_id, store_id, key.raw_key, externally_serialized_blob_index)
                except KeyError:
                    info = None

                if info is not None:
                    data_path = pathlib.Path(str(db_id), f"{info.blob_number >> 8:02x}", f"{info.blob_number:x}")
                    try:
                        blob = self.get_blob(db_id, store_id, key.raw_key, externally_serialized_blob_index).read()
                    except FileNotFoundError:
                        if bad_deserializer_data_handler is not None:
                            bad_deserializer_data_handler(key, buffer)
                            return None
                        raise

                    return self.read_record_precursor(
                        key, db_id, store_id,
                        blob,
                        bad_deserializer_data_handler, str(data_path))
                else:
                    return None

            elif buffer[val_idx] == 0x02:  # kCompressedWithSnappy
                val_idx += 1
                decompressed = ccl_simplesnappy.decompress(io.BytesIO(buffer[val_idx:]))
                return self.read_record_precursor(
                    key, db_id, store_id,
                    decompressed,
                    bad_deserializer_data_handler, str(external_data_path))
            else:
                raise ValueError("Unexpected value after kRequiresProcessingSSVPseudoVersion")
        else:
            if blink_version >= BlinkTrailer.MIN_WIRE_FORMAT_VERSION_FOR_TRAILER:
                trailer = BlinkTrailer.from_buffer(buffer, val_idx)  # TODO: do something with the trailer
                val_idx += BlinkTrailer.TRAILER_SIZE

            obj_raw = io.BytesIO(buffer[val_idx:])

        return blink_version, obj_raw, trailer, external_data_path

    def iterate_records(
            self, db_id: int, store_id: int, *,
            live_only=False, bad_deserializer_data_handler: typing.Callable[[IdbKey, bytes], typing.Any] = None):
        blink_deserializer = ccl_blink_value_deserializer.BlinkV8Deserializer()

        # goodness me this is a slow way of doing things
        prefix = IndexedDb.make_prefix(db_id, store_id, 1)

        for record in self._fetched_records:
            if record.key.startswith(prefix):
                key = IdbKey(record.key[len(prefix):])
                if not record.value:
                    # empty values will obviously fail, returning None is probably better than dying.
                    yield IndexedDbRecord(self, db_id, store_id, key, None,
                                          record.state == ccl_leveldb.KeyState.Live, record.seq, record.origin_file)
                    continue
                value_version, varint_raw = _le_varint_from_bytes(record.value)
                val_idx = len(varint_raw)
                # read the blink envelope
                precursor = self.read_record_precursor(
                    key, db_id, store_id, record.value[val_idx:], bad_deserializer_data_handler)
                if precursor is None:
                    continue  # only returns None on error, handled in the function if bad_deserializer_data_handler can

                blink_version, obj_raw, trailer, external_path = precursor

                try:
                    deserializer = ccl_v8_value_deserializer.Deserializer(
                        obj_raw, host_object_delegate=blink_deserializer.read)
                    value = deserializer.read()
                except Exception:
                    if bad_deserializer_data_handler is not None:
                        bad_deserializer_data_handler(key, record.value)
                        continue
                    raise
                yield IndexedDbRecord(self, db_id, store_id, key, value,
                                      record.state == ccl_leveldb.KeyState.Live,
                                      record.seq, record.origin_file, external_path)

    def get_blob_info(self, db_id: int, store_id: int, raw_key: bytes, file_index: int) -> IndexedDBExternalObject:
        # if db_id > 0x7f or store_id > 0x7f:
        #     raise NotImplementedError("there could be this many dbs, but I don't support it yet")

        if result := self._blob_lookup_cache.get((db_id, store_id, raw_key, file_index)):
            return result

        # goodness me this is a slow way of doing things,
        # TODO: we should at least cache along the way to our record
        # prefix = bytes([0, db_id, store_id, 3])
        prefix = IndexedDb.make_prefix(db_id, store_id, 3)
        for record in self._fetched_records:
            if record.user_key.startswith(prefix):
                this_raw_key = record.user_key[len(prefix):]
                buff = io.BytesIO(record.value)
                idx = 0
                while buff.tell() < len(record.value):
                    blob_info = IndexedDBExternalObject.from_stream(buff)
                    self._blob_lookup_cache[(db_id, store_id, this_raw_key, idx)] = blob_info
                    idx += 1
                # if this_raw_key == raw_key:
                #     break

        if result := self._blob_lookup_cache.get((db_id, store_id, raw_key, file_index)):
            return result
        else:
            raise KeyError((db_id, store_id, raw_key, file_index))

    def get_blob(self, db_id: int, store_id: int, raw_key: bytes, file_index: int) -> typing.BinaryIO:
        # Some detail here: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/README.md
        if self._blob_dir is None:
            raise ValueError("Can't resolve blob if blob dir is not set")
        info = self.get_blob_info(db_id, store_id, raw_key, file_index)

        # path will be: origin.blob/database id/top 16 bits of blob number with two digits/blob number
        # TODO: check if this is still the case on non-windows systems
        path = pathlib.Path(self._blob_dir, f"{db_id:x}", f"{info.blob_number >> 8:02x}", f"{info.blob_number:x}")

        if path.exists():
            return path.open("rb")

        raise FileNotFoundError(path)

    def get_undo_task_scopes(self):
        # https://github.com/chromium/chromium/blob/master/components/services/storage/indexed_db/scopes/leveldb_scopes_coding.cc

        # Prefix will be 00 00 00 00 32 (00|01|02) (varint of scope number) 00
        # 00 00 00 00  =  Global metadata
        # 32           =  kScopesPrefixByte from indexed_db_leveldb_coding.cc
        # (00|01|02)   =  one of: kGlobalMetadataByte, kScopesMetadataByte or kLogByte from leveldb_scopes_coding.h
        # (varint of scope)
        # 00           =  kUndoTasksByte from leveldb_scopes_coding.h

        # This is a slow way of doing this:
        prefix = bytes.fromhex("00 00 00 00 32")
        for record in self._fetched_records:
            if record.state != ccl_leveldb.KeyState.Live:
                continue
            if record.user_key.startswith(prefix):
                # process the key first as they define what we'll do later
                o = len(prefix)
                metadata_byte = record.user_key[o]
                assert metadata_byte in (0, 1, 2)  # TODO: replace with real exception

                o += 1

                if metadata_byte == 0:  # global meta
                    # print(f"Global metadata:\t{record.user_key.hex(' ')}")
                    continue  # Don't currently think I need this to do the work
                elif metadata_byte == 1:  # scope meta
                    # print(f"Scope metadata:\t{record.user_key.hex(' ')}")
                    # scope_number, varint_bytes = _le_varint_from_bytes(record.user_key)
                    # o += len(varint_bytes)
                    continue  # Don't currently think I need this to do the work
                elif metadata_byte == 2:  # log
                    scope_number, varint_bytes = _le_varint_from_bytes(record.user_key)
                    o += len(varint_bytes)
                    undo_byte = record.key[o]
                    if undo_byte != 0:
                        continue
                    o += 1
                    # print(f"Log\t{record.user_key.hex(' ')}")
                    undo_sequence_number, = struct.unpack(">q", record.user_key[o:o + 8])

                    # Value should be a LevelDBScopesUndoTask protobuf
                    # (indexed_db_components\indexed_db\scopes\scopes_metadata.proto).
                    # We're looking for a "Put" protobuf (first and only tag should be a Message numbered 1, with two
                    # bytes values numbered 1 and 2 which are the original key and value respectively.
                    # To reduce the need for dependencies, as they are so simple, the protobuf can be decoded "manually"
                    with io.BytesIO(record.value) as value_stream:
                        root_tag_raw = read_le_varint(value_stream)
                        root_number = root_tag_raw >> 3
                        if root_tag_raw & 0x07 != 2 or root_number != 1:
                            assert root_number in (2, 3)  # TODO: remove?
                            continue  # I don't think I need to raise an exception here?
                        data_length = read_le_varint(value_stream)
                        inner_value_bytes = value_stream.read(data_length)
                        if len(inner_value_bytes) != data_length:
                            raise ValueError("Couldn't get all data when reading the LevelDBScopesUndoTask")

                    record_key_raw = None
                    record_value_raw = None
                    with io.BytesIO(inner_value_bytes) as inner_value_stream:
                        while inner_value_stream.tell() < len(inner_value_bytes) and (
                                record_key_raw is None or record_value_raw is None):
                            tag_raw = read_le_varint(inner_value_stream)
                            assert tag_raw & 0x07 == 2
                            tag_number = tag_raw >> 3
                            data_length = read_le_varint(inner_value_stream)
                            data = inner_value_stream.read(data_length)
                            if len(data) != data_length:
                                raise ValueError("Couldn't get enough from the protobuf in LevelDBScopesUndoTask")
                            if tag_number == 1:
                                record_key_raw = data
                            elif tag_number == 2:
                                record_value_raw = data
                            else:
                                raise ValueError("Unexpected message in LevelDBScopesUndoTask")

                    if not record_value_raw:
                        continue  # I don't think we need to go further here

                    with io.BytesIO(record_key_raw) as record_key_stream:
                        db_id, object_store, index_id, length = IndexedDb.read_prefix(record_key_stream)
                        if db_id < 1 or object_store < 1 or index_id < 1:
                            continue  # only work with indexeddb record records

                        key = IdbKey(record_key_stream.read())

                        yield key, record_value_raw

    def close(self):
        self._db.close()

    @property
    def database_path(self):
        return self._db.in_dir_path

    def __enter__(self) -> "IndexedDb":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class WrappedObjectStore:
    """
    A wrapper class around a "raw" IndexedDb which simplifies accessing records related to an object store. Usually only
    created by a WrappedDatabase.
    """
    def __init__(self, raw_db: IndexedDb,  dbid_no: int, obj_store_id: int):
        self._raw_db = raw_db
        self._dbid_no = dbid_no
        self._obj_store_id = obj_store_id

    @property
    def object_store_id(self) -> int:
        return self._obj_store_id

    @property
    def name(self) -> str:
        return self._raw_db.get_object_store_metadata(
            self._dbid_no, self._obj_store_id, ObjectStoreMetadataType.StoreName)

    @staticmethod
    def _log_error(key: IdbKey, data: bytes):
        sys.stderr.write(f"ERROR decoding key: {key}\n")

    def get_blob(self, raw_key: bytes, file_index: int) -> typing.BinaryIO:
        """
        Deprecated: use IndexedDbRecord.get_blob_stream

        :param raw_key: raw key of the record from which the blob originates
        :param file_index: the file/blob index from a ccl_blink_value_deserializer.BlobIndex
        :return: a file-like object of the blob
        """

        return self._raw_db.get_blob(self._dbid_no, self.object_store_id, raw_key, file_index)

    # def __iter__(self):
    #     yield from self._raw_db.iterate_records(self._dbid_no, self._obj_store_id)

    def iterate_records(
            self, *, live_only=False, errors_to_stdout=False,
            bad_deserializer_data_handler: typing.Callable[[IdbKey, bytes], typing.Any] = None):

        def _handler(key, record):
            if bad_deserializer_data_handler is not None:
                bad_deserializer_data_handler(key, record)
            if errors_to_stdout:
                WrappedObjectStore._log_error(key, record)

        handler = _handler if errors_to_stdout or bad_deserializer_data_handler is not None else None

        yield from self._raw_db.iterate_records(
            self._dbid_no, self._obj_store_id, live_only=live_only,
            bad_deserializer_data_handler=handler)

    def __repr__(self):
        return f"<WrappedObjectStore: object_store_id={self.object_store_id}; name={self.name}>"


class WrappedDatabase:
    """
    A wrapper class around the raw "IndexedDb" class which simplifies access to a Database in the IndexedDb. Usually
    only created by WrappedIndexedDb.
    """
    def __init__(self, raw_db: IndexedDb,  dbid: DatabaseId):
        self._raw_db = raw_db
        self._dbid = dbid

        names = []
        for obj_store_id in range(1, self.object_store_count + 1):
            names.append(self._raw_db.get_object_store_metadata(
                self.db_number, obj_store_id, ObjectStoreMetadataType.StoreName))
        self._obj_store_names = tuple(names)
        # pre-compile object store wrappers as there's little overhead
        self._obj_stores = tuple(
            WrappedObjectStore(
                self._raw_db, self.db_number, i) for i in range(1, self.object_store_count + 1))

    @property
    def name(self) -> str:
        """
        :return: the name of this WrappedDatabase
        """
        return self._dbid.name

    @property
    def origin(self) -> str:
        """
        :return: the origin (host name) for this WrappedDatabase
        """
        return self._dbid.origin

    @property
    def db_number(self) -> int:
        """
        :return: the numerical ID assigned to this WrappedDatabase
        """
        return self._dbid.dbid_no

    @property
    def object_store_count(self) -> int:
        """
        :return: the "MaximumObjectStoreId" value fot this database; NB this may not be the *actual* number of object
            stores which can be read - it is possible that some object stores may be deleted. Use len() to check the
            number of object stores you can actually access
        """
        # NB obj store ids are enumerated from 1.
        return self._raw_db.get_database_metadata(
            self.db_number,
            DatabaseMetadataType.MaximumObjectStoreId) or 0  # returns None if there are none.

    @property
    def object_store_names(self) -> typing.Iterable[str]:
        """
        :return: yields the names of the object stores in this WrappedDatabase
        """
        yield from self._obj_store_names

    def get_object_store_by_id(self, obj_store_id: int) -> WrappedObjectStore:
        """
        :param obj_store_id: the numerical ID for an object store in this WrappedDatabase
        :return: the WrappedObjectStore with the ID provided
        """
        if obj_store_id > 0 and obj_store_id <= self.object_store_count:
            return self._obj_stores[obj_store_id - 1]
        raise ValueError("obj_store_id must be greater than zero and less or equal to object_store_count "
                         "NB object stores are enumerated from 1 - there is no store with id 0")

    def get_object_store_by_name(self, name: str) -> WrappedObjectStore:
        """
        :param name: the name of an object store in this WrappedDatabase
        :return: the WrappedObjectStore with the name provided
        """
        if name in self:
            return self.get_object_store_by_id(self._obj_store_names.index(name) + 1)
        raise KeyError(f"{name} is not an object store in this database")

    def __iter__(self) -> typing.Iterable[WrappedObjectStore]:
        """
        :return: yields the object stores in this WrappedDatabase
        """
        yield from self._obj_stores

    def __len__(self) -> int:
        """
        :return: the number of object stores accessible in this WrappedDatabase
        """
        return len(self._obj_stores)

    def __contains__(self, item: str) -> bool:
        """
        :param item: the name of an object store in this WrappedDatabase
        :return: True if the name provided matches one of the Object stores in this WrappedDatabase
        """
        return item in self._obj_store_names

    def __getitem__(self, item: typing.Union[int, str]) -> WrappedObjectStore:
        """
        :param item: either the numerical ID of an object store (as an int) or the name of an object store in this
            WrappedDatabase
        :return:
        """
        if isinstance(item, int):
            return self.get_object_store_by_id(item)
        elif isinstance(item, str):
            return self.get_object_store_by_name(item)
        raise TypeError("Key can only be str (name) or int (id number)")

    def __repr__(self):
        return f"<WrappedDatabase: id={self.db_number}; name={self.name}; origin={self.origin}>"


class WrappedIndexDB:
    """
    A wrapper object around the "raw" IndexedDb class. This should be used in most cases as the code required to use it
    is simpler and more pythonic.
    """
    def __init__(self, leveldb_dir: os.PathLike, leveldb_blob_dir: os.PathLike = None):
        self._raw_db = IndexedDb(leveldb_dir, leveldb_blob_dir)
        self._multiple_origins = len(set(x.origin for x in self._raw_db.global_metadata.db_ids)) > 1

        self._db_number_lookup = {
            x.dbid_no: WrappedDatabase(self._raw_db, x)
            for x in self._raw_db.global_metadata.db_ids}
        # set origin to 0 if there's only 1, and we'll ignore it in all lookups
        self._db_name_lookup = {
            (x.name, x.origin if self.has_multiple_origins else 0): x
            for x in self._db_number_lookup.values()}

    def close(self):
        self._raw_db.close()

    @property
    def database_count(self) -> int:
        """
        :return: The number of databases in this IndexedDB
        """
        return len(self._db_number_lookup)

    @property
    def database_ids(self) -> typing.Iterable[DatabaseId]:
        """
        :return: yields DatabaseId objects which define the databases in this IndexedDb
        """
        yield from self._raw_db.global_metadata.db_ids

    @property
    def has_multiple_origins(self) -> bool:
        return self._multiple_origins

    def __len__(self):
        """
        :return: the number of databases in this IndexedDb
        """
        len(self._db_number_lookup)

    def __contains__(self, item: typing.Union[str, int, tuple[str, str]]):
        """
        :param item: either a database id number, the name of a database (as a string), or (if the database has multiple
            origins), a tuple of database name and origin
        :return: True if this IndexedDb contains the referenced database identifier
        """
        if isinstance(item, str):
            if self.has_multiple_origins:
                raise ValueError(
                    "Database contains multiple origins, lookups must be provided as a tuple of (name, origin)")
            return (item, 0) in self._db_name_lookup
        elif isinstance(item, tuple) and len(item) == 2:
            name, origin = item
            if not self.has_multiple_origins:
                origin = 0  # origin ignored if not needed
            return (name, origin) in self._db_name_lookup
        elif isinstance(item, int):
            return item in self._db_number_lookup
        elif isinstance(item, DatabaseId):
            hit = self._db_number_lookup.get(item.dbid_no)
            return hit is not None and hit.name == item.name and hit.origin == item.origin
        else:
            raise TypeError("keys must be provided as a tuple of (name, origin) or a str (if only single origin) or int")

    def __getitem__(self, item: typing.Union[DatabaseId, int, str, typing.Tuple[str, str]]) -> WrappedDatabase:
        """
        :param item: either a DatabaseID object database id number, the name of a database (as a string), or
        (if the database has multiple origins), a tuple of database name and origin
        :return: the WrappedDatabase referenced by the id in item
        """
        if isinstance(item, DatabaseId):
            if item.dbid_no in self._db_number_lookup:
                result = self._db_number_lookup[item.dbid_no]
                if result.name == item.name and result.origin == item.origin:
                    return result
                else:
                    raise KeyError(item)
            else:
                raise KeyError(item)
        if isinstance(item, int):
            if item in self._db_number_lookup:
                return self._db_number_lookup[item]
            else:
                raise KeyError(item)
        elif isinstance(item, str):
            if self.has_multiple_origins:
                raise ValueError(
                    "Database contains multiple origins, indexes must be provided as a tuple of (name, origin)")
            if item in self:
                return self._db_name_lookup[item, 0]
            else:
                raise KeyError(item)
        elif isinstance(item, tuple) and len(item) == 2:
            name, origin = item
            if not self.has_multiple_origins:
                origin = 0  # origin ignored if not needed
            if (name, origin) in self:
                return self._db_name_lookup[name, origin]
            else:
                raise KeyError(item)

        raise TypeError("Lookups must be one of int, str or tuple of name and origin")

    def __repr__(self):
        return f"<WrappedIndexDB: {self._raw_db.database_path}>"

    def __enter__(self) -> "WrappedIndexDB":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()