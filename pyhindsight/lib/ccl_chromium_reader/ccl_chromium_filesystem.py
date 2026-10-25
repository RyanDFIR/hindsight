"""
Copyright 2022, CCL Forensics

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

__version__ = "0.8"
__description__ = "Library for reading Chrome/Chromium File System API data"
__contact__ = "Alex Caithness"

import dataclasses
import os
import sys
import pathlib
import datetime
import re
import typing
import types
import functools

from .storage_formats import ccl_leveldb
from .serialization_formats.ccl_easy_chromium_pickle import EasyPickleIterator


@dataclasses.dataclass(frozen=True)
class FileInfo:
    _owner: "FileSystem" = dataclasses.field(repr=False)
    origin: str
    folder_id: str
    is_persistent: bool
    seq_no: int
    file_id: int
    parent_id: int
    data_path: str
    name: str
    timestamp: datetime.datetime

    @classmethod
    def from_pickle(
            cls, owner: "FileSystem", origin: str, folder_id: str, is_persistent: bool,
            seq_no: int, file_id: int, data: bytes):
        with EasyPickleIterator(data) as reader:
            parent_id = reader.read_uint64()
            data_path = reader.read_string()
            name = reader.read_string()
            timestamp = reader.read_datetime()

        return cls(owner, origin, folder_id, is_persistent, seq_no, file_id, parent_id, data_path, name, timestamp)

    def get_local_storage_path(self) -> pathlib.Path:
        return self._owner.get_local_path_for_fileinfo(self)

    @property
    def is_stored_locally(self) -> bool:
        return self.get_local_storage_path().exists()


class OriginStorage:
    def __init__(
            self,
            owner: "FileSystem",
            origin: str,
            folder_id: str,
            persistent_files: typing.Optional[typing.Mapping[int, FileInfo]],
            persistent_deleted_file_ids: typing.Optional[typing.Iterable[int]],
            temporary_files: typing.Optional[typing.Mapping[int, FileInfo]],
            temporary_deleted_file_ids: typing.Optional[typing.Iterable[int]]):
        self._owner = owner
        self._origin = origin
        self._folder_id = folder_id
        self._persistent_files = types.MappingProxyType(persistent_files or {})
        self._persistent_deleted_file_ids = set(persistent_deleted_file_ids or [])
        self._temporary_files = types.MappingProxyType(temporary_files or {})
        self._temporary_deleted_file_ids = set(temporary_deleted_file_ids or [])

        self._persistent_file_listing_lookup = types.MappingProxyType(self._make_file_listing_lookup(True))
        self._temporary_file_listing_lookup = types.MappingProxyType(self._make_file_listing_lookup(False))

        self._file_listing_lookup_reverse: dict[str, list[str]] = {}
        for k, v in self._persistent_file_listing_lookup.items():
            self._file_listing_lookup_reverse.setdefault(v, [])
            self._file_listing_lookup_reverse[v].append(f"p_{k}")

        for k, v in self._temporary_file_listing_lookup.items():
            self._file_listing_lookup_reverse.setdefault(v, [])
            self._file_listing_lookup_reverse[v].append(f"t_{k}")
        self._file_listing_lookup_reverse = types.MappingProxyType(
            self._file_listing_lookup_reverse)

    def _make_file_listing_lookup(self, persistent=True) -> dict[int, str]:
        files = self._persistent_files if persistent else self._temporary_files
        file_listing_lookup: dict[int, str] = {}

        for file_info in files.values():
            if not file_info.data_path:
                continue
            path_parts = []
            current = file_info
            while current.file_id != current.parent_id:
                path_parts.insert(0, current.name)
                current = files.get(current.parent_id, "<MISSING PATH SEGMENT>")

            path_parts.insert(0, "p" if persistent else "t")
            # path_parts.insert(0, self._origin)
            # path_parts.insert(0, "")
            file_listing_lookup[file_info.file_id] = "/".join(path_parts)

        return file_listing_lookup

    def get_file_listing(self) -> typing.Iterable[tuple[str, FileInfo]]:
        for file_id in self._persistent_file_listing_lookup:
            yield self._persistent_file_listing_lookup[file_id], self._persistent_files[file_id]
        for file_id in self._temporary_file_listing_lookup:
            yield self._temporary_file_listing_lookup[file_id], self._temporary_files[file_id]

    def _get_file_info_from_path(self, path) -> typing.Iterable[FileInfo]:
        file_keys = self._file_listing_lookup_reverse[str(path)]
        for key in file_keys:
            p_or_t, file_id = key.split("_", 1)
            yield self._persistent_files[int(file_id)] if p_or_t == "p" else self._temporary_files[int(file_id)]


class FileSystem:
    def __init__(self, path: typing.Union[os.PathLike, str]):
        """
        Constructor for the File System API access (the entry point for most processing scripts)
        :param path: the path of the File System API storage
        """
        self._root = pathlib.Path(path)
        self._origins = self._get_origins()
        self._origins_reverse = {}
        for origin, folders in self._origins.items():
            for folder in folders:
                self._origins_reverse[folder] = origin

    def _get_origins(self) -> dict[str, tuple]:
        result = {}
        with ccl_leveldb.RawLevelDb(self._root / "Origins") as db:
            for record in db.iterate_records_raw():
                if record.state != ccl_leveldb.KeyState.Live:
                    continue
                if record.user_key.startswith(b"ORIGIN:"):
                    _, origin = record.user_key.split(b":", 1)
                    origin = origin.decode("utf-8")
                    result.setdefault(origin, [])
                    result[origin].append(record.value.decode("utf-8"))

        return {k: tuple(v) for (k, v) in result.items()}

    def get_origins(self) -> typing.Iterable[str]:
        """
        Yields the origins for this File System API
        :return: Yields the origins in this File System API
        """
        yield from self._origins.keys()

    def get_folders_for_origin(self, origin) -> tuple[str, ...]:
        """
        Returns the folder ids which are used by the origin (host/domain)
        :param origin:
        :return: a tuple of strings which are the folder id(s) for this origin
        """
        return self._origins[origin]

    def get_storage_for_folder(self, folder_id) -> OriginStorage:
        """
        Get the OriginStorage object for the folder
        :param folder_id: a folder id (such as those returned by get_folders_for_origin)
        :return: OriginStorage for the folder_id
        """
        return self._build_file_graph(folder_id)

    @functools.cache
    def _build_file_graph(self, folder_id) -> OriginStorage:
        persistent_files: typing.Optional[dict[int, FileInfo]] = {}
        persistent_deleted_files: typing.Optional[dict[int, int]] = {}  # file_id: seq_no
        temporary_files: typing.Optional[dict[int, FileInfo]] = {}
        temporary_deleted_files: typing.Optional[dict[int, int]] = {}  # file_id: seq_no

        origin = self._origins_reverse[folder_id]

        for p_or_t in ("p", "t"):
            db_path = self._root / folder_id / p_or_t / "Paths"
            if not db_path.exists():
                continue
            files: dict[int, FileInfo] = persistent_files if p_or_t == "p" else temporary_files
            deleted_files: dict[int, int] = persistent_deleted_files if p_or_t == "p" else temporary_deleted_files
            with ccl_leveldb.RawLevelDb(db_path) as db:
                # TODO: we can infer file modified (created?) times using the parent's modified times maybe
                for record in db.iterate_records_raw():
                    if re.match(b"[0-9]+", record.user_key) is not None:
                        if record.state == ccl_leveldb.KeyState.Live:
                            file_id = int(record.user_key.decode("utf-8"))
                            file_info = FileInfo.from_pickle(
                                self, origin, folder_id, p_or_t == "p", record.seq, file_id, record.value)

                            # undelete a file if more recent than deletion record:
                            if file_id in deleted_files and deleted_files[file_id] < file_info.seq_no:
                                deleted_files.pop(file_id)

                            if old_file_info := files.get(file_id):
                                if old_file_info.seq_no < file_info.seq_no:
                                    # TODO: any reason to keep older records (other than for the timestamps as above?)
                                    files[file_id] = file_info
                            else:
                                files[file_id] = file_info
                        else:
                            if old_file_info := files.get(file_id):
                                if old_file_info.seq_no < record.seq:
                                    deleted_files[file_id] = record.seq
                            else:
                                deleted_files[file_id] = record.seq

        return OriginStorage(
            self, origin, folder_id,
            persistent_files, persistent_deleted_files.keys(),
            temporary_files, temporary_deleted_files.keys())

    def get_local_path_for_fileinfo(self, file_info: FileInfo):
        """
        Returns the path on the local file system for the FilInfo object
        :param file_info:
        :return: the path on the local file system for the FilInfo object
        """
        path = self._root / file_info.folder_id / ("p" if file_info.is_persistent else "t") / file_info.data_path
        return path

    def get_file_stream_for_fileinfo(self, file_info: FileInfo) -> typing.Optional[typing.BinaryIO]:
        """
        Returns a file object from the local file system for the FilInfo object
        :param file_info:
        :return: a file object from the local file system for the FilInfo object
        """
        path = self.get_local_path_for_fileinfo(file_info)
        if path.exists():
            return path.open("rb")
        return None


class FileSystemUtils:
    @staticmethod
    def print_origin_to_folder(fs_folder: typing.Union[os.PathLike, str]) -> None:
        """
        utility function to print out origins in the File System API to their folders
        :param fs_folder: the path of the File System API storage
        :return: None
        """
        fs = FileSystem(fs_folder)
        for origin in sorted(fs.get_origins()):
            print(f"{origin}: {','.join(fs.get_folders_for_origin(origin))}")

    @staticmethod
    def print_folder_to_origin(fs_folder: typing.Union[os.PathLike, str]) -> None:
        """
        utility function to print out folders in the File System API to their Origin
        :param fs_folder: the path of the File System API storage
        :return: None
        """
        fs = FileSystem(fs_folder)
        result = {}
        for origin in fs.get_origins():
            for folder in fs.get_folders_for_origin(origin):
                result[folder] = origin

        for folder in sorted(result.keys()):
            print(f"{folder}: {result[folder]}")

    @staticmethod
    def print_all_files(fs_folder: typing.Union[os.PathLike, str]) -> None:
        """
        utility function to print out all files in the File System API
        :param fs_folder: the path of the File System API storage
        :return: None
        """
        fs = FileSystem(fs_folder)
        for origin in sorted(fs.get_origins()):
            for folder in fs.get_folders_for_origin(origin):
                storage = fs.get_storage_for_folder(folder)
                for file_path, file_info in storage.get_file_listing():
                    print("/".join([origin, file_path]))


if __name__ == "__main__":
    FileSystemUtils.print_all_files(sys.argv[1])


