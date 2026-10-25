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

import datetime
import enum
import io
import os
import struct
import sys
import pathlib
import dataclasses
import typing

from .storage_formats import ccl_leveldb
from .serialization_formats import ccl_blink_value_deserializer, ccl_v8_value_deserializer, ccl_protobuff as pb

__version__ = "0.3"
__description__ = "Library for reading Chrome/Chromium notifications (Platform Notifications)"
__contact__ = "Alex Caithness"

# See content/browser/notifications/notification_database.cc
#   and content/browser/notifications/notification_database_data.proto

EPOCH = datetime.datetime(1601, 1, 1)


# stolen from ccl_chromium_indexeddb 20230907
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


class ClosedReason(enum.IntEnum):
    USER = 0
    DEVELOPER = 1
    UNKNOWN = 2


class ActionType(enum.IntEnum):
    BUTTON = 0
    TEXT = 1


class Direction(enum.IntEnum):
    LEFT_TO_RIGHT = 0
    RIGHT_TO_LEFT = 1
    AUTO = 2


def read_datetime(stream):
    ms = pb.read_le_varint(stream)
    return EPOCH + datetime.timedelta(microseconds=ms)


NotificationAction_Structure = {
    1: pb.ProtoDecoder("action", pb.read_string),
    2: pb.ProtoDecoder("title", pb.read_string),
    3: pb.ProtoDecoder("icon", pb.read_string),
    4: pb.ProtoDecoder("type", lambda x: ActionType(pb.read_le_varint(x))),
    5: pb.ProtoDecoder("placeholder", pb.read_string),
}

NotificationData_Structure = {
    1: pb.ProtoDecoder("title", pb.read_string),
    2: pb.ProtoDecoder("closed_reason", lambda x: Direction(pb.read_le_varint(x))),
    3: pb.ProtoDecoder("lang", pb.read_string),
    4: pb.ProtoDecoder("body", pb.read_string),
    5: pb.ProtoDecoder("tag", pb.read_string),
    6: pb.ProtoDecoder("icon", pb.read_string),
    7: pb.ProtoDecoder("silent", lambda x: pb.read_le_varint(x) != 0),
    8: pb.ProtoDecoder("data", pb.read_blob),
    9: pb.ProtoDecoder("vibration", pb.read_blob),
    10: pb.ProtoDecoder(
        "actions", lambda x: pb.read_embedded_protobuf(x, NotificationAction_Structure, use_friendly_tag=True)),
    11: pb.ProtoDecoder("require_interaction", lambda x: pb.read_le_varint(x) != 0),
    12: pb.ProtoDecoder("timestamp", read_datetime),
    13: pb.ProtoDecoder("renotify", lambda x: pb.read_le_varint(x) != 0),
    14: pb.ProtoDecoder("badge", pb.read_string),
    15: pb.ProtoDecoder("image", pb.read_string),
    16: pb.ProtoDecoder("show_trigger_timestamp", read_datetime),
}

NotificationDatabaseDataProto_Structure = {
    1: pb.ProtoDecoder("persistent_notification_id", pb.read_le_varint),
    2: pb.ProtoDecoder("origin", pb.read_string),
    3: pb.ProtoDecoder("service_worker_registration_id", pb.read_le_varint),
    4: pb.ProtoDecoder(
        "notification_data", lambda x: pb.read_embedded_protobuf(x, NotificationData_Structure, use_friendly_tag=True)),
    5: pb.ProtoDecoder("notification_id", pb.read_string),
    6: pb.ProtoDecoder("replaced_existing_notification", lambda x: pb.read_le_varint(x) != 0),
    7: pb.ProtoDecoder("num_clicks", pb.read_le_varint32),
    8: pb.ProtoDecoder("num_action_button_clicks", pb.read_le_varint32),
    9: pb.ProtoDecoder("creation_time_millis", read_datetime),
    10: pb.ProtoDecoder("time_until_first_click_millis", pb.read_le_varint),
    11: pb.ProtoDecoder("time_until_last_click_millis", pb.read_le_varint),
    12: pb.ProtoDecoder("time_until_close_millis", pb.read_le_varint),
    13: pb.ProtoDecoder("closed_reason", lambda x: ClosedReason(pb.read_le_varint(x))),
    14: pb.ProtoDecoder("has_triggered", lambda x: pb.read_le_varint(x) != 0),
    15: pb.ProtoDecoder("is_shown_by_browser", lambda x: pb.read_le_varint(x) != 0),
}


@dataclasses.dataclass(frozen=True)
class LevelDbInfo:
    user_key: bytes
    origin_file: os.PathLike
    seq_no: int


@dataclasses.dataclass(frozen=True)
class NotificationAction:
    action: typing.Optional[str]
    title: typing.Optional[str]
    icon: typing.Optional[str]
    action_type: typing.Optional[ActionType]
    placeholder: typing.Optional[str]


@dataclasses.dataclass(frozen=True)
class ChromiumNotification:
    level_db_info: LevelDbInfo
    origin: str
    persistent_notification_id: int
    notification_id: str
    title: typing.Optional[str]
    body: typing.Optional[str]
    data: typing.Optional[typing.Any]
    timestamp: datetime.datetime
    creation_time: datetime.datetime  # from creation_time_millis
    closed_reason: ClosedReason
    time_until_first_click_millis: int
    time_until_last_click_millis: int
    time_until_close_millis: int

    tag: typing.Optional[str]
    image: typing.Optional[str]
    icon: typing.Optional[str]
    badge: typing.Optional[str]

    actions: typing.Optional[typing.Iterable[NotificationAction]]


class NotificationReader:
    def __init__(self, notification_input_path: pathlib.Path):
        self._db = ccl_leveldb.RawLevelDb(notification_input_path)

    def close(self):
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._db.close()

    def read_notifications(self) -> typing.Iterable[ChromiumNotification]:
        blink_deserializer = ccl_blink_value_deserializer.BlinkV8Deserializer()
        for record in self._db.iterate_records_raw():
            if record.state != ccl_leveldb.KeyState.Live:
                continue

            key = record.user_key.decode("utf-8")
            record_type, key_info = key.split(":", 1)
            origin, key_id = key_info.split("\0", 1)
            level_db_info = LevelDbInfo(record.user_key, record.origin_file, record.seq)
            if record_type == "DATA":
                with io.BytesIO(record.value) as stream:
                    root = pb.ProtoObject(
                        0x2,
                        "root",
                        pb.read_protobuff(stream, NotificationDatabaseDataProto_Structure, use_friendly_tag=True))

                data = root.only("notification_data").only("data").value
                if data:
                    if data[0] != 0xff:
                        print(key)
                        print(data)
                        raise ValueError("Missing blink tag at the start of data")
                    blink_version, blink_version_bytes = pb._read_le_varint(io.BytesIO(data[1:]))
                    data_start = 1 + len(blink_version_bytes)
                    if blink_version >= BlinkTrailer.MIN_WIRE_FORMAT_VERSION_FOR_TRAILER:
                        trailer = BlinkTrailer.from_buffer(data, data_start)  # TODO: do something with the trailer?
                        data_start += BlinkTrailer.TRAILER_SIZE

                    with io.BytesIO(data[data_start:]) as obj_raw:
                        try:
                            deserializer = ccl_v8_value_deserializer.Deserializer(
                                obj_raw, host_object_delegate=blink_deserializer.read)
                        except ValueError:
                            print("Error record:")
                            print(level_db_info, key)
                            raise
                        data = deserializer.read()

                yield ChromiumNotification(
                    level_db_info,
                    root.only("origin").value,
                    root.only("persistent_notification_id").value,
                    root.only("notification_id").value,
                    root.only("notification_data").only("title").value,
                    root.only("notification_data").only("body").value,
                    data,
                    root.only("notification_data").only("timestamp").value,
                    root.only("creation_time_millis").value,
                    root.only("closed_reason").value,
                    root.only("time_until_first_click_millis").value,
                    root.only("time_until_last_click_millis").value,
                    root.only("time_until_close_millis").value,
                    root.only("notification_data").only("tag").value,
                    root.only("notification_data").only("image").value,
                    root.only("notification_data").only("icon").value,
                    root.only("notification_data").only("badge").value,
                    tuple(
                        NotificationAction(
                            x.only("action").value,
                            x.only("title").value,
                            x.only("icon").value,
                            x.only("type").value,
                            x.only("placeholder").value
                        )
                        for x in root["notification_data"][0]["actions"])
                )


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <Platform Notifications Folder>")
        exit(1)

    _reader = NotificationReader(pathlib.Path(sys.argv[1]))
    _blink_deserializer = ccl_blink_value_deserializer.BlinkV8Deserializer()
    for notification in _reader.read_notifications():
        print(notification)
