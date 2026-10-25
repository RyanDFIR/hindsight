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

import sys
import struct
import io
import typing

__version__ = "0.8"
__description__ = "Module for naive parsing of Protocol Buffers"
__contact__ = "Alex Caithness"

DEBUG = False


class Empty:
    value = None


class ProtoObject:
    def __init__(self, tag, name, value):
        self.tag = tag
        self.name = name
        self.value = value
        self.wire = tag & 0x07

    def __str__(self):
        if self.name:
            return "{0} ({1}): {2}".format(
                self.tag if self.tag > 0x7f else hex(self.tag), self.name, repr(self.value))
        else:
            return "{0}: {1}".format(
                self.tag if self.tag > 0x7f else hex(self.tag), repr(self.value))
    __repr__ = __str__

    @property
    def friendly_tag(self) -> int:
        """:return the "real" tag (i.e. the one that would be seen inside the .proto schema)"""
        return self.tag >> 3

    def get_items_by_tag(self, tag_id: int) -> list[typing.Any]:
        """
        :param tag_id: the tag id for the child items
        :return: list of child items with this tag number
        """
        if not isinstance(self.value, list):
            raise ValueError("This object does not support child items")
        if not isinstance(tag_id, int):
            raise TypeError("Expected type: int; actual type: {0}".format(type(tag_id)))
        return [x for x in self.value if x.tag == tag_id]

    def get_items_by_name(self, name: str) -> list[typing.Any]:
        """
        :param name: the field name for the child items
        :return: list of child items with this name
        """
        if not isinstance(self.value, list):
            raise ValueError("This object does not support child items")
        if not isinstance(name, str):
            raise TypeError("Expected type: str; actual type: {0}".format(type(name)))
        return [x for x in self.value if x.name == name]

    def only(self, name: str, default=Empty):
        """
        Returns a single item which matches the name parameter. Use this to streamline getting non-repeating items
        :param name: the name of the child item
        :param default: optional: the value to return if the item is not present (default: None)
        :return: the single child item
        :exception: ValueError: if there is more than one child item which matches this name
        """
        got = self.get_items_by_name(name)
        if len(got) == 0:
            return default
        elif len(got) == 1:
            return got[0]
        else:
            raise ValueError("More than one value with this key")

    def __getitem__(self, key: typing.Union[str, int]) -> list[typing.Any]:
        if isinstance(key, str):
            return self.get_items_by_name(key)
        elif isinstance(key, int):
            return self.get_items_by_tag(key)
        else:
            raise TypeError("Key should be int or str; actual type: {0}".format(type(key)))

    def __len__(self) -> int:
        return self.value.__len__()

    def __iter__(self):
        if not isinstance(self.value, list):
            raise ValueError("This object does not support child items")
        else:
            yield from (x.tag for x in self.value)


class ProtoDecoder:
    def __init__(self, object_name, func):
        self.func = func
        self.object_name = object_name

    def __call__(self, arg):
        return self.func(arg)


def _read_le_varint(stream: typing.BinaryIO, is_32bit=False) -> typing.Optional[typing.Tuple[int, bytes]]:
    # this only outputs unsigned
    limit = 5 if is_32bit else 10
    i = 0
    result = 0
    underlying_bytes = []
    while i < limit:  # 64 bit max possible?
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


def read_le_varint(stream: typing.BinaryIO, is_32bit=False) -> typing.Optional[int]:
    x = _read_le_varint(stream, is_32bit)
    if x is None:
        return None
    else:
        return x[0]


def read_le_varint32(stream: typing.BinaryIO) -> typing.Optional[int]:
    return read_le_varint(stream, True)


def read_tag(
        stream: typing.BinaryIO,
        tag_mappings: dict[int, typing.Callable[[typing.BinaryIO], typing.Any]],
        log_out=sys.stderr, use_friendly_tag=False) -> typing.Optional[ProtoObject]:
    tag_id = read_le_varint(stream)
    if tag_id is None: 
        return None
    decoder = tag_mappings.get(tag_id if not use_friendly_tag else tag_id >> 3)
    name = None
    if isinstance(decoder, ProtoDecoder):
        name = decoder.object_name
    
    available_wirebytes = io.BytesIO(_get_bytes_for_wiretype(tag_id, stream))

    tag_value = decoder(available_wirebytes) if decoder else _fallback_decode(
        tag_id, available_wirebytes, log_out)
    
    return ProtoObject(tag_id, name, tag_value)


def read_protobuff(
        stream: typing.BinaryIO,
        tag_mappings: dict [int, typing.Callable[[typing.BinaryIO], typing.Any]],
        use_friendly_tag=False) -> list[ProtoObject]:
    result = []
    while True:
        tag = read_tag(stream, tag_mappings, use_friendly_tag=use_friendly_tag)
        if tag is None:
            break
        result.append(tag)

    return result


def read_blob(stream: typing.BinaryIO) -> bytes:
    blob_length = read_le_varint(stream)
    blob = stream.read(blob_length)
    return blob


def read_string(stream: typing.BinaryIO) -> str:
    raw_string = read_blob(stream)
    string = raw_string.decode("utf-8")
    return string


def read_double(stream: typing.BinaryIO) -> float:
    return struct.unpack("<d", stream.read(8))[0]


def read_long(stream: typing.BinaryIO) -> int:
    return struct.unpack("<q", stream.read(8))[0]


def read_int(stream: typing.BinaryIO) -> int:
    return struct.unpack("<i", stream.read(4))[0]


def read_embedded_protobuf(stream: typing.BinaryIO, mappings, use_friendly_tag=False) -> list[ProtoObject]:
    blob_blob = read_blob(stream)
    blob_stream = io.BytesIO(blob_blob)
    return read_protobuff(blob_stream, mappings, use_friendly_tag)


def read_fixed_blob(stream: typing.BinaryIO, length: int) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("Couldn't read enough data")
    return data


_fallback_wire_types = {
    0: read_le_varint,
    1: lambda x: read_fixed_blob(x, 8),
    2: read_blob,
    5: lambda x: read_fixed_blob(x, 4)
    }

_wire_type_friendly_names = {
    0: "Varint",
    1: "64-Bit",
    2: "Length Delimited",
    5: "32-Bit"
    }


def _get_bytes_for_wiretype(tag_id: int, stream: typing.BinaryIO):
    wire_type = tag_id & 0x07
    if wire_type == 0:
        read_bytes = []
        for i in range(10):
            x = stream.read(1)[0]
            read_bytes.append(x)
            if x & 0x80 == 0:
                break
        buffer = bytes(read_bytes)
    elif wire_type == 1:
        buffer = stream.read(8)
    elif wire_type == 2:
        l, b = _read_le_varint(stream)
        available_bytes = stream.read(l)
        if len(available_bytes) < l:
            raise ValueError("Stream too short")
        buffer = b + available_bytes
    elif wire_type == 5:
        buffer = stream.read(4)
    else:
        raise ValueError("Invalid wiretype")

    return buffer


def _fallback_decode(tag_id, stream, log):
    fallback_func = _fallback_wire_types.get(tag_id & 0x07)
    if not fallback_func:
        raise ValueError("No appropriate fallback function for tag {0} (wire type {1})".format(
            tag_id, tag_id & 0x07))
    if DEBUG:
        log.write("Tag {0} ({1}) not defined, using fallback decoding.\n".format(
            tag_id if tag_id > 0x7f else hex(tag_id), _wire_type_friendly_names[tag_id & 0x07]))
    return fallback_func(stream)
