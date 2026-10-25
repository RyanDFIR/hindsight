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

import io
import datetime
import struct
import os


__version__ = "0.1"
__description__ = "Module for reading Chromium Pickles."
__contact__ = "Alex Caithness"


class EasyPickleException(Exception):
    ...


class EasyPickleIterator:
    """
    A pythonic implementation of the PickleIterator object used in various places in Chrom(e|ium).
    """
    def __init__(self, data: bytes, alignment: int=4):
        """
        Takes a bytes buffer and wraps the EasyPickleIterator around it
        :param data: the data to be wrapped
        :param alignment: (optional) the number of bytes to align reads to (default: 4)
        """
        self._f = io.BytesIO(data)
        self._alignment = alignment

        self._pickle_length = self.read_uint32()
        if len(data) != self._pickle_length + 4:
            raise EasyPickleException("pickle length invalid")

    def __enter__(self) -> "EasyPickleIterator":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self._f.close()

    def read_aligned(self, length: int) -> bytes:
        """
        reads the number of bytes specified by the length parameter. Aligns the buffer afterwards if required.
        :param length: the length od data to be read
        :return: the data read (without the alignment padding)
        """
        raw = self._f.read(length)
        if len(raw) != length:
            raise EasyPickleException(f"Tried to read {length} bytes but only got {len(raw)}")

        align_count = self._alignment - (length % self._alignment)
        if align_count != self._alignment:
            self._f.seek(align_count, os.SEEK_CUR)

        return raw

    def read_uint16(self) -> int:
        raw = self.read_aligned(2)
        return struct.unpack("<H", raw)[0]

    def read_uint32(self) -> int:
        raw = self.read_aligned(4)
        return struct.unpack("<I", raw)[0]

    def read_uint64(self) -> int:
        raw = self.read_aligned(8)
        return struct.unpack("<Q", raw)[0]

    def read_int16(self) -> int:
        raw = self.read_aligned(2)
        return struct.unpack("<h", raw)[0]

    def read_int32(self) -> int:
        raw = self.read_aligned(4)
        return struct.unpack("<i", raw)[0]

    def read_int64(self) -> int:
        raw = self.read_aligned(8)
        return struct.unpack("<q", raw)[0]

    def read_bool(self) -> bool:
        raw = self.read_int32()
        if raw == 0:
            return False
        elif raw == 1:
            return True
        else:
            raise EasyPickleException("bools should only contain 0 or 1")

    def read_single(self) -> float:
        raw = self.read_aligned(4)
        return struct.unpack("<f", raw)[0]

    def read_double(self) -> float:
        raw = self.read_aligned(8)
        return struct.unpack("<d", raw)[0]

    def read_string(self) -> str:
        length = self.read_uint32()
        raw = self.read_aligned(length)
        return raw.decode("utf-8")

    def read_string16(self) -> str:
        length = self.read_uint32() * 2  # character count
        raw = self.read_aligned(length)
        return raw.decode("utf-16-le")

    def read_datetime(self) -> datetime.datetime:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=self.read_uint64())

