import datetime
import os
import struct
import unittest

from pyhindsight.browsers.firefox import Firefox


FIXTURE_DIR = os.path.join('tests', 'fixtures', 'firefox')


def _make_firefox():
    ff = Firefox(FIXTURE_DIR, no_copy=True, temp_dir=None,
                 timezone=datetime.timezone.utc)
    ff.parsed_artifacts = []
    ff.parsed_storage = []
    ff.preferences = []
    return ff


def _snappy_encode_raw(data):
    # Literal-only snappy raw block, mirrors make_fixtures.py.
    out = bytearray()
    n = len(data)
    while True:
        if n < 0x80:
            out.append(n)
            break
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    i = 0
    while i < len(data):
        chunk_len = min(60, len(data) - i)
        out.append((chunk_len - 1) << 2)
        out.extend(data[i:i + chunk_len])
        i += chunk_len
    return bytes(out)


class TestSnappyDecompressor(unittest.TestCase):

    def test_round_trip_short_literal(self):
        payload = b'Hello, Firefox!'
        encoded = _snappy_encode_raw(payload)
        self.assertEqual(Firefox._snappy_decompress(encoded), payload)

    def test_round_trip_multichunk_literal(self):
        payload = b'A' * 200 + b'B' * 200
        encoded = _snappy_encode_raw(payload)
        self.assertEqual(Firefox._snappy_decompress(encoded), payload)

    def test_handles_back_references(self):
        # Literal "ABCDEFGH" then a 2-byte-offset copy of length 8 at offset 8.
        encoded = bytes([
            16,
            0x1C,
        ]) + b'ABCDEFGH' + bytes([
            (7 << 2) | 0x02,
            0x08, 0x00,
        ])
        self.assertEqual(Firefox._snappy_decompress(encoded),
                         b'ABCDEFGHABCDEFGH')


class TestMozLz4Decoder(unittest.TestCase):

    def test_decompresses_pure_literal_block(self):
        # LZ4 token 0x50: 5 literal bytes, 0 match bytes.
        payload = b'\x50hello'
        framed = b'mozLz40\x00' + struct.pack('<I', 5) + payload
        tmp = os.path.join(FIXTURE_DIR, '_tmp_mozlz4_test.bin')
        with open(tmp, 'wb') as f:
            f.write(framed)
        try:
            result = Firefox._decompress_jsonlz4(tmp)
            self.assertEqual(result, b'hello')
        finally:
            os.remove(tmp)

    def test_rejects_wrong_magic(self):
        tmp = os.path.join(FIXTURE_DIR, '_tmp_mozlz4_bad.bin')
        with open(tmp, 'wb') as f:
            f.write(b'NOTAMOZ\x00' + struct.pack('<I', 0))
        try:
            self.assertIsNone(Firefox._decompress_jsonlz4(tmp))
        finally:
            os.remove(tmp)


class TestStructuredCloneReader(unittest.TestCase):

    @staticmethod
    def _pair(tag, data):
        # 64-bit LE: high 32 bits = tag, low 32 = data.
        return struct.pack('<Q', (tag << 32) | data)

    def test_int32_value(self):
        buf = (
            self._pair(Firefox._SC_HEADER, 8) +
            self._pair(Firefox._SC_INT32, 42)
        )
        reader = Firefox._StructuredCloneReader(Firefox, buf)
        self.assertEqual(reader.read(), 42)

    def test_negative_int32(self):
        # 0xFFFFFFFF as signed int32 = -1.
        buf = (
            self._pair(Firefox._SC_HEADER, 8) +
            self._pair(Firefox._SC_INT32, 0xFFFFFFFF)
        )
        reader = Firefox._StructuredCloneReader(Firefox, buf)
        self.assertEqual(reader.read(), -1)

    def test_boolean_and_null(self):
        for sctag, data, expected in [
                (Firefox._SC_BOOLEAN, 1, True),
                (Firefox._SC_BOOLEAN, 0, False),
                (Firefox._SC_NULL, 0, None),
        ]:
            buf = self._pair(Firefox._SC_HEADER, 8) + self._pair(sctag, data)
            reader = Firefox._StructuredCloneReader(Firefox, buf)
            self.assertEqual(reader.read(), expected)

    def test_latin1_string(self):
        s = b'hello'
        data = 0x80000000 | len(s)
        body = s + b'\x00' * (8 - len(s))
        buf = (
            self._pair(Firefox._SC_HEADER, 8) +
            self._pair(Firefox._SC_STRING, data) +
            body
        )
        reader = Firefox._StructuredCloneReader(Firefox, buf)
        self.assertEqual(reader.read(), 'hello')

    def test_utf16_string(self):
        body = 'café'.encode('utf-16-le')
        data = len('café')
        padded = body + b'\x00' * (8 - len(body) % 8 if len(body) % 8 else 0)
        buf = (
            self._pair(Firefox._SC_HEADER, 8) +
            self._pair(Firefox._SC_STRING, data) +
            padded
        )
        reader = Firefox._StructuredCloneReader(Firefox, buf)
        self.assertEqual(reader.read(), 'café')

    def test_object_with_string_value(self):
        # {key: "v"} -> OBJECT_OBJECT, STRING("key"), STRING("v"), END_OF_KEYS.
        key_data = 0x80000000 | 3
        val_data = 0x80000000 | 1
        buf = (
            self._pair(Firefox._SC_HEADER, 8) +
            self._pair(Firefox._SC_OBJECT_OBJECT, 0) +
            self._pair(Firefox._SC_STRING, key_data) + b'key\x00\x00\x00\x00\x00' +
            self._pair(Firefox._SC_STRING, val_data) + b'v\x00\x00\x00\x00\x00\x00\x00' +
            self._pair(Firefox._SC_END_OF_KEYS, 0)
        )
        reader = Firefox._StructuredCloneReader(Firefox, buf)
        self.assertEqual(reader.read(), {'key': 'v'})

    def test_double(self):
        # Doubles are the raw 64-bit IEEE bit pattern; tag < SCTAG_HEADER.
        bits = struct.unpack('<Q', struct.pack('<d', 3.14))[0]
        buf = (
            self._pair(Firefox._SC_HEADER, 8) +
            struct.pack('<Q', bits)
        )
        reader = Firefox._StructuredCloneReader(Firefox, buf)
        self.assertAlmostEqual(reader.read(), 3.14)


class TestIDBKeyDecoder(unittest.TestCase):

    def test_string_key_with_byte_shift(self):
        # Type 0x30 = string; each char is stored as byte + 1.
        encoded = bytes([0x30]) + bytes(c + 1 for c in b'hello') + b'\x00'
        self.assertEqual(Firefox._decode_idb_key(encoded), 'hello')

    def test_empty_key(self):
        self.assertEqual(Firefox._decode_idb_key(b''), '')

    def test_float_key_roundtrip(self):
        import struct
        d = 42.5
        raw = bytearray(struct.pack('>d', d))
        raw[0] |= 0x80
        encoded = bytes([0x10]) + bytes(raw)
        result = Firefox._decode_idb_key(encoded)
        self.assertEqual(float(result), 42.5)


class TestLocalStorage(unittest.TestCase):
    def test_walk_fixture_storage_directory(self):
        ff = _make_firefox()
        reported = ff.get_local_storage(FIXTURE_DIR)

        # One origin, two key/value pairs (one raw, one snappy-compressed).
        # get_local_storage reports partial failures, so it returns a ParseResult;
        # the count is the first field.
        self.assertEqual(reported.count, 2)
        self.assertFalse(reported.is_partial)
        self.assertEqual(len(ff.parsed_storage), 2)

        by_key = {item.key: item for item in ff.parsed_storage}

        self.assertEqual(by_key['theme'].value, 'dark')
        self.assertEqual(by_key['theme'].origin, 'https://en.wikipedia.org')

        self.assertIn('recent_articles', by_key['app_state'].value)
        self.assertIn('Computer forensics', by_key['app_state'].value)

    def test_decode_origin_folder(self):
        self.assertEqual(
            Firefox._decode_origin_folder('https+++en.wikipedia.org'),
            'https://en.wikipedia.org')
        self.assertEqual(
            Firefox._decode_origin_folder('http+++localhost+8080'),
            'http://localhost:8080')


if __name__ == '__main__':
    unittest.main()
