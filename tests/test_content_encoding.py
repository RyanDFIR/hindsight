"""Cached bodies are decoded with a limit on how large the result may be."""
import gzip
import unittest
import zlib

import brotli
import zstd

from pyhindsight import content_encoding
from pyhindsight.content_encoding import DecodedSizeExceeded, NotDecodable, decode
from pyhindsight.lib import ccl_chromium_reader

PLAIN = b'<html><body>' + b'Hindsight ' * 500 + b'</body></html>'
LIMIT = 64 * 1024
ZEROS = b'\0' * (LIMIT * 16)

ZSTD_MAGIC = bytes.fromhex('28b52ffd')
# A block header marked last, type RLE, standing for one byte, then that byte.
ZSTD_LAST_RLE_BLOCK = bytes([0x0B, 0x00, 0x00, 0x00])


def deflate_raw(data):
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


ENCODERS = {
    'gzip': gzip.compress,
    'deflate': deflate_raw,
    'br': brotli.compress,
    'zstd': zstd.compress,
}


class TestDecode(unittest.TestCase):
    def test_each_encoding_round_trips(self):
        for encoding, encode in ENCODERS.items():
            with self.subTest(encoding=encoding):
                self.assertEqual(PLAIN, decode(encode(PLAIN), encoding))

    def test_whitespace_around_the_encoding_name_is_ignored(self):
        self.assertEqual(PLAIN, decode(gzip.compress(PLAIN), ' gzip '))

    def test_no_encoding_or_an_unknown_one_is_not_decoded(self):
        for encoding in ('', 'identity', 'compress', 'GZIP', 'gzip, br'):
            with self.subTest(encoding=encoding):
                self.assertIsNone(decode(gzip.compress(PLAIN), encoding))

    def test_a_body_that_is_not_the_encoding_it_claims_is_not_decodable(self):
        for encoding in ENCODERS:
            with self.subTest(encoding=encoding):
                with self.assertRaises(NotDecodable):
                    decode(b'this is not compressed data at all', encoding)

    def test_a_truncated_body_is_not_decodable(self):
        for encoding, encode in ENCODERS.items():
            with self.subTest(encoding=encoding):
                with self.assertRaises(NotDecodable):
                    decode(encode(PLAIN)[:-6], encoding)

    def test_gzip_members_one_after_another_are_joined(self):
        body = gzip.compress(b'first ') + b'\0\0\0' + gzip.compress(b'second')
        self.assertEqual(b'first second', decode(body, 'gzip'))

    def test_an_empty_gzip_body_decodes_to_nothing(self):
        # What gzip.decompress does, and so what ccl did.
        self.assertEqual(b'', decode(b'', 'gzip'))


class TestSizeLimit(unittest.TestCase):
    def test_a_body_that_expands_past_the_limit_is_refused(self):
        for encoding, encode in ENCODERS.items():
            with self.subTest(encoding=encoding):
                bomb = encode(ZEROS)
                self.assertLess(len(bomb), LIMIT // 8)
                with self.assertRaises(DecodedSizeExceeded) as raised:
                    decode(bomb, encoding, max_size=LIMIT)
                self.assertEqual(encoding, raised.exception.encoding)
                self.assertEqual(LIMIT, raised.exception.limit)

    def test_a_body_exactly_at_the_limit_is_decoded(self):
        exact = b'\0' * LIMIT
        for encoding, encode in ENCODERS.items():
            with self.subTest(encoding=encoding):
                self.assertEqual(exact, decode(encode(exact), encoding, max_size=LIMIT))

    def test_one_byte_past_the_limit_is_refused(self):
        over = b'\0' * (LIMIT + 1)
        for encoding, encode in ENCODERS.items():
            with self.subTest(encoding=encoding):
                with self.assertRaises(DecodedSizeExceeded):
                    decode(encode(over), encoding, max_size=LIMIT)

    def test_gzip_members_count_towards_one_limit(self):
        member = gzip.compress(b'\0' * (LIMIT // 2 + 1))
        with self.assertRaises(DecodedSizeExceeded):
            decode(member + member, 'gzip', max_size=LIMIT)

    def test_zstd_frames_count_towards_one_limit(self):
        frame = zstd.compress(b'\0' * (LIMIT // 2 + 1))
        with self.assertRaises(DecodedSizeExceeded):
            decode(frame + frame, 'zstd', max_size=LIMIT)
        self.assertEqual(b'\0' * (LIMIT + 2), decode(frame + frame, 'zstd', max_size=LIMIT + 2))

    def test_a_zstd_frame_claiming_a_huge_size_is_refused_before_decoding(self):
        # Descriptor 0x80: a four-byte Frame_Content_Size after the window byte.
        frame = ZSTD_MAGIC + b'\x80\x58' + (0xFFFFFFFF).to_bytes(4, 'little') + ZSTD_LAST_RLE_BLOCK
        with self.assertRaises(DecodedSizeExceeded):
            decode(frame, 'zstd', max_size=LIMIT)

    def test_a_zstd_frame_with_no_declared_size_is_not_decoded(self):
        # Descriptor 0x00: a window byte and no Frame_Content_Size. A server that
        # compresses as it sends writes these, and the zstd package cannot decode them.
        frame = ZSTD_MAGIC + b'\x00\x58' + ZSTD_LAST_RLE_BLOCK
        with self.assertRaises(NotDecodable):
            decode(frame, 'zstd')

    def test_the_default_limit_is_what_the_module_says(self):
        self.assertEqual(256 * 1024 * 1024, content_encoding.MAX_DECODED_SIZE)


class TestSameAnswerAsCcl(unittest.TestCase):
    """Below the limit, a body decodes to what the bundled ccl would have made of it."""

    def bodies(self):
        for encoding, encode in ENCODERS.items():
            good = encode(PLAIN)
            yield encoding, 'valid', good
            yield encoding, 'truncated', good[:-6]
            yield encoding, 'trailing bytes', good + b'xyz'
            yield encoding, 'doubled', good + good
            yield encoding, 'not compressed', PLAIN
            yield encoding, 'empty', b''
        yield 'gzip', 'padded members', gzip.compress(b'a') + b'\0' * 4 + gzip.compress(b'b')
        yield 'gzip', 'bad checksum', gzip.compress(PLAIN)[:-8] + b'\0' * 8
        yield 'identity', 'no encoding', PLAIN

    def test_decoded_or_not_and_the_bytes_agree(self):
        ccl_decode = ccl_chromium_reader.ChromiumProfileFolder._decompress_cache_data
        for encoding, label, body in self.bodies():
            with self.subTest(encoding=encoding, body=label):
                was_decoded, expected = ccl_decode(body, encoding)
                try:
                    decoded = decode(body, encoding)
                except NotDecodable:
                    decoded = None
                self.assertEqual(was_decoded, decoded is not None)
                if was_decoded:
                    self.assertEqual(expected, decoded)


if __name__ == '__main__':
    unittest.main()
