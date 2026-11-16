"""Decode an HTTP content-encoding, refusing to produce more than a set number of bytes.

A cached response body is stored as the server sent it, and the server chose those bytes.
gzip, deflate, Brotli and zstd can all describe a very long run of repeated data in a
few bytes: 106 bytes of Brotli expand to 64 MiB. A browser decodes such a body as a
stream and never holds it whole, but Hindsight decodes each body into memory to hash it,
so one small cache entry could ask for more memory than the machine has. Every decoder
here stops once its output passes a limit and raises DecodedSizeExceeded.
"""
import zlib

import brotli
import zstd

# The most bytes one body may decode to. A real page resource of this size would be
# remarkable, and it is small enough that decoding one does no harm.
MAX_DECODED_SIZE = 256 * 1024 * 1024

# The most that the bodies of one cache may grow by when decoded, counted as decoded
# size less stored size. The limit above is on each body, and a cache can hold
# thousands of bodies that each stay just under it. The caller keeps this count.
MAX_CACHE_EXPANSION = 4 * 1024 * 1024 * 1024

_ZSTD_FRAME_MAGIC = 0xFD2FB528
_ZSTD_SKIPPABLE_MAGIC = 0x184D2A50  # the low four bits vary


class DecodedSizeExceeded(Exception):
    """The body would decode to more than the limit, so it was not decoded."""

    def __init__(self, encoding, limit):
        super().__init__(f'{encoding} body decodes to more than {limit} bytes')
        self.encoding = encoding
        self.limit = limit


class NotDecodable(Exception):
    """The bytes are not a complete, valid stream of the encoding they claim to be."""


def decode(data, content_encoding, max_size=MAX_DECODED_SIZE):
    """Decode `data` as `content_encoding` and return the decoded bytes.

    Returns None when the encoding is not one of gzip, br, deflate and zstd, which
    includes there being no encoding at all. Raises NotDecodable when the bytes are not
    a complete valid stream, and DecodedSizeExceeded when decoding them would produce
    more than `max_size` bytes. In both cases the caller still has the bytes as stored.
    """
    encoding = content_encoding.strip()
    try:
        if encoding == 'gzip':
            return _inflate(data, 16 + zlib.MAX_WBITS, max_size, encoding, members=True)
        if encoding == 'deflate':
            # Raw deflate, with no zlib header to read.
            return _inflate(data, -zlib.MAX_WBITS, max_size, encoding, members=False)
        if encoding == 'br':
            return _brotli(data, max_size)
        if encoding == 'zstd':
            return _zstd(data, max_size)
    except (zlib.error, brotli.error, zstd.Error) as e:
        raise NotDecodable(str(e)) from e
    return None


def _inflate(data, wbits, max_size, encoding, members):
    """gzip (`members` True: one stream after another is allowed) or raw deflate."""
    chunks = []
    total = 0
    while data:
        decoder = zlib.decompressobj(wbits)
        # One byte more than is allowed, so that reaching the limit exactly can be
        # told apart from passing it.
        chunk = decoder.decompress(data, max_size - total + 1)
        total += len(chunk)
        if total > max_size:
            raise DecodedSizeExceeded(encoding, max_size)
        chunks.append(chunk)
        if not decoder.eof:
            raise NotDecodable(f'{encoding} stream ends before it is complete')
        if not members:
            return b''.join(chunks)
        # A gzip file may be several members, with zero padding between them.
        data = decoder.unused_data.lstrip(b'\x00')
    if not members:
        raise NotDecodable(f'{encoding} stream is empty')
    return b''.join(chunks)


def _brotli(data, max_size):
    decoder = brotli.Decompressor()
    chunks = []
    total = 0
    pending = data
    while True:
        # The limit is on how far the output buffer grows in this call, and the call
        # can pass it by part of a buffer, which is why the total is checked after.
        chunk = decoder.process(pending, output_buffer_limit=max_size - total + 1)
        pending = b''
        total += len(chunk)
        if total > max_size:
            raise DecodedSizeExceeded('br', max_size)
        chunks.append(chunk)
        if decoder.is_finished():
            return b''.join(chunks)
        if decoder.can_accept_more_data():
            # It wants input and there is none left.
            raise NotDecodable('br stream ends before it is complete')


def _zstd(data, max_size):
    # The zstd package decodes in one call with no limit to give it. It does refuse a
    # frame that does not declare its decoded size, and it fails a frame whose content
    # is not the size declared, so the sizes in the frame headers are the size of the
    # output and can be added up before anything is decoded.
    declared = _zstd_declared_size(data)
    if declared is None:
        raise NotDecodable('zstd frame does not declare its decoded size')
    if declared > max_size:
        raise DecodedSizeExceeded('zstd', max_size)
    return zstd.decompress(data)


def _zstd_declared_size(data):
    """Total of the decoded sizes declared by every frame in `data`, or None.

    None means a frame does not declare its size or the frames could not be walked.
    Layout is from RFC 8878 section 3.1.
    """
    total = 0
    position = 0
    end = len(data)
    if not end:
        return None
    while position < end:
        if position + 4 > end:
            return None
        magic = int.from_bytes(data[position:position + 4], 'little')
        if magic & 0xFFFFFFF0 == _ZSTD_SKIPPABLE_MAGIC:
            if position + 8 > end:
                return None
            position += 8 + int.from_bytes(data[position + 4:position + 8], 'little')
            continue
        if magic != _ZSTD_FRAME_MAGIC or position + 5 > end:
            return None

        descriptor = data[position + 4]
        size_flag = descriptor >> 6
        single_segment = (descriptor >> 5) & 1
        has_checksum = (descriptor >> 2) & 1
        dictionary_id_size = (0, 1, 2, 4)[descriptor & 3]
        size_field = (0, 2, 4, 8)[size_flag]
        if size_flag == 0 and single_segment:
            size_field = 1
        if not size_field:
            return None

        position += 5
        if not single_segment:
            position += 1  # window descriptor
        position += dictionary_id_size
        if position + size_field > end:
            return None
        size = int.from_bytes(data[position:position + size_field], 'little')
        if size_field == 2:
            size += 256
        total += size
        position += size_field

        # Blocks, to find where this frame ends and the next begins.
        while True:
            if position + 3 > end:
                return None
            header = int.from_bytes(data[position:position + 3], 'little')
            block_type = (header >> 1) & 3
            if block_type == 3:
                return None
            # An RLE block is one byte however long the run it stands for.
            position += 3 + (1 if block_type == 1 else header >> 3)
            if header & 1:
                break
        if has_checksum:
            position += 4
    if position != end:
        return None
    return total
