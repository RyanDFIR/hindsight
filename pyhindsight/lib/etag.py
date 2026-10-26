"""Decode HTTP ETags that carry a server-side file's modification time or size.

An ETag is opaque by definition (RFC 9110, section 8.8.3): a server may put anything
in it, and a client is only meant to compare one for equality. In practice the common
servers and object stores build theirs from the file's metadata in a fixed way, so the
value can be read back into when the file was last modified on the server, and how
big it was:

    nginx               "<mtime>-<size>"              hex; mtime in seconds
    Apache httpd        "[<inode>-]<size>-<mtime>"    hex; mtime in microseconds;
                                                      mod_deflate / mod_brotli append
                                                      -gzip / -br
    Express (send)      W/"<size>-<mtime>"            hex; mtime in milliseconds
    Express (body)      W/"<size>-<sha1>"             hex size; first 27 characters of
                                                      the body's base64 SHA-1
    Tomcat              W/"<size>-<mtime>"            decimal; mtime in milliseconds
    IIS                 "<FILETIME>:<change number>"  each byte of the little-endian
                                                      FILETIME as unpadded hex
    ASP.NET Core        "<FILETIME XOR size>"         hex
    .NET (other)        "<FILETIME>"                  upper-case hex
    Azure Blob Storage  "0x<ticks>"                   hex .NET ticks; GitHub release
                                                      downloads are served from here
    Amazon S3, Swift    "<md5>" / "<md5>-<parts>"     MD5 of the object; an S3 multipart
                                                      upload's is not an MD5 of the file
    Akamai NetStorage   "<md5>:<seconds>[.<fraction>]"
                                                      MD5 of the object; suffix undocumented
    althttpd (SQLite)   "m<mtime>s<size>"             hex; mtime in seconds
    Werkzeug (Flask)    "<mtime>-<size>[-<adler32>]"  decimal; mtime in seconds
    Qiniu Kodo          "<qetag>"                     SHA-1 of the content

What a decoded value says is still only what the server claimed. It is worth most
where it agrees with something recorded independently, so every decode is checked
against the Last-Modified header and the byte count the browser stored for the same
response, and the notes say which checks passed. A decode that every available check
contradicts is discarded rather than reported, and the formats whose shape alone does
not identify them (ASP.NET Core, a bare Unix timestamp) are only decoded when
Last-Modified confirms them; without one they are shown as unconfirmed.

The forensic method this supports, tying a download to a later re-acquisition of
the same file when the original is gone, is described in
https://thelocalh0st.com/posts/etag-download-forensics/
"""

import base64
import dataclasses
import datetime
import email.utils
import hashlib
import itertools
import re

UTC = datetime.timezone.utc

# A decoded time outside these bounds means the shape matched by accident: most of the
# formats are "some hex digits", and an arbitrary hex string read as a timestamp lands
# almost anywhere. Server and client clocks do disagree, so a file may appear to have
# been modified a little after the browser fetched it.
EARLIEST_PLAUSIBLE_TIME = datetime.datetime(1990, 1, 1, tzinfo=UTC)
CLOCK_SKEW_ALLOWANCE = datetime.timedelta(days=2)
LARGEST_PLAUSIBLE_SIZE = 1 << 40  # 1 TiB

_UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=UTC)
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=UTC)
_DOTNET_EPOCH = datetime.datetime(1, 1, 1, tzinfo=UTC)

# Part sizes the common S3 clients upload with, smallest first.
_COMMON_PART_SIZES_MIB = (5, 8, 10, 16, 25, 32, 50, 64, 100, 128, 256, 512, 1024)


@dataclasses.dataclass
class ETagAnalysis:
    """What could be read out of one ETag."""
    format: str
    weak: bool = False
    modified: datetime.datetime | None = None  # timezone-aware
    size: int | None = None
    notes: list = dataclasses.field(default_factory=list)

    @property
    def summary(self):
        return '; '.join(self.notes)


@dataclasses.dataclass
class _Candidate:
    format: str
    modified: datetime.datetime | None = None
    size: int | None = None
    notes: list = dataclasses.field(default_factory=list)
    # Only reported when Last-Modified confirms it, because the shape is too common
    # to identify the format on its own.
    needs_confirmation: bool = False


@dataclasses.dataclass
class _Context:
    header_time: datetime.datetime | None
    size: int | None
    latest: datetime.datetime
    body: bytes | None
    timezone: datetime.tzinfo
    encoded_size: int | None = None
    content_encoding: str | None = None
    encoded_md5: str | None = None

    def size_matches(self, value):
        return value is not None and value in (self.size, self.encoded_size)

    def body_mismatch(self, what):
        # Most servers hash the uncompressed object and let a CDN compress it, so a
        # compressed response is only a possible explanation for a mismatch.
        if self.content_encoding:
            return (f'does not match {what} (decoded from {self.content_encoding}; the ETag '
                    f'may describe the compressed bytes)')
        return f'does not match {what}'

    def plausible_time(self, value):
        if value is None or value > self.latest:
            return False
        # Earlier is accepted when Last-Modified agrees (reproducible builds use 1980).
        return value >= EARLIEST_PLAUSIBLE_TIME or (
            value >= _UNIX_EPOCH and self.header_time is not None
            and _same_second(value, self.header_time))

    def describe_time(self, value):
        return value.astimezone(self.timezone).strftime('%Y-%m-%d %H:%M:%S %Z').strip()


def _from_epoch(epoch, value, units_per_second):
    """`value` units after `epoch`, or None where that is not a representable date."""
    try:
        return epoch + datetime.timedelta(microseconds=value * 1_000_000 // units_per_second)
    except (OverflowError, ValueError):
        return None


def _parse_http_date(value):
    if isinstance(value, datetime.datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = email.utils.parsedate_to_datetime(value.strip())
        except (TypeError, ValueError, IndexError):
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _same_second(first, second):
    return int(first.timestamp()) == int(second.timestamp())


def _describe_duration(delta):
    return str(datetime.timedelta(seconds=int(abs(delta.total_seconds()))))


def _decode_azure(value, ctx):
    match = re.fullmatch(r'0x([0-9A-Fa-f]{15,16})', value)
    if not match:
        return []
    modified = _from_epoch(_DOTNET_EPOCH, int(match.group(1), 16), 10_000_000)
    if not ctx.plausible_time(modified):
        return []
    return [_Candidate('Azure Blob Storage', modified=modified)]


def _decode_microsoft_distribute(value, ctx):
    # Microsoft's download servers (Visual Studio, .NET, Windows ISOs). Not a time, and
    # not the file's SHA-256 (which Visual Studio download URLs carry).
    if not re.fullmatch(r'0x[0-9A-Fa-f]{64}', value):
        return []
    return [_Candidate('Microsoft Distribute (0x + 256 bits)',
                       notes=['not a time and not the file\'s SHA-256; compare the whole '
                              'value with a later download of the same file'])]


def _decode_s3_multipart(value, ctx):
    match = re.fullmatch(r'([0-9a-fA-F]{32})-(\d{1,5})', value)
    if not match or not 1 <= int(match.group(2)) <= 10_000:
        return []
    parts = int(match.group(2))
    notes = [f'multipart upload in {parts} part{"s" if parts > 1 else ""}; '
             f'not an MD5 of the file']
    if ctx.size and parts > 1:
        # Every part but the last is the same size, so the part size P satisfies
        # (parts - 1) * P < size <= parts * P.
        fits = [mib for mib in _COMMON_PART_SIZES_MIB
                if (parts - 1) * mib * 1024 * 1024 < ctx.size <= parts * mib * 1024 * 1024]
        if fits:
            listed = ', '.join(str(mib) for mib in fits[:-1]) + (' or ' if len(fits) > 1 else '')
            notes.append(f'size consistent with {listed}{fits[-1]} MiB parts')
    return [_Candidate('Amazon S3 multipart', notes=notes)]


def _decode_md5(value, ctx):
    if not re.fullmatch(r'[0-9a-fA-F]{32}', value):
        return []
    notes = ['usually the MD5 of the content (Amazon S3 single-part uploads, OpenStack '
             'Swift and others); compare with the MD5 of a recovered copy']
    notes += _check_md5(value, ctx)
    return [_Candidate('MD5 hash', notes=notes)]


def _check_md5(digest, ctx):
    if not ctx.body:
        return []
    if hashlib.md5(ctx.body, usedforsecurity=False).hexdigest() == digest.lower():
        return ['matches the MD5 of the cached body']
    if ctx.encoded_md5 == digest.lower():
        return [f'matches the MD5 of the cached body as sent ({ctx.content_encoding}-compressed)']
    return [ctx.body_mismatch('the MD5 of the cached body')]


def _decode_netstorage(value, ctx):
    """Akamai NetStorage's "<md5>:<seconds>[.<fraction>]".

    The suffix is undocumented and is often minutes or days from Last-Modified, so it
    is compared with it but not reported as the modification time.
    """
    match = re.fullmatch(r'([0-9a-fA-F]{32}):(\d{1,12})(?:\.\d{1,9})?', value)
    if not match:
        return []
    digest, seconds = match.groups()
    notes = ['usually the MD5 of the content; compare with the MD5 of a recovered copy']
    notes += _check_md5(digest, ctx)
    suffix = f'suffix {value.partition(":")[2]} is not read as the modification time'
    suffix_time = _from_epoch(_UNIX_EPOCH, int(seconds), 1)
    if suffix_time is not None and ctx.header_time is not None:
        if _same_second(suffix_time, ctx.header_time):
            suffix += '; as a Unix time it is the second of Last-Modified'
        else:
            direction = 'before' if suffix_time < ctx.header_time else 'after'
            suffix += (f'; as a Unix time it is {_describe_duration(suffix_time - ctx.header_time)} '
                       f'{direction} Last-Modified')
    notes.append(suffix)
    return [_Candidate('Akamai NetStorage-style', notes=notes)]


def _decode_althttpd(value, ctx):
    # althttpd.c: sprintf(zETag, "m%xs%x", (int)pStat->st_mtime, (int)pStat->st_size)
    match = re.fullmatch(r'm([0-9a-f]{1,8})s([0-9a-f]{1,8})', value)
    if not match:
        return []
    modified = _from_epoch(_UNIX_EPOCH, int(match.group(1), 16), 1)
    if not ctx.plausible_time(modified):
        return []
    return [_Candidate('althttpd (SQLite)', modified=modified, size=int(match.group(2), 16))]


def _decode_werkzeug(value, ctx):
    # send_file: "<mtime>-<size>-<adler32 of the path>" in 2.x, "<mtime>-<size>" in 3.x.
    match = re.fullmatch(r'(\d{9,10}\.\d{1,9})-(\d{1,13})(?:-(\d{1,10}))?', value)
    if not match:
        return []
    modified = _from_epoch(_UNIX_EPOCH, round(float(match.group(1)) * 1_000_000), 1_000_000)
    size = int(match.group(2))
    if not ctx.plausible_time(modified) or size > LARGEST_PLAUSIBLE_SIZE:
        return []
    notes = [f'adler32 of the file\'s path on the server {match.group(3)}'] if match.group(3) else []
    return [_Candidate('Werkzeug (Flask)', modified=modified, size=size, notes=notes)]


_QINIU_BLOCK_SIZE = 4 * 1024 * 1024


def _decode_qiniu(value, ctx):
    # URL-safe base64 of 0x16 and the file's SHA-1, or for over 4 MiB, 0x96 and the
    # SHA-1 of its 4 MiB blocks' SHA-1s.
    if not re.fullmatch(r'[Fl][A-Za-z0-9_-]{27}', value):
        return []
    raw = base64.urlsafe_b64decode(value)
    if raw[0] not in (0x16, 0x96):
        return []
    multi_block = raw[0] == 0x96
    notes = ['SHA-1 of the 4 MiB blocks\' SHA-1s; the file is over 4 MiB' if multi_block
             else 'SHA-1 of the content; the file is 4 MiB or less']
    if ctx.size and (ctx.size > _QINIU_BLOCK_SIZE) != multi_block:
        notes.append('the recorded size is on the other side of 4 MiB')
    if ctx.body:
        notes.append('matches the cached body' if raw == _qetag(ctx.body)
                     else ctx.body_mismatch('the cached body'))
    return [_Candidate('Qiniu Kodo', notes=notes)]


def _qetag(body):
    def sha1(data):
        return hashlib.sha1(data, usedforsecurity=False).digest()

    if len(body) <= _QINIU_BLOCK_SIZE:
        return b'\x16' + sha1(body)
    return b'\x96' + sha1(b''.join(sha1(body[i:i + _QINIU_BLOCK_SIZE])
                                   for i in range(0, len(body), _QINIU_BLOCK_SIZE)))


def _iis_filetimes(digits):
    """Every FILETIME the digits before an IIS ETag's colon can be read as.

    IIS writes each byte of the little-endian FILETIME with an unpadded %x, so a byte
    under 0x10 takes one digit and every other byte two, and nothing marks which is
    which. Each way of dividing the digits into eight bytes is a possible value.
    """
    two_digit_bytes = len(digits) - 8
    if not 0 <= two_digit_bytes <= 8:
        return
    for wide in itertools.combinations(range(8), two_digit_bytes):
        position, octets = 0, []
        for index in range(8):
            width = 2 if index in wide else 1
            chunk = digits[position:position + width]
            position += width
            if width == 2 and chunk[0] == '0':
                break  # %x never writes a leading zero
            octets.append(int(chunk, 16))
        else:
            yield _from_epoch(_FILETIME_EPOCH, int.from_bytes(bytes(octets), 'little'), 10_000_000)


def _decode_iis(value, ctx):
    match = re.fullmatch(r'([0-9a-f]{8,16}):([0-9a-f]{1,8})', value)
    if not match:
        return []
    change_number = int(match.group(2), 16)
    notes = [f'configuration change number {change_number}'] if change_number else []
    times = sorted(t for t in _iis_filetimes(match.group(1)) if ctx.plausible_time(t))

    # The ambiguity only shows in the low-order bytes when the digits happen to split
    # more than one way, and Last-Modified (the same FILETIME, to the second) settles it.
    if ctx.header_time is not None:
        confirmed = [t for t in times if _same_second(t, ctx.header_time)]
        if confirmed:
            return [_Candidate('IIS', modified=confirmed[0], notes=notes)]
        if times:
            notes.append(f'none of the {len(times)} possible timestamps matches Last-Modified')
        return [_Candidate('IIS', notes=notes)]
    if len(times) == 1:
        return [_Candidate('IIS', modified=times[0], notes=notes)]
    if times:
        notes.append(f'{len(times)} possible timestamps from {ctx.describe_time(times[0])} '
                     f'to {ctx.describe_time(times[-1])}; Last-Modified is needed to choose')
    return [_Candidate('IIS', notes=notes)]


def _decode_tomcat(value, ctx):
    match = re.fullmatch(r'(\d{1,13})-(\d{12,13})', value)
    if not match:
        return []
    modified = _from_epoch(_UNIX_EPOCH, int(match.group(2)), 1000)
    size = int(match.group(1))
    if not ctx.plausible_time(modified) or size > LARGEST_PLAUSIBLE_SIZE:
        return []
    return [_Candidate('Tomcat', modified=modified, size=size)]


def _decode_express_body(value, ctx):
    match = re.fullmatch(r'([0-9a-f]{1,10})-([A-Za-z0-9+/]{27})', value)
    if not match:
        return []
    notes = ['body SHA-1 (base64, first 27 characters)']
    if ctx.body:
        digest = base64.b64encode(hashlib.sha1(ctx.body, usedforsecurity=False).digest()).decode()
        notes.append('matches the cached body' if digest[:27] == match.group(2)
                     else ctx.body_mismatch('the cached body'))
    return [_Candidate('Express (Node.js)', size=int(match.group(1), 16), notes=notes)]


def _decode_size_and_mtime(value, ctx):
    """The hyphenated hex forms: nginx, Apache httpd and Express static files.

    All three are "hex-hex" and differ in field order and time unit. The units put
    the time field at different lengths (8 digits for seconds, 10-11 for milliseconds,
    13 for microseconds over the plausible range), so usually only one reading
    survives the plausibility bounds; where more do, the checks decide.
    """
    suffix = None
    compressed = re.fullmatch(r'(.+)-(gzip|br)', value)
    if compressed:
        value, suffix = compressed.groups()

    candidates = []
    apache_notes = [f'compressed variant (-{suffix}); size is of the uncompressed file'] if suffix else []

    match = re.fullmatch(r'([0-9a-f]{1,16})-([0-9a-f]{1,16})-([0-9a-f]{1,16})', value)
    if match:
        inode, size, mtime = (int(field, 16) for field in match.groups())
        modified = _from_epoch(_UNIX_EPOCH, mtime, 1_000_000)
        if ctx.plausible_time(modified) and size <= LARGEST_PLAUSIBLE_SIZE:
            candidates.append(_Candidate('Apache httpd', modified=modified, size=size,
                                         notes=[f'inode {inode}'] + apache_notes))
        return candidates

    match = re.fullmatch(r'([0-9a-f]{1,16})-([0-9a-f]{1,16})', value)
    if not match:
        return candidates
    first, second = (int(field, 16) for field in match.groups())

    # (format, size, mtime, mtime units per second, notes). Only Apache adds the
    # compression suffix, so a suffixed value is only read as Apache.
    readings = [('Apache httpd', first, second, 1_000_000, apache_notes)]
    if not suffix:
        readings = [('nginx', second, first, 1, [])] + readings + [
            ('Express (Node.js)', first, second, 1000, [])]
    for name, size, mtime, units_per_second, notes in readings:
        modified = _from_epoch(_UNIX_EPOCH, mtime, units_per_second)
        if ctx.plausible_time(modified) and size <= LARGEST_PLAUSIBLE_SIZE:
            candidates.append(_Candidate(name, modified=modified, size=size, notes=list(notes)))
    return candidates


def _decode_filetime_hex(value, ctx):
    """A FILETIME in hex, as .NET servers write it.

    ASP.NET Core's static files write the FILETIME XORed with the file's length, in
    lower case. Upper case is the FILETIME as it is (seen from an Optimizely CMS site,
    always matching Last-Modified). The length only touches the low-order digits, so
    an XORed value still lands near the right time when the length is unknown.
    """
    if not re.fullmatch(r'[0-9a-fA-F]{15,16}', value):
        return []
    if value == value.lower():
        name, filetime = 'ASP.NET Core', int(value, 16) ^ (ctx.size or 0)
    else:
        name, filetime = '.NET (FILETIME)', int(value, 16)
    modified = _from_epoch(_FILETIME_EPOCH, filetime, 10_000_000)
    if not ctx.plausible_time(modified):
        return []
    return [_Candidate(name, modified=modified, needs_confirmation=True)]


def _decode_unix_seconds(value, ctx):
    if not re.fullmatch(r'\d{9,10}', value):
        return []
    modified = _from_epoch(_UNIX_EPOCH, int(value), 1)
    if not ctx.plausible_time(modified):
        return []
    return [_Candidate('Unix timestamp', modified=modified, needs_confirmation=True)]


_DECODERS = (
    _decode_azure,
    _decode_microsoft_distribute,
    _decode_s3_multipart,
    _decode_md5,
    _decode_netstorage,
    _decode_althttpd,
    _decode_werkzeug,
    _decode_qiniu,
    _decode_iis,
    _decode_tomcat,
    _decode_express_body,
    _decode_size_and_mtime,
    _decode_filetime_hex,
    _decode_unix_seconds,
)


def analyze(etag, last_modified=None, size=None, reference_time=None,
            reference_label='the download', size_label='total bytes', body=None, timezone=UTC,
            content_encoding=None, encoded_size=None, encoded_md5=None):
    """Identify the server format behind an ETag and decode what it carries.

    :param etag: The ETag header value as the browser stored it, quotes and W/ included.
    :param last_modified: The Last-Modified value stored with it, as an HTTP-date
        string or a datetime. Used to confirm a decoded time.
    :param size: The byte count the browser recorded for the same response, to
        confirm a decoded size.
    :param reference_time: When the browser fetched the response. A decoded time well
        after it is implausible, and the gap before it is reported.
    :param reference_label: How the notes refer to the fetch ("the download").
    :param size_label: How the notes refer to `size` ("total bytes").
    :param body: The response body, where it is held, to check a content hash against.
    :param timezone: Timezone for the times written into the notes.
    :param content_encoding: The response's Content-Encoding, when `size` and `body`
        describe it after decoding. A server serving a precompressed file builds the
        ETag from the compressed one.
    :param encoded_size: The response's Content-Length before decoding, which is what
        a decoded size matches in that case.
    :param encoded_md5: The MD5 (hex) of the body as sent, before decoding, which is
        what an MD5 ETag matches in that case.
    :return: An ETagAnalysis, or None when there is no ETag.
    """
    if not isinstance(etag, str) or not etag.strip():
        return None

    value = etag.strip()
    weak = value[:2] in ('W/', 'w/')
    if weak:
        value = value[2:].strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]

    if reference_time is not None and reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=UTC)
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        size = None
    if not content_encoding or not isinstance(encoded_size, int) or encoded_size <= 0:
        encoded_size = None
    if not content_encoding or not isinstance(encoded_md5, str):
        encoded_md5 = None
    ctx = _Context(
        header_time=_parse_http_date(last_modified), size=size,
        latest=(reference_time or datetime.datetime.now(UTC)) + CLOCK_SKEW_ALLOWANCE,
        body=bytes(body) if body else None, timezone=timezone or UTC,
        encoded_size=encoded_size, content_encoding=content_encoding or None,
        encoded_md5=encoded_md5.lower() if encoded_md5 else None)

    weak_note = ['weak ETag: equivalent content, not necessarily the same bytes'] if weak else []

    scored = []
    for decoder in _DECODERS:
        for candidate in decoder(value, ctx):
            time_ok = size_ok = None
            if candidate.modified is not None and ctx.header_time is not None:
                time_ok = _same_second(candidate.modified, ctx.header_time)
            if candidate.size is not None and (ctx.size or ctx.encoded_size) is not None:
                size_ok = ctx.size_matches(candidate.size)
            checks = [check for check in (time_ok, size_ok) if check is not None]
            if checks and not any(checks):
                continue  # everything that could be checked disagrees
            if candidate.needs_confirmation and not time_ok:
                if ctx.header_time is not None:
                    continue
                # Nothing to check it against: show the reading, ranked below the rest.
                candidate = _Candidate(
                    f'{candidate.format} (unconfirmed)',
                    notes=[f'reads as {ctx.describe_time(candidate.modified)}; not confirmed: '
                           f'no Last-Modified to check against'])
                scored.append((-1, candidate))
                continue
            scored.append((checks.count(True) - checks.count(False), candidate))

    if not scored:
        return ETagAnalysis('Unrecognized', weak=weak, notes=weak_note)

    # Stable sort: among equal scores the decoder order above is the preference.
    scored.sort(key=lambda pair: -pair[0])
    best_score, best = scored[0]
    result = ETagAnalysis(best.format, weak=weak, modified=best.modified, size=best.size,
                          notes=weak_note + best.notes)

    # Without anything to check against, the format was chosen on the shape alone, and
    # a quarter of random "8 hex digits - hex digits" values read as nginx.
    time_checked = best.modified is not None and ctx.header_time is not None
    size_checked = best.size is not None and (ctx.size or ctx.encoded_size) is not None
    if (best.modified is not None or best.size is not None) and not (time_checked or size_checked):
        result.notes.append('not confirmed: no Last-Modified or size recorded to check against')

    if best.modified is not None and ctx.header_time is not None:
        if _same_second(best.modified, ctx.header_time):
            result.notes.append('time matches Last-Modified')
        else:
            direction = 'before' if best.modified < ctx.header_time else 'after'
            result.notes.append(f'time is {_describe_duration(best.modified - ctx.header_time)} '
                                f'{direction} Last-Modified')
    if best.size is not None and (ctx.size or ctx.encoded_size) is not None:
        compressed = f'the {ctx.content_encoding}-compressed Content-Length'
        if best.size == ctx.size:
            result.notes.append(f'size matches {size_label}')
        elif best.size == ctx.encoded_size:
            result.notes.append(f'size matches {compressed}')
        else:
            recorded = [f'{label} ({count:,})' for label, count in
                        ((size_label, ctx.size), (compressed, ctx.encoded_size)) if count]
            result.notes.append(f'size differs from {" and ".join(recorded)}')
    if best.modified is not None and reference_time is not None:
        gap = reference_time - best.modified
        if gap >= datetime.timedelta(0):
            result.notes.append(f'modified {_describe_duration(gap)} before {reference_label}')
        else:
            result.notes.append(f'modified {_describe_duration(gap)} after {reference_label} '
                                f'(server and browser clocks disagree?)')

    for score, other in scored[1:]:
        if score == best_score and other.format != best.format:
            reading = ctx.describe_time(other.modified) if other.modified else 'no time'
            result.notes.append(f'also reads as {other.format} ({reading})')
    return result
