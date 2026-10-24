import base64
import datetime
import email.utils
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
import zoneinfo

import openpyxl

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.webbrowser import WebBrowser
from pyhindsight.lib import etag

UTC = datetime.timezone.utc
IST = zoneinfo.ZoneInfo('Asia/Kolkata')
# A fetch time after every sample below, so none is rejected as being from the future.
FETCHED = datetime.datetime(2026, 10, 24, tzinfo=UTC)


def utc(*args):
    return datetime.datetime(*args, tzinfo=UTC)


class TestRealWorldETags(unittest.TestCase):
    """Each format against values real servers sent, with the headers sent beside them.

    Captured in October 2026 with `curl -I`. Every decoded time is checked against the
    Last-Modified header from the same response and every decoded size against its
    Content-Length, so a sample here is evidence for the format, not an assumption
    about it.
    """

    # (server it came from, ETag, Last-Modified, Content-Length,
    #  expected format, expected time to the second, expected size)
    SAMPLES = [
        # The worked example in https://thelocalh0st.com/posts/etag-download-forensics/
        ('nginx (article)', '"6ac46e19-13e7f8"', 'Tue, 06 Oct 2026 03:42:17 GMT', 1304568,
         'nginx', utc(2026, 10, 6, 3, 42, 17), 1304568),
        ('www.nasa.gov', '"6acca3e6-c6"', 'Mon, 12 Oct 2026 09:09:58 GMT', 198,
         'nginx', utc(2026, 10, 12, 9, 9, 58), 198),
        ('www.python.org', '"6703bf29-1adb060"', 'Mon, 07 Oct 2024 10:59:53 GMT', 28160096,
         'nginx', utc(2024, 10, 7, 10, 59, 53), 28160096),
        ('www.apache.org', '"3c2e-6470630308aec"', 'Sun, 28 Dec 2025 17:09:24 GMT', 15406,
         'Apache httpd', utc(2025, 12, 28, 17, 9, 24), 15406),
        ('downloads.apache.org', '"86413-5caef2edf0372"', 'Wed, 01 Sep 2021 13:38:35 GMT', 549907,
         'Apache httpd', utc(2021, 9, 1, 13, 38, 35), 549907),
        ('the.earth.li (PuTTY)', '"1a0898-658fb8c515bde"', 'Fri, 14 Aug 2026 06:01:14 GMT', 1706136,
         'Apache httpd', utc(2026, 8, 14, 6, 1, 14), 1706136),
        ('live.sysinternals.com', '"a6c8bf9fa5cdd1:0"', 'Thu, 15 Oct 2026 23:14:48 GMT', 4776760,
         'IIS', utc(2026, 10, 15, 23, 14, 48), None),
        ('live.sysinternals.com', '"07e79518efedc1:0"', 'Wed, 17 Jun 2026 19:20:12 GMT', 1809728,
         'IIS', utc(2026, 6, 17, 19, 20, 12), None),
        ('live.sysinternals.com', '"09e80f3a06cd91:0"', 'Tue, 11 Apr 2023 18:10:52 GMT', 944520,
         'IIS', utc(2023, 4, 11, 18, 10, 52), None),
        ('live.sysinternals.com', '"0e495bbd8b4cc1:0"', 'Wed, 07 Dec 2011 12:07:04 GMT', 7903,
         'IIS', utc(2011, 12, 7, 12, 7, 4), None),
        ('download.sysinternals.com', '"0x8DF2B14CD9F2C17"', 'Thu, 15 Oct 2026 23:34:05 GMT', 5144350,
         'Azure Blob Storage', utc(2026, 10, 15, 23, 34, 5), None),
        ('GitHub release (Git for Windows)', '"0x8DCE7807154A6C6"', 'Tue, 08 Oct 2024 10:03:22 GMT',
         68778832, 'Azure Blob Storage', utc(2024, 10, 8, 10, 3, 22), None),
        ('learn.microsoft.com', 'W/"4316-1a141555da0"', 'Thu, 15 Oct 2026 20:51:16 GMT', 17174,
         'Express (Node.js)', utc(2026, 10, 15, 20, 51, 16), 17174),
        ('support.microsoft.com', '"1dd626648e2d1ee"', 'Thu, 22 Oct 2026 20:45:34 GMT', 15086,
         'ASP.NET Core', utc(2026, 10, 22, 20, 45, 34), None),
        ('www.irs.gov', '"1792680962"', 'Thu, 22 Oct 2026 14:56:02 GMT', None,
         'Unix timestamp', utc(2026, 10, 22, 14, 56, 2), None),
    ]

    def test_each_sample_decodes_and_agrees_with_its_own_headers(self):
        for source, value, last_modified, size, fmt, modified, decoded_size in self.SAMPLES:
            with self.subTest(source=source, etag=value):
                result = etag.analyze(value, last_modified, size, reference_time=FETCHED)
                self.assertEqual(fmt, result.format)
                self.assertEqual(modified, result.modified.replace(microsecond=0))
                self.assertEqual(decoded_size, result.size)
                self.assertIn('time matches Last-Modified', result.notes)
                if decoded_size is not None:
                    self.assertIn('size matches total bytes', result.notes)

    def test_s3_multipart(self):
        # awscli.amazonaws.com/AWSCLIV2.msi: 50,204,672 bytes in 6 parts. The AWS CLI
        # uploads in 8 MiB parts, and 5 * 8 MiB < 50,204,672 <= 6 * 8 MiB.
        result = etag.analyze('"8584da86526b24ab6b47c4f45426f202-6"',
                              'Thu, 22 Oct 2026 19:05:14 GMT', 50204672)
        self.assertEqual('Amazon S3 multipart', result.format)
        self.assertIsNone(result.modified)
        self.assertIn('multipart upload in 6 parts; not an MD5 of the file', result.notes)
        self.assertIn('size consistent with 8 MiB parts', result.notes)

    def test_md5(self):
        result = etag.analyze('"45b4cc5ffeb4ba28564a5872331d3d40"')  # nodejs.org
        self.assertEqual('MD5 hash', result.format)
        self.assertIsNone(result.modified)
        self.assertIsNone(result.size)


class TestCorpusFindings(unittest.TestCase):
    """Cases found by running the decoder over the bf4sa_2025_bob-1 corpus root."""

    def test_a_precompressed_file_matches_the_compressed_length(self):
        # An Express origin serving .js.gz files: the ETag's size is the gzip file's
        # (501, the Content-Length), while the cache holds the decoded 963 bytes.
        mtime = datetime.datetime.fromtimestamp(0x1967e7e9c04 / 1000, UTC)
        result = etag.analyze('W/"1f5-1967e7e9c04"', email.utils.format_datetime(mtime, usegmt=True),
                              size=963, size_label='the cached body size',
                              content_encoding='gzip', encoded_size=501)
        self.assertEqual('Express (Node.js)', result.format)
        self.assertIn('size matches the gzip-compressed Content-Length', result.notes)

    def test_a_size_matching_neither_length_names_both(self):
        # The same origin behind a CDN that recompressed it as brotli.
        mtime = datetime.datetime.fromtimestamp(0x1967e7e9c04 / 1000, UTC)
        result = etag.analyze('W/"219-1967e7e9c04"', email.utils.format_datetime(mtime, usegmt=True),
                              size=799, size_label='the cached body size',
                              content_encoding='br', encoded_size=486)
        self.assertEqual('Express (Node.js)', result.format)
        self.assertIn('size differs from the cached body size (799) and the br-compressed '
                      'Content-Length (486)', result.notes)

    def test_a_hash_mismatch_on_a_compressed_response_says_why_it_might_be(self):
        value = hashlib.md5(b'hello').hexdigest()
        result = etag.analyze(value, body=b'jello', content_encoding='gzip', encoded_size=25)
        self.assertIn('does not match the MD5 of the cached body (decoded from gzip; the ETag '
                      'may describe the compressed bytes)', result.notes)

    def test_upper_case_filetime(self):
        # www.montereybayaquarium.org (Optimizely CMS); every one matched Last-Modified.
        result = etag.analyze('"1DA771657FC7680"', 'Fri, 15 Mar 2024 20:21:21 GMT')
        self.assertEqual('.NET (FILETIME)', result.format)
        self.assertEqual(utc(2024, 3, 15, 20, 21, 21), result.modified.replace(microsecond=0))
        self.assertEqual('Unrecognized', etag.analyze('"1DA771657FC7680"').format)


class TestDecoding(unittest.TestCase):

    def test_no_etag(self):
        for value in (None, '', '   ', b'"6ac46e19-13e7f8"', 12345):
            with self.subTest(value=value):
                self.assertIsNone(etag.analyze(value))

    def test_quotes_are_optional(self):
        # Chrome stores the header as the server sent it, and some servers omit the
        # quotes the RFC requires (upload.wikimedia.org among them).
        quoted = etag.analyze('"6ac46e19-13e7f8"')
        bare = etag.analyze('6ac46e19-13e7f8')
        self.assertEqual((quoted.format, quoted.modified, quoted.size),
                         (bare.format, bare.modified, bare.size))

    def test_weak_etags_still_decode_and_say_they_are_weak(self):
        # nginx turns its ETag weak when it gzips the response, and keeps the value.
        result = etag.analyze('W/"6ac46e19-13e7f8"')
        self.assertEqual('nginx', result.format)
        self.assertTrue(result.weak)
        self.assertEqual(1304568, result.size)
        self.assertTrue(result.notes[0].startswith('weak ETag'))

    def test_an_unknown_shape_is_unrecognized_not_guessed(self):
        # dl.google.com: hyphenated hex, but no reading of it gives a plausible time.
        result = etag.analyze('"6e71e56-e4d464d1"', 'Mon, 12 Oct 2026 20:47:03 GMT', 13283768)
        self.assertEqual('Unrecognized', result.format)
        self.assertIsNone(result.modified)
        self.assertIsNone(result.size)

    def test_a_decode_every_check_contradicts_is_discarded(self):
        # Shaped like nginx, but neither the time nor the size agrees with the response
        # it came with, so the shape matched by accident.
        result = etag.analyze('"6ac46e19-13e7f8"', 'Mon, 01 Jan 2024 00:00:00 GMT', 999)
        self.assertEqual('Unrecognized', result.format)

    def test_a_single_failed_check_is_reported_rather_than_hidden(self):
        # The time agrees, so the format is credible, and the size disagreeing is a
        # finding in its own right (a different copy, or a transformed response).
        result = etag.analyze('"6ac46e19-13e7f8"', 'Tue, 06 Oct 2026 03:42:17 GMT', 1000)
        self.assertEqual('nginx', result.format)
        self.assertIn('time matches Last-Modified', result.notes)
        self.assertIn('size differs from total bytes (1,000)', result.notes)

    def test_a_time_mismatch_says_by_how_much(self):
        result = etag.analyze('"6ac46e19-13e7f8"', 'Tue, 06 Oct 2026 05:42:17 GMT', 1304568)
        self.assertEqual('nginx', result.format)
        self.assertIn('time is 2:00:00 before Last-Modified', result.notes)

    def test_shapes_that_need_last_modified_are_not_reported_without_it(self):
        # Fifteen hex digits or ten decimal ones are common enough to match by chance.
        for value in ('"1dd626648e2d1ee"', '"1792680962"'):
            with self.subTest(etag=value):
                self.assertEqual('Unrecognized', etag.analyze(value, size=15086).format)

    def test_the_gap_before_the_download_is_reported(self):
        result = etag.analyze('"6ac46e19-13e7f8"', reference_time=utc(2026, 10, 7, 3, 42, 17))
        self.assertIn('modified 1 day, 0:00:00 before the download', result.notes)

    def test_a_time_after_the_download_is_flagged(self):
        result = etag.analyze('"6ac46e19-13e7f8"', reference_time=utc(2026, 10, 6, 3, 0, 0))
        self.assertIn('modified 0:42:17 after the download (server and browser clocks disagree?)',
                      result.notes)

    def test_a_time_far_after_the_download_is_not_a_timestamp(self):
        result = etag.analyze('"6ac46e19-13e7f8"', reference_time=utc(2020, 1, 1))
        self.assertEqual('Unrecognized', result.format)

    def test_a_decode_with_nothing_to_check_it_against_says_so(self):
        unchecked = etag.analyze('"6ac46e19-13e7f8"', reference_time=FETCHED)
        self.assertEqual('nginx', unchecked.format)
        self.assertIn('not confirmed: no Last-Modified or size recorded to check against',
                      unchecked.notes)
        for checked in (etag.analyze('"6ac46e19-13e7f8"', 'Tue, 06 Oct 2026 03:42:17 GMT'),
                        etag.analyze('"6ac46e19-13e7f8"', size=1304568)):
            with self.subTest(notes=checked.notes):
                self.assertFalse(any(note.startswith('not confirmed') for note in checked.notes))

    def test_iis_without_last_modified_lists_the_possibilities(self):
        # Without Last-Modified the unpadded bytes split several ways. The ETag is still
        # identifiably IIS; the time is not, and saying so beats picking one.
        result = etag.analyze('"a6c8bf9fa5cdd1:0"', reference_time=FETCHED, timezone=IST)
        self.assertEqual('IIS', result.format)
        self.assertIsNone(result.modified)
        self.assertEqual(1, len(result.notes))
        self.assertIn('possible timestamps from 2026-07-05 23:12:18 IST', result.notes[0])
        self.assertIn('Last-Modified is needed to choose', result.notes[0])

    def test_iis_change_number(self):
        result = etag.analyze('"a6c8bf9fa5cdd1:3"', 'Thu, 15 Oct 2026 23:14:48 GMT')
        self.assertEqual('IIS', result.format)
        self.assertIn('configuration change number 3', result.notes)

    def test_apache_with_inode_and_a_compression_suffix(self):
        result = etag.analyze('"1a2b3c-3c2e-6470630308aec-gzip"', 'Sun, 28 Dec 2025 17:09:24 GMT')
        self.assertEqual('Apache httpd', result.format)
        self.assertEqual(15406, result.size)
        self.assertEqual(utc(2025, 12, 28, 17, 9, 24), result.modified.replace(microsecond=0))
        self.assertIn(f'inode {0x1a2b3c}', result.notes)
        self.assertIn('compressed variant (-gzip); size is of the uncompressed file', result.notes)

    def test_tomcat(self):
        modified = utc(2025, 12, 28, 17, 9, 24)
        value = f'W/"15406-{int(modified.timestamp()) * 1000}"'
        result = etag.analyze(value, 'Sun, 28 Dec 2025 17:09:24 GMT', 15406)
        self.assertEqual('Tomcat', result.format)
        self.assertEqual(modified, result.modified)
        self.assertEqual(15406, result.size)

    def test_express_body_hash_is_checked_against_a_cached_body(self):
        body = b'hello'
        digest = base64.b64encode(hashlib.sha1(body).digest()).decode()[:27]
        value = f'W/"{len(body):x}-{digest}"'
        matching = etag.analyze(value, size=len(body), body=body)
        self.assertEqual('Express (Node.js)', matching.format)
        self.assertEqual(5, matching.size)
        self.assertIn('matches the cached body', matching.notes)
        self.assertIn('does not match the cached body',
                      etag.analyze(value, body=b'jello').notes)

    def test_md5_is_checked_against_a_cached_body(self):
        value = hashlib.md5(b'hello').hexdigest()
        self.assertIn('matches the MD5 of the cached body',
                      etag.analyze(value, body=b'hello').notes)
        self.assertIn('does not match the MD5 of the cached body',
                      etag.analyze(value, body=b'jello').notes)

    def test_malformed_values_do_not_raise(self):
        for value in ('W/', '"', '""', 'W/""', '0x', '0xFFFFFFFFFFFFFFFF', 'f' * 16 + ':0',
                      'ffffffffffffffff-ffffffffffffffff', '-', ':', '9' * 13 + '-' + '9' * 13,
                      '\x00\xff', '"' * 50):
            with self.subTest(etag=value):
                etag.analyze(value, 'not a date', -1, reference_time=FETCHED, body=b'x')


def _download(**overrides):
    fields = dict(
        etag='"6ac46e19-13e7f8"', last_modified='Tue, 06 Oct 2026 03:42:17 GMT',
        total_bytes=1304568, start_time=utc(2026, 10, 7, 3, 42, 17))
    fields.update(overrides)
    item = WebBrowser.DownloadItem(
        'Default', 1, 'https://example.test/payload.exe', fields['total_bytes'],
        fields['total_bytes'], 1, start_time=fields['start_time'], etag=fields['etag'],
        last_modified=fields['last_modified'], opened=0)
    item.row_type = 'download'
    item.timestamp = item.start_time
    item.status_friendly = 'Complete'
    item.value = r'C:\Users\x\Downloads\payload.exe'
    item.interpretation = ''
    item.source_item = 'History'
    item.interrupt_reason_friendly = 'No Interrupt'
    item.danger_type_friendly = 'Not Dangerous'
    return item


def _session(items, timezone=UTC):
    session = AnalysisSession.__new__(AnalysisSession)
    session.parsed_artifacts = items
    session.parsed_storage = []
    session.parsed_extension_data = []
    session.parsed_sync_data = []
    session.preferences = []
    session.installed_extensions = None
    session.plugin_results = {}
    session.artifact_filter = None
    session.timezone = timezone
    return session


class TestSessionAnalysis(unittest.TestCase):

    def test_a_download_is_decoded_into_the_display_timezone(self):
        item = _download(start_time=utc(2026, 10, 7, 3, 42, 17).astimezone(IST))
        _session([item], IST).apply_etag_analysis()
        self.assertEqual('nginx', item.etag_format)
        self.assertEqual(1304568, item.etag_size)
        self.assertEqual(datetime.datetime(2026, 10, 6, 9, 12, 17, tzinfo=IST), item.etag_modified)
        self.assertEqual(datetime.timedelta(hours=5, minutes=30), item.etag_modified.utcoffset())
        self.assertEqual('time matches Last-Modified; size matches total bytes; '
                         'modified 1 day, 0:00:00 before the download', item.etag_notes)

    def test_a_cached_body_is_used_only_when_it_is_the_resource(self):
        body = b'hello'
        item = WebBrowser.CacheItem('Default', 'https://example.test/a', None,
                                    FETCHED, 'locations', 'key', None, body)
        item.row_type = 'cache'
        item.etag = hashlib.md5(body).hexdigest()

        _session([item]).apply_etag_analysis()
        # No body_sha256 means the bytes may still be compressed, so they are not
        # compared: a mismatch against a gzip stream would be a false finding.
        self.assertNotIn('MD5 of the cached body', item.etag_notes)

        item.body_sha256 = hashlib.sha256(body).hexdigest()
        _session([item]).apply_etag_analysis()
        self.assertIn('matches the MD5 of the cached body', item.etag_notes)

    def test_a_range_response_is_checked_against_the_full_size(self):
        # A 206 holds a slice of the file, so the slice's length and hash are not the
        # file's. Content-Range carries the full size after the slash.
        class Metadata:
            def __init__(self, headers):
                self.headers = headers

            def get_attribute(self, name):
                return [self.headers[name]] if name in self.headers else []

        part = b'x' * 100
        for content_range, size, note in (
                ('bytes 0-99/1304568', 1304568, 'size matches the Content-Range total'),
                ('bytes 0-99/*', None, 'not confirmed')):
            with self.subTest(content_range=content_range):
                item = WebBrowser.CacheItem(
                    'Default', 'https://example.test/a', None, FETCHED, 'locations', 'key',
                    Metadata({'content-range': content_range, 'content-length': '100'}), part)
                item.row_type = 'cache'
                item.etag = '"6ac46e19-13e7f8"'
                item.body_sha256 = hashlib.sha256(part).hexdigest()
                _session([item]).apply_etag_analysis()
                self.assertEqual('nginx', item.etag_format)
                self.assertEqual(1304568, item.etag_size)
                self.assertIn(note, item.etag_notes)
                self.assertNotIn('size differs', item.etag_notes)

    def test_items_without_an_etag_are_left_alone(self):
        item = _download(etag=None)
        _session([item]).apply_etag_analysis()
        self.assertIsNone(item.etag_format)

    def test_real_history_downloads(self):
        # upload.wikimedia.org serves from OpenStack Swift, whose ETag is the object's
        # MD5. Hard_disk.jpg was downloaded into the v30 profile in 2013 and the v60 one
        # in 2017: Last-Modified moved between the two, the ETag did not, and the file
        # it still serves hashes to that same value. That is the correlation this
        # decoding exists to support.
        decoded = {}
        for version in (30, 60):
            browser = Chrome(os.path.join('tests', 'fixtures', 'profiles', str(version)),
                             version=[version], no_copy=True, timezone=UTC)
            browser.get_downloads(browser.profile_path, 'History', browser.version, 'download')
            _session(browser.parsed_artifacts).apply_etag_analysis()
            hard_disk = next(item for item in browser.parsed_artifacts
                             if item.url.endswith('Hard_disk.jpg'))
            decoded[version] = hard_disk

        for item in decoded.values():
            self.assertEqual('ea6b7682ed897a3e9cf22274e431a455', item.etag)
            self.assertEqual('MD5 hash', item.etag_format)
        self.assertNotEqual(decoded[30].last_modified, decoded[60].last_modified)


class TestOutputs(unittest.TestCase):
    """The decoded fields reach all three output formats, under their own names."""

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.session = _session([_download()], IST)
        self.session.apply_etag_analysis()

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.remove(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def test_xlsx(self):
        buffer = io.BytesIO()
        self.session.generate_excel(buffer)
        buffer.seek(0)
        sheet = openpyxl.load_workbook(buffer)['Timeline']
        row = {header.value: value.value for header, value in zip(sheet[2], sheet[3])}

        self.assertEqual('"6ac46e19-13e7f8"', row['ETag'])
        # One readable cell; the parts are separate fields in SQLite and JSONL.
        self.assertEqual('nginx | modified 2026-10-06 09:12:17.000 | 1,304,568 bytes | '
                         'time matches Last-Modified; size matches total bytes; '
                         'modified 1 day, 0:00:00 before the download',
                         row['ETag Decoded (Asia/Kolkata)'])
        # The columns after the inserted one moved right and still hold their own data.
        self.assertIn('All HTTP Headers', row)
        self.assertIn('Body SHA256', row)
        self.assertEqual('AH', sheet.auto_filter.ref.split(':')[1].rstrip('0123456789'))

    def test_xlsx_leaves_the_cell_empty_without_an_etag(self):
        self.session.parsed_artifacts = [_download(etag=None)]
        self.session.apply_etag_analysis()
        buffer = io.BytesIO()
        self.session.generate_excel(buffer)
        buffer.seek(0)
        sheet = openpyxl.load_workbook(buffer)['Timeline']
        row = {header.value: value.value for header, value in zip(sheet[2], sheet[3])}
        self.assertIsNone(row['ETag Decoded (Asia/Kolkata)'])

    def test_xlsx_leaves_the_cell_empty_for_an_unrecognized_etag(self):
        # SQLite and JSONL still say 'Unrecognized'; the XLSX cell would only repeat
        # the ETag column beside it.
        self.session.parsed_artifacts = [_download(etag='"6e71e56-e4d464d1"')]
        self.session.apply_etag_analysis()
        self.assertEqual('Unrecognized', self.session.parsed_artifacts[0].etag_format)
        buffer = io.BytesIO()
        self.session.generate_excel(buffer)
        buffer.seek(0)
        sheet = openpyxl.load_workbook(buffer)['Timeline']
        row = {header.value: value.value for header, value in zip(sheet[2], sheet[3])}
        self.assertIsNone(row['ETag Decoded (Asia/Kolkata)'])

    def test_sqlite(self):
        path = os.path.join(self.directory, 'out.sqlite')
        self.session.generate_sqlite(path)
        con = sqlite3.connect(path)
        try:
            self.assertEqual(
                ('nginx', '2026-10-06 09:12:17.000', 1304568),
                con.execute('SELECT etag_format, etag_modified, etag_size FROM timeline').fetchone())
            # Appended after the existing columns, so their positions are unchanged.
            columns = [row[1] for row in con.execute('PRAGMA table_info(timeline)')]
            self.assertEqual(['body_sha256', 'etag_format', 'etag_modified', 'etag_size',
                              'etag_notes'], columns[-5:])
        finally:
            con.close()

    def test_jsonl(self):
        path = os.path.join(self.directory, 'out.jsonl')
        self.session.generate_jsonl(path)
        with open(path, encoding='utf-8') as f:
            record = json.loads(f.readline())
        self.assertEqual('nginx', record['etag_format'])
        self.assertEqual('2026-10-06T09:12:17+05:30', record['etag_modified'])
        self.assertEqual(1304568, record['etag_size'])
        self.assertIn('size matches total bytes', record['etag_notes'])


if __name__ == '__main__':
    unittest.main()
