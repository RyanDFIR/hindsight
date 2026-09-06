"""SHA-256 over File System backing files and cached response bodies.

Both are content Hindsight already reads and then describes only in ways that cannot be
compared to anything: a size and a guessed type for a stored file, a size and a
content-type for a cached body. A digest is what makes either of them matchable against
a known-file set, a copy recovered elsewhere in the evidence, or the same resource in
another profile.

The cache half has a trap worth pinning. Chrome's HTTP cache stores a response body as it
arrived on the wire, so ccl decompresses it per content-encoding, and when that fails it
silently returns the compressed bytes instead. Hashing those would give the digest of a
gzip stream, which in the output is indistinguishable from a digest of the resource and
matches nothing, so the hash is withheld rather than qualified. An absent digest is a
question; a wrong one that looks right is a wrong answer.

CacheStorage is the opposite and is not covered here: it stores the already-decoded body
while keeping the original response headers, so content-encoding and content-length there
describe the wire form rather than the bytes on disk and cannot be used to answer this.
Its rows are built in `Chrome.get_service_workers`, which these tests do not reach; that
gap is what issue #313 (row-level output inspection) is for.
"""

import datetime
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest

import openpyxl

from pyhindsight import utils
from pyhindsight.analysis import AnalysisSession, HindsightEncoder
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.webbrowser import WebBrowser

UTC = datetime.timezone.utc

# A PNG signature followed by filler. Real magic bytes so puremagic identifies the file
# the way it would in a profile, rather than the hash path being exercised on content
# the type detection never sees.
PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'hindsight test file' * 8
PNG_SHA256 = hashlib.sha256(PNG_BYTES).hexdigest()


class FakeMetadata:
    """The two CachedMetadata members the cache parser touches."""

    def __init__(self, **attributes):
        self.attributes = attributes
        self.http_header_attributes = list(attributes.items())

    def get_attribute(self, name):
        value = self.attributes.get(name)
        return [value] if value is not None else []


def cache_item(data, was_decompressed=False, **attributes):
    item = WebBrowser.CacheItem(
        profile='p', url='https://example.test/logo.png', title=None,
        request_time=datetime.datetime(2024, 6, 1, tzinfo=UTC),
        locations='{}', key='https://example.test/logo.png',
        metadata=FakeMetadata(**attributes), data=data)
    item.hash_body(was_decompressed)
    return item


class TestSha256File(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.path = os.path.join(self.directory, 'backing_file')
        with open(self.path, 'wb') as f:
            f.write(PNG_BYTES)

    def tearDown(self):
        if os.path.isfile(self.path):
            os.remove(self.path)
        os.rmdir(self.directory)

    def test_it_matches_the_digest_of_the_whole_file(self):
        self.assertEqual(PNG_SHA256, utils.sha256_file(self.path))

    def test_a_file_spanning_many_chunks_hashes_the_same(self):
        # The chunked read must reassemble to one digest; a per-chunk or truncated
        # digest would still look like a plausible hash in the output.
        self.assertEqual(PNG_SHA256, utils.sha256_file(self.path, chunk_size=7))

    def test_a_missing_file_returns_none(self):
        self.assertIsNone(utils.sha256_file(os.path.join(self.directory, 'absent')))

    def test_an_unreadable_path_returns_none_rather_than_raising(self):
        # A hash annotates a record; failing to take one must not cost the caller the
        # artifact those records belong to.
        self.assertIsNone(utils.sha256_file(self.directory))


class TestGetLocalFileInfo(unittest.TestCase):
    """File System API backing files: the hash rides alongside size and type."""

    def setUp(self):
        self.directory = tempfile.mkdtemp()

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.remove(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def _write(self, name, content):
        path = os.path.join(self.directory, name)
        with open(path, 'wb') as f:
            f.write(content)
        return path

    def test_a_stored_file_is_hashed(self):
        exists, size, magic_results, sha256 = Chrome.get_local_file_info(
            self._write('stored', PNG_BYTES))
        self.assertTrue(exists)
        self.assertEqual(len(PNG_BYTES), size)
        self.assertEqual(PNG_SHA256, sha256)
        self.assertIsNotNone(magic_results)

    def test_an_empty_file_is_not_given_the_digest_of_no_bytes(self):
        # e3b0c442... would otherwise appear against every empty file and read as a
        # group of identical files rather than as an absence of content.
        exists, size, _, sha256 = Chrome.get_local_file_info(self._write('empty', b''))
        self.assertTrue(exists)
        self.assertEqual(0, size)
        self.assertIsNone(sha256)

    def test_a_missing_file_reports_no_hash(self):
        exists, size, magic_results, sha256 = Chrome.get_local_file_info(
            os.path.join(self.directory, 'absent'))
        self.assertFalse(exists)
        self.assertIsNone(size)
        self.assertIsNone(magic_results)
        self.assertIsNone(sha256)


class TestCacheBodyHash(unittest.TestCase):

    def test_a_cached_body_is_hashed(self):
        self.assertEqual(PNG_SHA256, cache_item(PNG_BYTES).body_sha256)

    def test_an_evicted_entry_has_no_hash(self):
        # Its metadata survives without its body; a digest here would describe nothing.
        self.assertIsNone(cache_item(None).body_sha256)

    def test_a_decompressed_body_is_hashed(self):
        # ccl decoded it, so the bytes in hand are the resource.
        item = cache_item(PNG_BYTES, was_decompressed=True, **{'content-encoding': 'gzip'})
        self.assertEqual(PNG_SHA256, item.body_sha256)

    def test_a_body_that_failed_to_decompress_is_not_hashed(self):
        # ccl returns the compressed bytes on a decompression failure. Their digest would
        # sit in the same column as every other one, look equally authoritative, and match
        # nothing, so no digest is recorded at all.
        item = cache_item(PNG_BYTES, was_decompressed=False,
                          **{'content-encoding': 'gzip'})
        self.assertIsNone(item.body_sha256)

    def test_the_withheld_hash_is_the_only_thing_withheld(self):
        # The row itself still carries the entry: the URL, the timestamp and the size are
        # unaffected by whether the body could be decoded.
        item = cache_item(PNG_BYTES, was_decompressed=False,
                          **{'content-encoding': 'gzip', 'content-type': 'image/png'})
        self.assertEqual('https://example.test/logo.png', item.url)
        self.assertEqual(f'image/png ({len(PNG_BYTES)} bytes)', item.create_data_summary())

    def test_an_entry_without_metadata_is_not_hashed(self):
        # Headers are what establish whether the bytes on disk are the resource. Without
        # them the question is unanswerable, so no digest is recorded, for the same
        # reason a body that failed to decompress gets none.
        item = self._no_metadata_item()
        item.hash_body()
        self.assertIsNone(item.body_sha256)

    def test_the_rest_of_an_entry_without_metadata_survives(self):
        # Withholding the digest must not cost the entry. Its URL is on the key, not in
        # the metadata, so the row still reports what was cached and how large it was.
        item = self._no_metadata_item()
        self.assertEqual('https://example.test/', item.url)
        self.assertEqual(f'{len(PNG_BYTES)} bytes', item.create_data_summary())

    def test_an_entry_without_metadata_reports_no_headers_rather_than_none(self):
        # '{}' would assert a response that carried no headers, which is a different
        # finding from headers that were never recovered.
        item = self._no_metadata_item()
        item.stringify_http_headers()
        self.assertEqual('', item.http_headers_str)

    @staticmethod
    def _no_metadata_item():
        return WebBrowser.CacheItem(
            profile='p', url='https://example.test/', title=None,
            request_time=None, locations='{}', key='k', metadata=None, data=PNG_BYTES)


def _file_system_item(sha256):
    return WebBrowser.FileSystemItem(
        profile='p', origin='https://example.test', key='docs/report.pdf',
        value='File System/000/p/00/00000000', seq=1, state='Live',
        source_path='File System/Origins', last_modified=None,
        file_exists=True, file_size=len(PNG_BYTES), magic_results='image/png (100%)',
        file_sha256=sha256)


def _cache_row(row_type='cache', was_decompressed=True, **attributes):
    item = cache_item(PNG_BYTES, was_decompressed=was_decompressed,
                      **(attributes or {'content-encoding': 'gzip'}))
    item.row_type = row_type
    item.data_summary = item.create_data_summary()
    item.interpretation = None
    item.source_item = 'Cache'
    item.etag = ''
    item.last_modified = ''
    item.http_headers_str = '{}'
    return item


class TestHashesReachTheOutput(unittest.TestCase):
    """A hash computed and then dropped before the report is worse than none at all."""

    def setUp(self):
        self.session = AnalysisSession.__new__(AnalysisSession)
        self.session.parsed_artifacts = [_cache_row()]
        self.session.parsed_storage = [_file_system_item(PNG_SHA256)]
        self.session.parsed_extension_data = []
        self.session.parsed_sync_data = []
        self.session.preferences = []
        self.session.installed_extensions = None
        self.session.timezone = UTC
        self.directory = tempfile.mkdtemp()

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.remove(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def test_sqlite_carries_both_hashes(self):
        path = os.path.join(self.directory, 'report.sqlite')
        self.session.generate_sqlite(path)
        con = sqlite3.connect(path)
        try:
            self.assertEqual(
                (PNG_SHA256,),
                con.execute('SELECT body_sha256 FROM timeline').fetchone())
            self.assertEqual(
                (PNG_SHA256,),
                con.execute('SELECT file_sha256 FROM storage').fetchone())
        finally:
            con.close()

    def test_jsonl_carries_both_hashes(self):
        path = os.path.join(self.directory, 'report.jsonl')
        self.session.generate_jsonl(path)
        with open(path, encoding='utf-8') as f:
            records = [json.loads(line) for line in f if line.strip()]

        by_type = {record['data_type']: record for record in records}
        self.assertEqual(PNG_SHA256, by_type['chrome:cache:entry']['body_sha256'])
        self.assertEqual(PNG_SHA256, by_type['chrome:file_system:entry']['file_sha256'])

    def test_an_undecodable_body_reaches_the_output_without_a_hash(self):
        # The field is simply absent rather than present and wrong.
        self.session.parsed_artifacts = [
            _cache_row(was_decompressed=False, **{'content-encoding': 'gzip'})]
        path = os.path.join(self.directory, 'encoded.jsonl')
        self.session.generate_jsonl(path)
        with open(path, encoding='utf-8') as f:
            records = [json.loads(line) for line in f if line.strip()]

        cache_records = [r for r in records if r['data_type'] == 'chrome:cache:entry']
        self.assertEqual(1, len(cache_records))
        self.assertNotIn('body_sha256', cache_records[0])

    def test_the_encoder_keeps_the_hash_when_it_drops_the_body(self):
        # The encoder pops `data` so the report does not carry the bytes; the digest is
        # what survives to identify them, so it must not be dropped with them.
        encoded = json.loads(json.dumps(_cache_row(), cls=HindsightEncoder))
        self.assertNotIn('data', encoded)
        self.assertEqual(PNG_SHA256, encoded['body_sha256'])

    def test_service_worker_cache_rows_are_carried_too(self):
        # CacheStorage entries reach the Timeline as their own row_type from a second
        # producer, and were 89% of the cache rows in the corpus root this was checked
        # against. A hash on only the HTTP cache ones would have looked like a working
        # feature while missing most of the output.
        self.session.parsed_artifacts = [_cache_row('cache (service worker)')]
        path = os.path.join(self.directory, 'sw.sqlite')
        self.session.generate_sqlite(path)
        con = sqlite3.connect(path)
        try:
            self.assertEqual(
                (PNG_SHA256,),
                con.execute('SELECT body_sha256 FROM timeline').fetchone())
        finally:
            con.close()


class TestXlsxColumns(unittest.TestCase):
    """The hashes must land under their own headers.

    Both sheets grew a column, which moved merge ranges and the autofilter. An
    off-by-one here writes a digest under a neighbouring header, which is worse than
    omitting it: the value looks authoritative and describes the wrong thing.
    """

    @classmethod
    def setUpClass(cls):
        session = AnalysisSession.__new__(AnalysisSession)
        session.parsed_artifacts = [_cache_row()]
        session.parsed_storage = [_file_system_item(PNG_SHA256)]
        session.parsed_extension_data = []
        session.parsed_sync_data = []
        session.preferences = []
        session.installed_extensions = None
        session.plugin_results = {}
        session.timezone = UTC
        session.artifact_filter = None

        buffer = io.BytesIO()
        session.generate_excel(buffer)
        buffer.seek(0)
        cls.workbook = openpyxl.load_workbook(buffer)

    def _column_under(self, sheet_name, header):
        sheet = self.workbook[sheet_name]
        for cell in sheet[2]:  # headers are on row 2; row 1 is the title bar
            if cell.value == header:
                return cell.column
        self.fail(f'no {header!r} header on the {sheet_name} sheet')

    def _value_under(self, sheet_name, header):
        sheet = self.workbook[sheet_name]
        return sheet.cell(row=3, column=self._column_under(sheet_name, header)).value

    def test_the_cache_body_hash_is_under_its_header(self):
        self.assertEqual(PNG_SHA256, self._value_under('Timeline', 'Body SHA256'))

    def test_the_file_hash_is_under_its_header(self):
        self.assertEqual(PNG_SHA256, self._value_under('Storage', 'File SHA256'))

    def test_the_neighbouring_columns_did_not_shift(self):
        # The columns the new ones were appended after must still hold their own values.
        self.assertEqual('{}', self._value_under('Timeline', 'All HTTP Headers'))
        self.assertEqual('image/png (100%)',
                         self._value_under('Storage', 'File Type (Confidence %)'))

    def test_every_column_is_inside_the_autofilter(self):
        # The Storage filter stopped a column short before this change, so the last
        # column could not be filtered on at all.
        for sheet_name, header in (('Timeline', 'Body SHA256'),
                                   ('Storage', 'File SHA256')):
            with self.subTest(sheet=sheet_name):
                sheet = self.workbook[sheet_name]
                last_filtered = openpyxl.utils.range_boundaries(
                    sheet.auto_filter.ref)[2]
                self.assertGreaterEqual(last_filtered,
                                        self._column_under(sheet_name, header))


if __name__ == '__main__':
    unittest.main()
