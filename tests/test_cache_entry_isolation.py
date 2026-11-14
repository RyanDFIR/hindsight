import datetime
import gzip
import hashlib
import inspect
import os
import tempfile
import types
import unittest
from unittest import mock

from pyhindsight import content_encoding
from pyhindsight.browsers import chrome
from pyhindsight.browsers.chrome import Chrome, iterate_cache_entries


def _key(url):
    return types.SimpleNamespace(url=url)


def _entry(url, metadata=None, data=b'body'):
    return types.SimpleNamespace(
        key=_key(url), metadata=metadata, data=data, was_decompressed=False,
        metadata_location=None, data_location=None)


class FakeCache:
    def __init__(self, keys, fail_after=None):
        self.keys = keys
        self.fail_after = fail_after

    def cache_keys(self):
        for index, key in enumerate(self.keys):
            if self.fail_after is not None and index == self.fail_after:
                raise ValueError('index is truncated')
            yield key


class FakeProfile:
    """Stands in for ccl's ChromiumProfileFolder: per-key reads, some of which fail."""

    def __init__(self, urls, unreadable=(), fail_after=None, metadata=None, bodies=None):
        self.urls = urls
        self.unreadable = dict(unreadable)
        self.metadata = metadata or {}
        self.bodies = bodies or {}
        self._cache = None
        self._fail_after = fail_after

    def _lazy_load_cache(self):
        self._cache = FakeCache([_key(url) for url in self.urls], self._fail_after)

    def _yield_cache_record(self, key, decompress, omit_data):
        if key.url in self.unreadable:
            raise self.unreadable[key.url]
        yield _entry(key.url, self.metadata.get(key.url), self.bodies.get(key.url, b'body'))


class _OutOfRangeMetadata:
    """Metadata whose request time cannot be converted, like a far-future timestamp."""

    @property
    def request_time(self):
        raise OverflowError('date value out of range')


class TestIterateCacheEntries(unittest.TestCase):
    def test_an_unreadable_entry_is_yielded_with_its_error_and_the_rest_continue(self):
        profile = FakeProfile(
            ['https://a/', 'https://bad/', 'https://c/'],
            unreadable={'https://bad/': ValueError('Metadata buffer is not the declared size')})

        seen = [(key.url, entry is not None, error) for key, entry, error in iterate_cache_entries(profile)]

        self.assertEqual(['https://a/', 'https://bad/', 'https://c/'], [url for url, _, _ in seen])
        self.assertEqual([True, False, True], [has_entry for _, has_entry, _ in seen])
        self.assertIsInstance(seen[1][2], ValueError)

    def test_the_bundled_ccl_still_has_the_private_helpers_it_relies_on(self):
        # iterate_cache_entries calls ChromiumProfileFolder internals. They only change
        # when ccl is re-bundled, and this is what notices if they did.
        folder = chrome.ccl_chromium_reader.ChromiumProfileFolder
        self.assertEqual(['self'], list(inspect.signature(folder._lazy_load_cache).parameters))
        self.assertEqual(['self', 'key', 'decompress', 'omit_data'],
                         list(inspect.signature(folder._yield_cache_record).parameters))


class TestGetCacheIsolatesEntries(unittest.TestCase):
    """One bad cache entry no longer decides how much of the directory is parsed (#326)."""

    def get_cache(self, profile):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = os.path.join(tmp, 'Cache_Data')
            os.makedirs(cache_dir)
            open(os.path.join(cache_dir, 'index'), 'wb').close()
            browser = Chrome(tmp)
            with mock.patch.object(chrome.ccl_chromium_reader, 'ChromiumProfileFolder', return_value=profile), \
                    mock.patch('pyhindsight.browsers.webbrowser.log') as log:
                result = browser.get_cache(tmp, 'Cache_Data')
            self.logged = [call.args[0] for call in log.debug.call_args_list + log.warning.call_args_list]
            return result, [item.url for item in browser.parsed_artifacts]

    def test_an_entry_ccl_cannot_read_is_counted_and_the_others_are_kept(self):
        profile = FakeProfile(
            ['https://a/', 'https://bad/', 'https://c/'],
            unreadable={'https://bad/': ValueError('Could not get all of the data for stream 1')})

        result, urls = self.get_cache(profile)

        self.assertEqual(['https://a/', 'https://c/'], urls)
        self.assertEqual(2, result.count)
        self.assertEqual(1, result.unparsed_records)
        self.assertTrue(any('cache entry could not be read (ValueError: Could not get all of the data '
                            'for stream 1)' in line for line in self.logged), self.logged)

    def test_an_exception_with_no_message_is_named_in_the_reason(self):
        profile = FakeProfile(['https://a/', 'https://bad/'], unreadable={'https://bad/': ValueError()})

        result, _ = self.get_cache(profile)

        self.assertEqual(1, result.unparsed_records)
        self.assertTrue(any('cache entry could not be read (ValueError)' in line for line in self.logged),
                        self.logged)

    def test_an_entry_whose_time_cannot_be_converted_is_counted_and_the_others_are_kept(self):
        profile = FakeProfile(
            ['https://a/', 'https://far-future/', 'https://c/'],
            metadata={'https://far-future/': _OutOfRangeMetadata()})

        result, urls = self.get_cache(profile)

        self.assertEqual(['https://a/', 'https://c/'], urls)
        self.assertEqual(1, result.unparsed_records)

    def test_a_cache_that_stops_being_readable_keeps_what_was_read(self):
        profile = FakeProfile(['https://a/', 'https://b/', 'https://c/'], fail_after=2)

        result, urls = self.get_cache(profile)

        self.assertEqual(['https://a/', 'https://b/'], urls)
        self.assertEqual(1, result.unparsed_sources)


class _GzipMetadata:
    """Metadata for a response that was sent gzip-encoded."""
    request_time = datetime.datetime(2024, 5, 1, 12, 0, 0)
    http_header_attributes = [('content-encoding', 'gzip'), ('content-type', 'text/html')]

    def get_attribute(self, name):
        return [value for attribute, value in self.http_header_attributes if attribute == name]


class TestGetCacheLimitsDecodedSize(unittest.TestCase):
    """A body that expands past the limit is kept as stored, not decoded into memory."""

    LIMIT = 64 * 1024

    def get_cache(self, bodies, cache_expansion=content_encoding.MAX_CACHE_EXPANSION):
        profile = FakeProfile(list(bodies), metadata={url: _GzipMetadata() for url in bodies}, bodies=bodies)
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = os.path.join(tmp, 'Cache_Data')
            os.makedirs(cache_dir)
            open(os.path.join(cache_dir, 'index'), 'wb').close()
            browser = Chrome(tmp)
            with mock.patch.object(chrome.ccl_chromium_reader, 'ChromiumProfileFolder', return_value=profile), \
                    mock.patch.object(content_encoding, 'MAX_DECODED_SIZE', self.LIMIT), \
                    mock.patch.object(content_encoding, 'MAX_CACHE_EXPANSION', cache_expansion), \
                    mock.patch('pyhindsight.browsers.chrome.log') as log:
                browser.get_cache(tmp, 'Cache_Data')
            self.warnings = [call.args[0] for call in log.warning.call_args_list]
            return {item.url: item for item in browser.parsed_artifacts}

    def test_a_body_past_the_limit_is_reported_and_left_as_stored(self):
        page = b'<html>ordinary page</html>'
        bomb = gzip.compress(b'\0' * (self.LIMIT * 16))
        self.assertLess(len(bomb), self.LIMIT // 8)

        items = self.get_cache({'https://ok/': gzip.compress(page), 'https://bomb/': bomb})

        ok = items['https://ok/']
        self.assertEqual(page, ok.data)
        self.assertEqual(hashlib.sha256(page).hexdigest(), ok.body_sha256)
        self.assertIsNotNone(ok.encoded_md5)

        # Still a row, with the bytes that are on disk and no hash claiming to be the
        # resource's.
        left = items['https://bomb/']
        self.assertEqual(bomb, left.data)
        self.assertIsNone(left.body_sha256)
        self.assertIsNone(left.encoded_md5)
        self.assertTrue(any('https://bomb/ was not decoded' in line for line in self.warnings), self.warnings)
        self.assertTrue(any('1 of those were left encoded' in line for line in self.warnings), self.warnings)

    def test_bodies_under_the_limit_stop_being_decoded_once_they_add_up(self):
        # Each is under the limit for one body. Together they are allowed to grow by
        # 100 KiB, which the first two use most of.
        plain = b'\0' * (40 * 1024)
        body = gzip.compress(plain)
        urls = ['https://one/', 'https://two/', 'https://three/', 'https://four/']

        items = self.get_cache({url: body for url in urls}, cache_expansion=100 * 1024)

        self.assertEqual([plain, plain, body, body], [items[url].data for url in urls])
        self.assertEqual([True, True, False, False], [items[url].body_sha256 is not None for url in urls])
        # Counted, and not named one by one.
        self.assertFalse(any('was not decoded' in line for line in self.warnings), self.warnings)
        self.assertTrue(any('2 of those were left encoded because the bodies decoded before them' in line
                            for line in self.warnings), self.warnings)

    def test_a_body_that_does_not_grow_is_decoded_after_the_allowance_is_spent(self):
        grows = gzip.compress(b'\0' * (40 * 1024))
        small = gzip.compress(b'x')  # longer encoded than decoded
        self.assertGreater(len(small), 1)

        items = self.get_cache({'https://grows/': grows, 'https://again/': grows, 'https://small/': small},
                               cache_expansion=40 * 1024)

        self.assertEqual(grows, items['https://again/'].data)
        self.assertEqual(b'x', items['https://small/'].data)


if __name__ == '__main__':
    unittest.main()
