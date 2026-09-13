import os
import tempfile
import types
import unittest
from unittest import mock

from pyhindsight.browsers import chrome
from pyhindsight.browsers.chrome import Chrome, iterate_cache_entries


def _key(url):
    return types.SimpleNamespace(url=url)


def _entry(url, metadata=None):
    return types.SimpleNamespace(
        key=_key(url), metadata=metadata, data=b'body', was_decompressed=False,
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

    def __init__(self, urls, unreadable=(), fail_after=None, metadata=None):
        self.urls = urls
        self.unreadable = dict(unreadable)
        self.metadata = metadata or {}
        self._cache = None
        self._fail_after = fail_after

    def _lazy_load_cache(self):
        self._cache = FakeCache([_key(url) for url in self.urls], self._fail_after)

    def _yield_cache_record(self, key, decompress, omit_data):
        if key.url in self.unreadable:
            raise self.unreadable[key.url]
        yield _entry(key.url, self.metadata.get(key.url))

    def iterate_cache(self, url=None, omit_cached_data=False):
        # The public generator: one unreadable entry ends it, as ccl's does.
        self._lazy_load_cache()
        for key in self._cache.cache_keys():
            yield from self._yield_cache_record(key, True, omit_cached_data)


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

    def test_falls_back_to_the_public_generator_without_the_per_key_helper(self):
        class PublicOnly:
            def iterate_cache(self, url=None, omit_cached_data=False):
                yield _entry('https://a/')

        [(key, entry, error)] = list(iterate_cache_entries(PublicOnly()))
        self.assertEqual('https://a/', key.url)
        self.assertIsNone(error)


class TestGetCacheIsolatesEntries(unittest.TestCase):
    """One bad cache entry no longer decides how much of the directory is parsed (#326)."""

    def get_cache(self, profile):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = os.path.join(tmp, 'Cache_Data')
            os.makedirs(cache_dir)
            open(os.path.join(cache_dir, 'index'), 'wb').close()
            browser = Chrome(tmp)
            with mock.patch.object(chrome.ccl_chromium_reader, 'ChromiumProfileFolder', return_value=profile):
                result = browser.get_cache(tmp, 'Cache_Data')
            return result, [item.url for item in browser.parsed_artifacts]

    def test_an_entry_ccl_cannot_read_is_counted_and_the_others_are_kept(self):
        profile = FakeProfile(
            ['https://a/', 'https://bad/', 'https://c/'],
            unreadable={'https://bad/': ValueError('Could not get all of the data for stream 1')})

        result, urls = self.get_cache(profile)

        self.assertEqual(['https://a/', 'https://c/'], urls)
        self.assertEqual(2, result.count)
        self.assertEqual(1, result.unparsed_records)

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


if __name__ == '__main__':
    unittest.main()
