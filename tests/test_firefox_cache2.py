import datetime
import os
import unittest

from pyhindsight.browsers.firefox import Firefox


FIXTURE_DIR = os.path.join('tests', 'fixtures', 'firefox')
CACHE_DIR = os.path.join(FIXTURE_DIR, 'cache2', 'entries')


def _make_firefox():
    ff = Firefox(FIXTURE_DIR, no_copy=True, temp_dir=None,
                 timezone=datetime.timezone.utc)
    ff.parsed_artifacts = []
    ff.parsed_storage = []
    ff.preferences = []
    return ff


class TestFirefoxCache2(unittest.TestCase):
    def test_parse_entry_unpacks_header(self):
        entry_path = os.path.join(
            CACHE_DIR, 'FIXTUREENTRY00000000000000000000FIXTURE0')
        parsed = Firefox._parse_cache2_entry(entry_path)
        self.assertIsNotNone(parsed)

        self.assertEqual(parsed['version'], 3)
        self.assertEqual(parsed['fetch_count'], 7)
        self.assertEqual(parsed['frecency'], 100)
        self.assertEqual(parsed['last_fetched'], int(
            datetime.datetime(2024, 1, 15, 12, 0, 0,
                              tzinfo=datetime.timezone.utc).timestamp()))
        self.assertEqual(parsed['last_modified'], parsed['last_fetched'] - 60)
        self.assertEqual(parsed['expiration'],
                         parsed['last_fetched'] + 86400)

    def test_parse_entry_extracts_url_from_key(self):
        entry_path = os.path.join(
            CACHE_DIR, 'FIXTUREENTRY00000000000000000000FIXTURE0')
        parsed = Firefox._parse_cache2_entry(entry_path)
        self.assertEqual(
            parsed['url'],
            'https://en.wikipedia.org/wiki/Computer_forensics')

    def test_parse_entry_decodes_response_head(self):
        entry_path = os.path.join(
            CACHE_DIR, 'FIXTUREENTRY00000000000000000000FIXTURE0')
        parsed = Firefox._parse_cache2_entry(entry_path)

        self.assertEqual(parsed['status_line'], 'HTTP/2 200 OK')
        self.assertEqual(parsed['headers']['content-type'],
                         'text/html; charset=UTF-8')
        self.assertEqual(parsed['headers']['etag'], '"fixture-etag"')
        self.assertEqual(parsed['elements']['request-method'], 'GET')

    def test_parse_entry_rejects_tiny_files(self):
        tiny = os.path.join(CACHE_DIR, 'tiny.bin')
        with open(tiny, 'wb') as f:
            f.write(b'\x00' * 20)
        try:
            self.assertIsNone(Firefox._parse_cache2_entry(tiny))
        finally:
            os.remove(tiny)

    def test_get_cache_emits_cacheitem(self):
        ff = _make_firefox()
        reported = ff.get_cache(CACHE_DIR)

        self.assertEqual(reported, 1)
        item = ff.parsed_artifacts[0]
        self.assertEqual(item.row_type, 'cache')
        self.assertEqual(item.url,
                         'https://en.wikipedia.org/wiki/Computer_forensics')
        self.assertIn('text/html', item.data_summary)
        self.assertEqual(item.etag, '"fixture-etag"')
        self.assertEqual(item.last_modified, 'Mon, 15 Jan 2024 11:00:00 GMT')


if __name__ == '__main__':
    unittest.main()
