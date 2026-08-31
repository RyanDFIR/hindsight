import datetime
import os
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


class TestFirefoxDownloads(unittest.TestCase):

    def test_get_downloads_count(self):
        ff = _make_firefox()
        reported = ff.get_downloads(FIXTURE_DIR, 'places.sqlite')
        self.assertEqual(reported, 1)
        self.assertEqual(len(ff.parsed_artifacts), 1)

    def test_download_fields(self):
        ff = _make_firefox()
        reported = ff.get_downloads(FIXTURE_DIR, 'places.sqlite')

        dl = ff.parsed_artifacts[0]
        self.assertEqual(dl.row_type, 'download')
        self.assertEqual(dl.url, 'https://example.com/big_file.zip')
        self.assertEqual(dl.value, 'C:/Users/test/Downloads/big_file.zip')
        self.assertEqual(dl.target_path, 'C:/Users/test/Downloads/big_file.zip')


if __name__ == '__main__':
    unittest.main()
