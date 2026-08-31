import datetime
import os
import unittest

from pyhindsight.browsers.firefox import Firefox


FIXTURE_DIR = os.path.join('tests', 'fixtures', 'firefox')
REF_DT = datetime.datetime(2024, 1, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _make_firefox():
    ff = Firefox(FIXTURE_DIR, no_copy=True, temp_dir=None,
                 timezone=datetime.timezone.utc)
    ff.parsed_artifacts = []
    ff.parsed_storage = []
    ff.preferences = []
    return ff


class TestFirefoxHistory(unittest.TestCase):

    def test_get_history(self):
        ff = _make_firefox()
        reported = ff.get_history(FIXTURE_DIR, 'places.sqlite')

        self.assertEqual(len(ff.parsed_artifacts), 3)
        self.assertEqual(reported, 3)

        wiki = [a for a in ff.parsed_artifacts
                if a.url == 'https://en.wikipedia.org/wiki/Computer_forensics']
        self.assertEqual(len(wiki), 1)
        wiki = wiki[0]
        self.assertEqual(wiki.title, 'Computer forensics - Wikipedia')
        self.assertEqual(wiki.visit_count, 2)
        self.assertEqual(wiki.transition_friendly, 'Typed')
        self.assertEqual(wiki.timestamp, REF_DT)

    def test_get_bookmarks(self):
        ff = _make_firefox()
        reported = ff.get_bookmarks(FIXTURE_DIR, 'places.sqlite')

        self.assertEqual(reported, 2)
        bookmark_urls = [a for a in ff.parsed_artifacts if a.row_type == 'bookmark']
        folders = [a for a in ff.parsed_artifacts if a.row_type == 'bookmark folder']
        self.assertEqual(len(bookmark_urls), 1)
        self.assertEqual(len(folders), 1)

        bm = bookmark_urls[0]
        self.assertEqual(bm.url, 'https://en.wikipedia.org/wiki/Computer_forensics')
        self.assertEqual(bm.name, 'Computer forensics')
        self.assertEqual(bm.parent_folder, 'menu')

    def test_determine_version(self):
        ff = _make_firefox()
        reported = ff.get_history(FIXTURE_DIR, 'places.sqlite')
        ff.determine_version(FIXTURE_DIR, 'places.sqlite')

        self.assertIn(80, ff.version)
        self.assertEqual(ff.display_version, 'places schema v80')


if __name__ == '__main__':
    unittest.main()
