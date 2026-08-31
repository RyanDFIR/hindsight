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


class TestFirefoxCookies(unittest.TestCase):
    def test_get_cookies_count(self):
        ff = _make_firefox()
        reported = ff.get_cookies(FIXTURE_DIR, 'cookies.sqlite')

        # 2 cookies, only the persistent one has a distinct lastAccessed,
        # so we expect 2 created + 1 accessed = 3 rows.
        self.assertEqual(reported, 3)

        created = [a for a in ff.parsed_artifacts
                   if a.row_type == 'cookie (created)']
        accessed = [a for a in ff.parsed_artifacts
                    if a.row_type == 'cookie (accessed)']
        self.assertEqual(len(created), 2)
        self.assertEqual(len(accessed), 1)

    def test_persistent_cookie_attributes(self):
        ff = _make_firefox()
        reported = ff.get_cookies(FIXTURE_DIR, 'cookies.sqlite')

        wiki = [a for a in ff.parsed_artifacts
                if a.name == 'WMF-Last-Access' and a.row_type == 'cookie (created)']
        self.assertEqual(len(wiki), 1)
        wiki = wiki[0]
        self.assertEqual(wiki.value, '15-Jan-2024')
        self.assertEqual(wiki.host_key, '.wikipedia.org')
        self.assertTrue(wiki.secure)
        self.assertTrue(wiki.httponly)
        self.assertTrue(wiki.persistent)
        self.assertEqual(wiki.url, 'wikipedia.org')
        self.assertEqual(wiki.timestamp, REF_DT)

    def test_session_cookie_no_expiry(self):
        ff = _make_firefox()
        reported = ff.get_cookies(FIXTURE_DIR, 'cookies.sqlite')

        session = [a for a in ff.parsed_artifacts
                   if a.name == 'session' and a.row_type == 'cookie (created)']
        self.assertEqual(len(session), 1)
        session = session[0]
        self.assertFalse(session.persistent)
        self.assertIsNone(session.expires_utc)


if __name__ == '__main__':
    unittest.main()
