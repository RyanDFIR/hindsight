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


class TestFirefoxPermissions(unittest.TestCase):
    def test_count_and_friendly_labels(self):
        ff = _make_firefox()
        reported = ff.get_permissions(FIXTURE_DIR, 'permissions.sqlite')

        self.assertEqual(reported, 2)

        rows = {(a.url, a.key): a for a in ff.parsed_artifacts}
        wiki = rows[('https://en.wikipedia.org', 'desktop-notification')]
        self.assertEqual(wiki.value, 'Deny')
        self.assertIn('Never', wiki.interpretation)

        geo = rows[('https://example.com', 'geo')]
        self.assertEqual(geo.value, 'Allow')
        self.assertIn('At a specific time', geo.interpretation)


class TestFirefoxPrefs(unittest.TestCase):
    def test_prefs_count(self):
        ff = _make_firefox()
        reported = ff.get_preferences(FIXTURE_DIR, 'prefs.js')
        # Fixture has 10 user_pref lines; the parser also emits curated rows.
        self.assertGreaterEqual(reported, 10)

    def test_homepage_and_download_dir_surface(self):
        ff = _make_firefox()
        reported = ff.get_preferences(FIXTURE_DIR, 'prefs.js')

        pref_rows = ff.preferences[0]['data']
        by_name = {p['name']: p['value'] for p in pref_rows if p.get('name')}
        self.assertEqual(by_name.get('browser.startup.homepage'),
                         'https://en.wikipedia.org/')
        self.assertEqual(by_name.get('browser.download.lastDir'),
                         'C:\\Users\\test\\Downloads')
        self.assertFalse(by_name.get('toolkit.telemetry.enabled'))
        self.assertTrue(by_name.get('signon.rememberSignons'))


class TestFirefoxLogins(unittest.TestCase):
    def test_login_emits_three_timestamp_rows(self):
        ff = _make_firefox()
        reported = ff.get_logins(FIXTURE_DIR, 'logins.json')

        # One credential, three distinct timestamps -> three rows.
        self.assertEqual(reported, 3)

        row_types = sorted(a.row_type for a in ff.parsed_artifacts)
        self.assertEqual(row_types, [
            'login (created)',
            'login (last used)',
            'login (password changed)',
        ])
        for a in ff.parsed_artifacts:
            self.assertEqual(a.url, 'https://en.wikipedia.org')
            self.assertEqual(a.value, '<encrypted>')


class TestFirefoxExtensions(unittest.TestCase):
    def test_one_extension_with_signed_state_label(self):
        ff = _make_firefox()
        reported = ff.get_extensions(FIXTURE_DIR, 'extensions.json')

        self.assertEqual(reported, 1)
        ext = ff.installed_extensions['data'][0]
        self.assertEqual(ext.ext_id, 'uBlock0@raymondhill.net')
        self.assertEqual(ext.name, 'uBlock Origin')
        self.assertEqual(ext.version, '1.55.0')
        self.assertIn('"signedState": "Signed"', ext.manifest)


if __name__ == '__main__':
    unittest.main()
