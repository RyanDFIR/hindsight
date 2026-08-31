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


class TestFirefoxFormHistory(unittest.TestCase):
    def test_form_history_count(self):
        ff = _make_firefox()
        reported = ff.get_form_history(FIXTURE_DIR, 'formhistory.sqlite')
        # Two saved form fields in the fixture.
        self.assertEqual(reported, 2)
        self.assertEqual(len(ff.parsed_artifacts), 2)

    def test_email_field(self):
        ff = _make_firefox()
        reported = ff.get_form_history(FIXTURE_DIR, 'formhistory.sqlite')

        email = [a for a in ff.parsed_artifacts if a.name == 'email']
        self.assertEqual(len(email), 1)
        email = email[0]
        self.assertEqual(email.value, 'forensic@example.com')
        self.assertEqual(email.count, 3)
        self.assertEqual(email.row_type, 'autofill')
        self.assertEqual(email.timestamp, REF_DT)

    def test_searchbar_field(self):
        ff = _make_firefox()
        reported = ff.get_form_history(FIXTURE_DIR, 'formhistory.sqlite')

        sb = [a for a in ff.parsed_artifacts if a.name == 'searchbar-history']
        self.assertEqual(len(sb), 1)
        self.assertEqual(sb[0].value, 'computer forensics')


if __name__ == '__main__':
    unittest.main()
