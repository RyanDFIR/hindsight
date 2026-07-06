import datetime
import os
import unittest
from pyhindsight.browsers.chrome import Chrome


class TestGetHistory(unittest.TestCase):

    def test_get_history(self):

        test_config = [
            {'version':  [1], 'record_count': 46, 'wikipedia_record': 7, 'wikipedia_timestamp': datetime.datetime(2013, 6, 5, 4, 28, 55, 498623, tzinfo=datetime.timezone.utc)},
            {'version': [10], 'record_count': 84, 'wikipedia_record': 7, 'wikipedia_timestamp': datetime.datetime(2013, 6, 27, 4, 23, 14, 176756, tzinfo=datetime.timezone.utc)},
            {'version': [20], 'record_count': 58, 'wikipedia_record': 7, 'wikipedia_timestamp': datetime.datetime(2013, 6, 30, 21, 26, 13, 162176, tzinfo=datetime.timezone.utc)},
            {'version': [30], 'record_count': 46, 'wikipedia_record': 4, 'wikipedia_timestamp': datetime.datetime(2013, 10, 2, 23, 15, 13, 326712, tzinfo=datetime.timezone.utc)},
            {'version': [60], 'record_count': 61, 'wikipedia_record': 5, 'wikipedia_timestamp': datetime.datetime(2017, 8, 5, 22, 6, 56, 507864, tzinfo=datetime.timezone.utc)}
        ]

        for config in test_config:
            with self.subTest(config):
                test_instance = Chrome(os.path.join('tests', 'fixtures', 'profiles', '{:02d}'.format(config['version'][0])), version=config['version'], no_copy=True)

                test_instance.get_history(test_instance.profile_path, 'History', test_instance.version, 'url')

                # Total number of records parsed; make sure we aren't dropping/adding any
                self.assertEqual(len(test_instance.parsed_artifacts), config['record_count'])

                # Wikipedia Computer Forensics page record; make sure it parses as expected
                self.assertIn(test_instance.parsed_artifacts[config['wikipedia_record']].url,
                              ['http://en.wikipedia.org/wiki/Computer_forensics', 'https://en.wikipedia.org/wiki/Computer_forensics'])

                self.assertEqual(test_instance.parsed_artifacts[config['wikipedia_record']].timestamp, config['wikipedia_timestamp'])


if __name__ == '__main__':
    unittest.main()
