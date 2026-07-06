import datetime
import os
import unittest
from pyhindsight.browsers.chrome import Chrome


class TestGetDownloads(unittest.TestCase):

    def test_get_downloads(self):

        test_config = [
            {'version':  [1], 'record_count': 2, 'wikipedia_record': 0, 'wikipedia_timestamp': datetime.datetime(2013, 6, 5, 4, 28, 30, tzinfo=datetime.timezone.utc)},
            {'version': [10], 'record_count': 2, 'wikipedia_record': 0, 'wikipedia_timestamp': datetime.datetime(2013, 6, 27, 4, 23, 25, tzinfo=datetime.timezone.utc)},
            {'version': [20], 'record_count': 2, 'wikipedia_record': 0, 'wikipedia_timestamp': datetime.datetime(2013, 6, 30, 21, 26, 5, tzinfo=datetime.timezone.utc)},
            {'version': [30], 'record_count': 2, 'wikipedia_record': 0, 'wikipedia_timestamp': datetime.datetime(2013, 10, 2, 23, 17, 29, 397160, tzinfo=datetime.timezone.utc)},
            {'version': [60], 'record_count': 2, 'wikipedia_record': 0, 'wikipedia_timestamp': datetime.datetime(2017, 8, 5, 22, 6, 52, 88356, tzinfo=datetime.timezone.utc)}
        ]

        for config in test_config:
            with self.subTest(config):
                test_instance = Chrome(os.path.join('tests', 'fixtures', 'profiles', '{:02d}'.format(config['version'][0])), version=config['version'], no_copy=True)

                test_instance.get_downloads(test_instance.profile_path, 'History', test_instance.version, 'download')

                # Total number of records parsed; make sure we aren't dropping/adding any
                self.assertEqual(len(test_instance.parsed_artifacts), config['record_count'])

                # Wikipedia Computer Forensics file download record; make sure it parses as expected
                self.assertIn(test_instance.parsed_artifacts[config['wikipedia_record']].url,
                              ['http://upload.wikimedia.org/wikipedia/commons/7/7a/Hard_disk.jpg',
                               'https://upload.wikimedia.org/wikipedia/commons/7/7a/Hard_disk.jpg'])

                self.assertEqual(test_instance.parsed_artifacts[config['wikipedia_record']].timestamp, config['wikipedia_timestamp'])

                self.assertEqual(test_instance.parsed_artifacts[config['wikipedia_record']].received_bytes, 1387537)

                self.assertIn(test_instance.parsed_artifacts[config['wikipedia_record']].value,
                              ['C:\\Users\\Ryan\\Downloads\\Hard_disk.jpg',
                               'C:\\Users\\Ryan\\Documents\\Downloads\\Hard_disk.jpg',
                               'C:\\Users\\IEUser\\Downloads\\Hard_disk.jpg'])


if __name__ == '__main__':
    unittest.main()
