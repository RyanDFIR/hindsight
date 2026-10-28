import os
import shutil
import sqlite3
import tempfile
import unittest

from pyhindsight.browsers.chrome import Chrome


class TestMediaHistoryDurations(unittest.TestCase):
    """Durations and positions are milliseconds and are written as H:MM:SS.mmm.

    They used to be str(timedelta)[:-3], which assumed str() always ends in a six-digit
    fraction. It leaves the fraction off a whole number of seconds, so cutting three
    characters took the seconds: 65 seconds came out as '0:01'.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        con = sqlite3.connect(os.path.join(self.tmp, 'Media History'))
        con.executescript('''
            CREATE TABLE playback (url TEXT, last_updated_time_s INTEGER, watch_time_s INTEGER,
                                   has_video INTEGER, has_audio INTEGER);
            CREATE TABLE playbackSession (last_updated_time_s INTEGER, title TEXT,
                                          source_title TEXT, duration_ms INTEGER, position_ms INTEGER);
        ''')
        for i, (duration_ms, position_ms) in enumerate(((65000, 30000), (65123, 1500), (3600007, 0))):
            updated = 13300000000 + i
            con.execute('INSERT INTO playback VALUES (?, ?, 10, 1, 1)', (f'https://v.example/{i}', updated))
            con.execute('INSERT INTO playbackSession VALUES (?, ?, ?, ?, ?)',
                        (updated, f'Video {i}', 'v.example', duration_ms, position_ms))
        con.commit()
        con.close()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_whole_seconds_keep_their_seconds(self):
        chrome = Chrome(self.tmp, version=[86], no_copy=True)
        chrome.get_media_history(self.tmp, 'Media History', [86], 'media')
        got = {item.url: (item.media_duration, item.position) for item in chrome.parsed_artifacts}
        self.assertEqual(got, {
            'https://v.example/0': ('0:01:05.000', '0:00:30.000'),
            'https://v.example/1': ('0:01:05.123', '0:00:01.500'),
            # Over the 2,600,000 ms sanity cap, so no duration; a 0 position is unset.
            'https://v.example/2': (None, None),
        })


if __name__ == '__main__':
    unittest.main()
