import datetime
import unittest

from pyhindsight.browsers.chrome import Chrome

UTC = datetime.timezone.utc


class TestLastActiveTimeEncoding(unittest.TestCase):
    """SNSS LastActiveTime is written two different ways and only one is a date.

    Chrome originally stored base::TimeTicks -- microseconds from an arbitrary origin,
    in practice boot -- and later switched to base::Time (Webkit microseconds since
    1601). Reading the tick form as a date produced impossible tab-last-active
    timestamps: 1971, 1973, 2585, or a conversion failure. All the values below are real,
    taken from profiles on the test corpus.
    """

    def test_tick_values_do_not_become_dates(self):
        # ~2.4 hours of uptime, from a 2021 Brave profile.
        timestamp, note = Chrome.interpret_last_active_time(8655513809, UTC)
        self.assertIsNone(timestamp)
        self.assertIn('8655513809', note)
        self.assertIn('not a wall-clock time', note)

    def test_wall_clock_values_still_parse(self):
        # From a 2025 Chrome profile; must keep converting normally.
        timestamp, note = Chrome.interpret_last_active_time(13409864977276644, UTC)
        self.assertIsNone(note)
        self.assertEqual(timestamp.year, 2025)

    def test_negative_ticks_are_not_dates_either(self):
        timestamp, note = Chrome.interpret_last_active_time(-322589385038, UTC)
        self.assertIsNone(timestamp)
        self.assertIn('-322589385038', note)

    def test_the_two_encodings_are_far_apart(self):
        # The largest tick value seen was ~12 days of uptime; the smallest real
        # base::Time was 2024-01-03. The threshold sits in the empty space between.
        largest_tick = 1053034791380
        smallest_wall_clock = 13348718354172767
        self.assertLess(largest_tick, Chrome.SESSION_LAST_ACTIVE_WALL_CLOCK_MIN)
        self.assertGreater(smallest_wall_clock, Chrome.SESSION_LAST_ACTIVE_WALL_CLOCK_MIN)

        self.assertIsNone(Chrome.interpret_last_active_time(largest_tick, UTC)[0])
        self.assertIsNotNone(Chrome.interpret_last_active_time(smallest_wall_clock, UTC)[0])

    def test_tick_note_reports_the_elapsed_interval(self):
        # The ticks are still useful: they order tab activity within one boot.
        _, note = Chrome.interpret_last_active_time(8655513809, UTC)
        self.assertIn('2:24:15.513809', note)


if __name__ == '__main__':
    unittest.main()
