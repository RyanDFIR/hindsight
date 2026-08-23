import datetime
import unittest

from pyhindsight.browsers.webbrowser import WebBrowser, timeline_sort_key
from pyhindsight.utils import to_datetime

UTC = datetime.timezone.utc


def _item(timestamp):
    return WebBrowser.HistoryItem('url', timestamp=timestamp, profile='p', url='u')


class TestUntimestampedSorting(unittest.TestCase):
    """An artifact with no usable time is evidence, not junk.

    It used to be dated to the epoch -- which collides with genuine 1970 timestamps --
    and then hidden, because a block of placeholder dates at the top of the Timeline is
    useless to open on. Sorting it to the end gets the same reading experience without
    hiding anything or inventing a date.
    """

    def test_untimestamped_items_sort_after_real_ones(self):
        early = _item(datetime.datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC))
        later = _item(datetime.datetime(2024, 6, 1, tzinfo=UTC))
        untimed = _item(None)

        ordered = sorted([untimed, later, early], key=timeline_sort_key)
        self.assertEqual([early, later, untimed], ordered)

    def test_a_genuine_epoch_timestamp_still_sorts_first(self):
        # The whole point: 1970 is a real date, so it must stay distinguishable from
        # "no timestamp" instead of being lumped in with it at the end.
        epoch = _item(datetime.datetime(1970, 1, 1, tzinfo=UTC))
        untimed = _item(None)
        self.assertEqual([epoch, untimed], sorted([untimed, epoch], key=timeline_sort_key))

    def test_sorting_tolerates_naive_datetimes(self):
        naive = _item(datetime.datetime(2024, 6, 1))
        aware = _item(datetime.datetime(2024, 1, 1, tzinfo=UTC))
        untimed = _item(None)
        ordered = sorted([untimed, naive, aware], key=timeline_sort_key)
        self.assertEqual([aware, naive, untimed], ordered)

    def test_comparison_operator_is_none_safe(self):
        # Anything still sorting via __lt__ must not raise on a None timestamp.
        untimed = _item(None)
        real = _item(datetime.datetime(2024, 6, 1, tzinfo=UTC))
        self.assertTrue(real < untimed)
        self.assertFalse(untimed < real)
        self.assertEqual([real, untimed], sorted([untimed, real]))


class TestNoneOnFailure(unittest.TestCase):
    """to_datetime can report 'no time could be read' instead of returning the epoch."""

    def test_unconvertible_value_returns_none_when_opted_in(self):
        self.assertIsNone(to_datetime('not a timestamp', UTC, none_on_failure=True))

    def test_default_behaviour_is_unchanged(self):
        self.assertEqual(to_datetime('not a timestamp', UTC),
                         datetime.datetime.fromtimestamp(0, UTC))

    def test_valid_values_are_unaffected_by_the_flag(self):
        for value in (1655000000000000, 13000000000000000):
            with self.subTest(value=value):
                self.assertEqual(to_datetime(value, UTC),
                                 to_datetime(value, UTC, none_on_failure=True))

    def test_zero_is_still_a_real_timestamp_unless_none_if_unset(self):
        # 0 converts cleanly, so none_on_failure must not touch it -- that is what
        # none_if_unset is for, and the two flags mean different things.
        self.assertEqual(to_datetime(0, UTC, none_on_failure=True),
                         datetime.datetime.fromtimestamp(0, UTC))
        self.assertIsNone(to_datetime(0, UTC, none_if_unset=True))


if __name__ == '__main__':
    unittest.main()
