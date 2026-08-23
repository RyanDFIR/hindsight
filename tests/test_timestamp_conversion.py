import datetime
import unittest

from pyhindsight.utils import (
    MAX_CONVERTIBLE_WEBKIT_MICROSECONDS,
    WEBKIT_EPOCH_OFFSET_SECONDS,
    to_datetime,
)

UTC = datetime.timezone.utc

# The raw epoch-microsecond limit: seconds from 1970 to year 10000, in microseconds.
# The clamp used to use this, which is the bug these tests pin down.
EPOCH_MICROSECOND_LIMIT = 253402300800 * 1_000_000


class TestClampBound(unittest.TestCase):
    """The clamp must use the Webkit-adjusted limit, not the raw epoch one.

    Chrome writes microseconds since 1601, and the conversion below the clamp applies
    that offset. A value between the two limits is unrepresentable only if read as
    microseconds since 1970; read as Webkit microseconds it is an ordinary (if absurd)
    date in the years 9631-9999. Clamping at the lower bound discarded those before the
    Webkit branch could convert them -- and because the clamp is skipped for quiet
    callers, the same input produced two different answers depending on a logging flag.
    """

    def test_bound_is_the_webkit_adjusted_limit(self):
        self.assertEqual(
            MAX_CONVERTIBLE_WEBKIT_MICROSECONDS,
            (253402300800 + WEBKIT_EPOCH_OFFSET_SECONDS) * 1_000_000)
        # The two limits differ by exactly the epoch offset -- that gap was the bug.
        self.assertEqual(
            MAX_CONVERTIBLE_WEBKIT_MICROSECONDS - EPOCH_MICROSECOND_LIMIT,
            WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000)

    def test_values_in_the_gap_convert_instead_of_clamping(self):
        # Both are real values from a 71-profile run that previously clamped.
        for value, expected in (
                (265046731200000000, datetime.datetime(9999, 12, 31, 12, 0, tzinfo=UTC)),
                (265046773601599970,
                 datetime.datetime(9999, 12, 31, 23, 46, 41, 599976, tzinfo=UTC)),
        ):
            with self.subTest(value=value):
                self.assertEqual(to_datetime(value, UTC), expected)
                self.assertNotEqual(to_datetime(value, UTC), datetime.datetime.max)

    def test_quiet_and_loud_agree_in_the_gap(self):
        # A logging flag must not change the parsed value for a representable input.
        for value in (EPOCH_MICROSECOND_LIMIT,
                      265046731200000000,
                      MAX_CONVERTIBLE_WEBKIT_MICROSECONDS - 1_000_000):
            with self.subTest(value=value):
                self.assertEqual(to_datetime(value, UTC),
                                 to_datetime(value, UTC, quiet=True))

    def test_genuinely_unrepresentable_values_still_clamp(self):
        for value in (MAX_CONVERTIBLE_WEBKIT_MICROSECONDS,
                      1840922744000000000):
            with self.subTest(value=value):
                self.assertEqual(to_datetime(value, UTC).replace(tzinfo=None),
                                 datetime.datetime.max)

    def test_ordinary_timestamps_are_unaffected(self):
        # Guards against the bound change disturbing the normal conversion paths.
        self.assertEqual(to_datetime(13000000000000000, UTC),
                         datetime.datetime(2012, 12, 14, 23, 6, 40, tzinfo=UTC))
        self.assertEqual(to_datetime(1655000000000000, UTC),
                         datetime.datetime(2022, 6, 12, 2, 13, 20, tzinfo=UTC))


if __name__ == '__main__':
    unittest.main()
