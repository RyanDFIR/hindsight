"""Chromium packs facts into notification_id; Hindsight was dropping all of them.

The developer tag is the slot a site overwrites, so it is what tells six
reminders from one recurring channel apart from six unrelated alerts. ccl parses
it, and `get_platform_notifications` used neither it nor `notification_id`.
"""
import unittest

from pyhindsight.browsers.chrome import Chrome


class TestDecodeNotificationId(unittest.TestCase):
    def test_the_real_sample_from_the_corpus(self):
        # bf4sa_2026_bob-2, Default profile: six live notifications, all from
        # Google Calendar, all sharing this id.
        decoded = Chrome.decode_notification_id(
            'p#https://calendar.google.com/#1event-notification')

        self.assertEqual(decoded, {
            'persistent': True,
            'raised_by': 'page',
            'origin': 'https://calendar.google.com/',
            'kind': 'developer tag',
            'value': 'event-notification',
        })

    def test_non_persistent_and_browser_raised(self):
        decoded = Chrome.decode_notification_id('nbhttps://example.test/#0abc123')

        self.assertFalse(decoded['persistent'])
        self.assertEqual(decoded['raised_by'], 'browser')
        self.assertEqual(decoded['kind'], 'notification id')
        self.assertEqual(decoded['value'], 'abc123')

    def test_an_origin_containing_a_hash_stops_at_the_first_one(self):
        # partition() splits on the first '#', which is the separator; the
        # test pins that rather than leaving it to chance.
        decoded = Chrome.decode_notification_id('p#https://a.test/#1tag#with#hashes')

        self.assertEqual(decoded['origin'], 'https://a.test/')
        self.assertEqual(decoded['value'], 'tag#with#hashes')

    def test_an_empty_value_still_decodes(self):
        decoded = Chrome.decode_notification_id('p#https://a.test/#1')

        self.assertEqual(decoded['value'], '')
        self.assertEqual(decoded['kind'], 'developer tag')

    def test_anything_unrecognised_decodes_to_nothing(self):
        # None rather than a guess, so a format change degrades to "we do not
        # know" and the caller falls back to printing the raw id.
        for value in (
            None,
            '',
            'p',
            'p#',
            'x#https://a.test/#1tag',      # neither p nor n
            'pxhttps://a.test/#1tag',      # neither b nor #
            'p#https://a.test/',           # no separator before the type digit
            'p#https://a.test/#',          # separator but nothing after it
            'p#https://a.test/#9tag',      # unknown type digit
            'an-opaque-handle',
        ):
            with self.subTest(value=value):
                self.assertIsNone(Chrome.decode_notification_id(value))


if __name__ == '__main__':
    unittest.main()
