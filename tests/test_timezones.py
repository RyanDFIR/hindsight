import datetime
import json
import os
import re
import tempfile
import unittest
import zoneinfo

from pyhindsight.utils import parse_timezone
from tests.test_cli_smoke import CHROME_FIXTURE, run_hindsight

TEMPLATE = os.path.join('pyhindsight', 'templates', 'options_selector.tpl')


def offset(hours, minutes=0):
    return datetime.timedelta(hours=hours, minutes=minutes)


class TestParseTimezone(unittest.TestCase):

    def test_iana_names(self):
        for name in ('UTC', 'Asia/Kolkata', 'America/New_York', 'Asia/Kathmandu'):
            with self.subTest(name=name):
                self.assertEqual(zoneinfo.ZoneInfo(name), parse_timezone(name))

    def test_iana_names_ignore_case(self):
        # The proper spelling is what ends up in the XLSX header.
        for text, name in (('asia/kolkata', 'Asia/Kolkata'), ('utc', 'UTC'),
                           ('US/PACIFIC', 'US/Pacific')):
            with self.subTest(text=text):
                self.assertEqual(name, str(parse_timezone(text)))

    def test_utc_offsets(self):
        # IANA has no fixed zone for a half- or quarter-hour offset, so this form is
        # the only way to name one without knowing a city in it.
        cases = {
            'UTC+5:30': offset(5, 30),
            'UTC+05:30': offset(5, 30),
            'UTC+530': offset(5, 30),
            '+0530': offset(5, 30),
            'utc+5:45': offset(5, 45),
            'GMT-3': -offset(3),
            'UTC-03:30': -offset(3, 30),
            ' UTC + 9 ': offset(9),
            'UTC+14': offset(14),
            'UTC-12:00': -offset(12),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(expected, parse_timezone(text).utcoffset(None))

    def test_a_fixed_offset_is_labelled_as_one(self):
        # The XLSX timestamp header is "Timestamp (<timezone>)".
        self.assertEqual('UTC+05:30', str(parse_timezone('UTC+5:30')))

    def test_unusable_values(self):
        for value in (None, '', '   ', 'Mars/Olympus_Mons', 'UTC+15', 'UTC+5:75',
                      '+123:00', 'UTC+', '5:30', '../../etc/passwd', 'UTC\t+5', 42):
            with self.subTest(value=value):
                self.assertIsNone(parse_timezone(value))

    def test_a_tzinfo_is_passed_through(self):
        tz = datetime.timezone(offset(5, 30))
        self.assertIs(tz, parse_timezone(tz))


class TestGuiTimezoneChoices(unittest.TestCase):
    """The GUI's timezone list must name real zones and describe them correctly."""

    @classmethod
    def setUpClass(cls):
        with open(TEMPLATE, encoding='utf-8') as f:
            cls.options = re.findall(r'<option value="([^"]+)"[^>]*>([^<]+)</option>',
                                     f.read().split('name="timezone"')[1].split('</select>')[0])

    def test_india_is_offered(self):
        self.assertIn(('Asia/Kolkata', 'India [+5:30]'), self.options)

    def test_every_label_matches_the_zone(self):
        # "[+9:30/+10:30]" lists the standard and daylight offsets. A label that has
        # gone stale (a country dropping daylight saving, as Brazil did in 2019) points
        # every timestamp in the report at the wrong hour.
        for value, label in self.options:
            with self.subTest(zone=value):
                zone = zoneinfo.ZoneInfo(value)
                actual = {zone.utcoffset(datetime.datetime(2026, month, 1)) for month in (1, 7)}
                listed = set()
                for sign, hours, minutes in re.findall(r'([+-]?)(\d+)(?::(\d+))?',
                                                       label.split('[')[1]):
                    delta = offset(int(hours), int(minutes or 0))
                    listed.add(-delta if sign == '-' else delta)
                self.assertEqual(actual, listed, label)

    def test_listed_in_offset_order(self):
        # Easternmost first, by standard (non-daylight) offset.
        moment = datetime.datetime(2026, 1, 1)
        standard = [zoneinfo.ZoneInfo(value).utcoffset(moment) - zoneinfo.ZoneInfo(value).dst(moment)
                    for value, _ in self.options]
        self.assertEqual(sorted(standard, reverse=True), standard)


class TestCommandLineTimezone(unittest.TestCase):

    def test_a_utc_offset_reaches_the_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', '-t', 'UTC+5:30', '--only', 'downloads',
                                   output_dir=tmp, profile=CHROME_FIXTURE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("Couldn't understand timezone", result.stdout)
            with open(os.path.join(tmp, 'out.jsonl'), encoding='utf-8') as f:
                records = [json.loads(line) for line in f if line.strip()]
        self.assertTrue(records)
        for record in records:
            self.assertTrue(record['datetime'].endswith('+05:30'), record['datetime'])

    def test_an_unknown_timezone_is_refused(self):
        # Falling back to UTC would shift every timestamp in the report.
        with tempfile.TemporaryDirectory() as tmp:
            result = run_hindsight('-f', 'jsonl', '-t', 'IST (UTC+5:30)', '--only', 'downloads',
                                   output_dir=tmp, profile=CHROME_FIXTURE)
            self.assertEqual(2, result.returncode)
            self.assertIn("can't understand timezone", result.stderr)
            self.assertFalse(os.path.exists(os.path.join(tmp, 'out.jsonl')))


if __name__ == '__main__':
    unittest.main()
