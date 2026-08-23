import datetime
import os
import sqlite3
import tempfile
import unittest

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.webbrowser import WebBrowser

UTC = datetime.timezone.utc


def _url_item(timestamp):
    item = WebBrowser.URLItem(
        profile='p', visit_id=1, url='https://example.test/', title='t',
        visit_time=timestamp, last_visit_time=timestamp, visit_count=1,
        typed_count=0, from_visit=None, transition=0, hidden=0, favicon_id=None)
    item.timestamp = timestamp
    item.interpretation = None
    item.source_item = 'History'
    item.transition_friendly = 'link'
    item.visit_source = None
    item.opener_visit = None
    item.visit_duration = None
    return item


class TestSqliteDateNulls(unittest.TestCase):
    """An absent date must be NULL, not ''.

    '' sorts before every real date, so it is swept into any `timestamp < ...` range
    query, and MIN()/COUNT(column) treat it as a value -- MIN() over a table holding any
    '' returns '' instead of the earliest event. NULL is excluded from comparisons and
    aggregates, which is what a query against this table expects.
    """

    def setUp(self):
        session = AnalysisSession.__new__(AnalysisSession)
        session.parsed_artifacts = [
            _url_item(datetime.datetime(2024, 6, 1, tzinfo=UTC)),
            _url_item(None),
        ]
        session.parsed_storage = []
        session.parsed_extension_data = []
        session.parsed_sync_data = []
        session.preferences = []
        session.installed_extensions = None
        session.timezone = UTC

        fd, self.db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(fd)
        os.remove(self.db_path)
        session.generate_sqlite(self.db_path)
        self.con = sqlite3.connect(self.db_path)

    def tearDown(self):
        self.con.close()
        os.remove(self.db_path)

    def _one(self, sql):
        return self.con.execute(sql).fetchone()[0]

    def test_absent_timestamp_is_null_not_empty_string(self):
        self.assertEqual(self._one('SELECT COUNT(*) FROM timeline WHERE timestamp IS NULL'), 1)
        self.assertEqual(self._one("SELECT COUNT(*) FROM timeline WHERE timestamp = ''"), 0)

    def test_range_query_does_not_sweep_in_undated_rows(self):
        # The row with no timestamp must not answer "was there activity before 2020?".
        self.assertEqual(
            self._one("SELECT COUNT(*) FROM timeline WHERE timestamp < '2020-01-01'"), 0)

    def test_aggregates_ignore_undated_rows(self):
        self.assertEqual(self._one('SELECT MIN(timestamp) FROM timeline'),
                         '2024-06-01 00:00:00.000')
        self.assertEqual(self._one('SELECT COUNT(timestamp) FROM timeline'), 1)
        self.assertEqual(self._one('SELECT COUNT(*) FROM timeline'), 2)


if __name__ == '__main__':
    unittest.main()
