import datetime
import json
import os
import shutil
import sqlite3
import tempfile
import unittest

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.webbrowser import WebBrowser

UTC = datetime.timezone.utc


def _session():
    session = AnalysisSession.__new__(AnalysisSession)
    session.parsed_artifacts = []
    session.parsed_storage = []
    session.parsed_extension_data = []
    session.parsed_sync_data = []
    session.preferences = []
    session.installed_extensions = None
    session.timezone = UTC
    return session


def _chrome_structure():
    # The shape Chrome.get_sessions builds: two windows, the first active and holding a
    # pinned tab, a selected tab in a group, and a tab with no index.
    return {
        'profile': 'C:\\Users\\bob\\Default',
        'browser': 'Chrome',
        'windows': {
            11: {'type': 'Normal', 'show_state': 'Maximized', 'bounds': '1247x1012 at (30,30)',
                 'rect': {'x': 30, 'y': 30, 'width': 1247, 'height': 1012}, 'selected_tab_index': 1},
            20: {'type': 'Popup', 'show_state': 'Normal'},
        },
        'tabs': {
            101: {'window_id': 11, 'index': 0, 'pinned': True, 'selected_nav_index': 0},
            102: {'window_id': 11, 'index': 1, 'selected_nav_index': 1, 'group_token': 'g1'},
            103: {'window_id': 11, 'selected_nav_index': 0},
            201: {'window_id': 20, 'index': 0},
        },
        'tab_groups': {'g1': {'title': 'Work'}},
        'active_window': 11,
        'tab_current_urls': {101: ('https://mail.example/', 'Mail'), 102: ('https://b.example/', 'B')},
        'tab_nav_stacks': {
            101: {0: ('https://mail.example/', 'Mail', datetime.datetime(2026, 9, 22, 18, 0, tzinfo=UTC))},
            102: {0: ('https://a.example/', 'A', datetime.datetime(2026, 9, 22, 18, 5, tzinfo=UTC)),
                  1: ('https://b.example/', 'B', datetime.datetime(2026, 9, 22, 18, 7, tzinfo=UTC))},
        },
    }


class TestSessionWindowRecords(unittest.TestCase):
    """The Sessions sheet's windows and tab layout, written to JSONL as well."""

    def setUp(self):
        self.directory = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _records(self, session):
        path = os.path.join(self.directory, 'report.jsonl')
        session.generate_jsonl(path)
        with open(path, encoding='utf-8') as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_each_window_becomes_a_record_with_its_tabs_in_order(self):
        session = _session()
        session.session_structures = [_chrome_structure()]
        windows = {r['window_id']: r for r in self._records(session)
                   if r['data_type'] == 'chrome:session:window'}
        self.assertEqual({11, 20}, set(windows))

        main = windows[11]
        self.assertEqual({'x': 30, 'y': 30, 'width': 1247, 'height': 1012}, main['window_rect'])
        self.assertEqual('Maximized', main['window_state'])
        self.assertTrue(main['active'])
        self.assertEqual('C:\\Users\\bob\\Default', main['profile'])
        self.assertEqual([101, 102, 103], [t['tab_id'] for t in main['tabs']])
        self.assertEqual(3, main['tab_count'])

        pinned, grouped, unindexed = main['tabs']
        self.assertTrue(pinned['pinned'])
        self.assertFalse(pinned['selected'])
        self.assertTrue(grouped['selected'])
        self.assertEqual('Work', grouped['group'])
        self.assertEqual('https://b.example/', grouped['url'])
        self.assertEqual(2, grouped['navigation_count'])
        self.assertNotIn('index', unindexed)

    def test_a_window_is_dated_by_its_latest_navigation(self):
        session = _session()
        session.session_structures = [_chrome_structure()]
        windows = {r['window_id']: r for r in self._records(session)
                   if r['data_type'] == 'chrome:session:window'}
        self.assertEqual('2026-09-22T18:07:00+00:00', windows[11]['datetime'])
        self.assertEqual('Last Navigation Time', windows[11]['timestamp_desc'])
        # No navigations to go by: no time is invented.
        self.assertEqual('Not a time', windows[20]['timestamp_desc'])
        self.assertNotIn('window_rect', windows[20])
        self.assertFalse(windows[20]['active'])

    def test_firefox_windows_are_labeled_as_firefox(self):
        structure = _chrome_structure()
        structure['browser'] = 'Firefox'
        session = _session()
        session.session_structures = [structure]
        types = {r['data_type'] for r in self._records(session)}
        self.assertIn('firefox:session:window', types)
        self.assertNotIn('chrome:session:window', types)

    def test_no_session_structures_writes_no_window_records(self):
        records = self._records(_session())
        self.assertFalse([r for r in records if r['data_type'].endswith(':session:window')])


def _visit(tab_id, window_id):
    timestamp = datetime.datetime(2026, 9, 22, 18, 1, tzinfo=UTC)
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
    item.tab_id = tab_id
    item.window_id = window_id
    return item


def _session_row(row_type, session_id, window_id):
    item = WebBrowser.SessionItem(
        profile='p', url='https://example.test/', title='t',
        timestamp=datetime.datetime(2026, 9, 22, 18, 2, tzinfo=UTC), session_id=session_id)
    item.row_type = row_type
    item.interpretation = None
    item.source_item = 'Session_1'
    if window_id is not None:
        item.window_id = window_id
    return item


class TestSessionWindowsSqlite(unittest.TestCase):
    """The same tab and window facts reach the SQLite output."""

    def setUp(self):
        self.directory = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _query(self, session, sql):
        path = os.path.join(self.directory, 'report.sqlite')
        if not os.path.exists(path):
            session.generate_sqlite(path)
        db = sqlite3.connect(path)
        try:
            return db.execute(sql).fetchall()
        finally:
            db.close()

    def test_visits_and_session_rows_carry_their_tab_and_window(self):
        session = _session()
        session.parsed_artifacts = [
            _visit(101, 11),
            _session_row('session (navigation)', 102, 11),
            _session_row('session (window closed)', 20, 20),
            _session_row('session (closed tab)', 999, None),
        ]
        rows = self._query(session, 'SELECT type, tab_id, window_id, session_id FROM timeline ORDER BY rowid')
        self.assertEqual([
            ('url', '101', '11', None),
            ('session (navigation)', None, '11', '102'),
            ('session (window closed)', None, '20', '20'),
            ('session (closed tab)', None, None, '999'),
        ], rows)

    def test_windows_and_their_tabs_get_tables(self):
        session = _session()
        session.session_structures = [_chrome_structure()]
        windows = self._query(
            session, 'SELECT window_id, browser, timestamp, window_state, x, y, width, height, active, tab_count '
                     'FROM session_windows ORDER BY window_id')
        self.assertEqual([
            ('11', 'Chrome', '2026-09-22 18:07:00.000', 'Maximized', 30, 30, 1247, 1012, 1, 3),
            # No navigations: no time, rather than the epoch.
            ('20', 'Chrome', None, 'Normal', None, None, None, None, 0, 1),
        ], windows)

        tabs = self._query(
            session, 'SELECT tab_id, tab_index, selected, pinned, tab_group, navigation_count, url '
                     "FROM session_tabs WHERE window_id = '11' ORDER BY rowid")
        self.assertEqual([
            ('101', 0, 0, 1, None, 1, 'https://mail.example/'),
            ('102', 1, 1, 0, 'Work', 2, 'https://b.example/'),
            ('103', None, 0, 0, None, 0, None),
        ], tabs)

    def test_timeline_window_ids_join_the_window_table(self):
        session = _session()
        session.session_structures = [_chrome_structure()]
        session.parsed_artifacts = [_visit(101, 11)]
        joined = self._query(
            session, 'SELECT w.window_state FROM timeline t JOIN session_windows w ON w.window_id = t.window_id')
        self.assertEqual([('Maximized',)], joined)


if __name__ == '__main__':
    unittest.main()
