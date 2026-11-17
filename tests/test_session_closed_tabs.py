import datetime
import json
import os
import shutil
import struct
import tempfile
import unittest

from pyhindsight.browsers.chrome import Chrome
from tests.test_session_windows import _session

UTC = datetime.timezone.utc

# A Webkit timestamp (microseconds since 1601) in 2025, for TabClosed's close time.
CLOSE_TIME = 13395345000000000


def _command(cmd_id, payload):
    body = bytes([cmd_id]) + payload
    return struct.pack('<H', len(body)) + body


def set_tab_window(window_id, tab_id):
    return _command(0, struct.pack('<II', window_id, tab_id))


def set_tab_index(tab_id, index):
    return _command(2, struct.pack('<Ii', tab_id, index))


def set_selected_tab(window_id, index):
    return _command(8, struct.pack('<Ii', window_id, index))


def tab_closed(tab_id):
    return _command(16, struct.pack('<I4xq', tab_id, CLOSE_TIME))


class TestClosedSessionTabs(unittest.TestCase):
    """A tab closed during the session is no longer in its window.

    Chrome records the close with TabClosed and renumbers the tabs that are left with
    SetTabIndexInWindow; it never says the closed tab left the window. Before this was
    handled, the closed tab stayed listed, sharing its old index with whichever open tab
    took it, so a window showed two tabs at index 0, both selected, and too many tabs.
    The sequence below is the one seen in the bf4sa_2025_bob-1 Default profile.
    """

    def setUp(self):
        self.profile = tempfile.mkdtemp()
        os.mkdir(os.path.join(self.profile, 'Sessions'))

    def tearDown(self):
        shutil.rmtree(self.profile, ignore_errors=True)

    def _parse(self, *commands):
        with open(os.path.join(self.profile, 'Sessions', 'Session_13395344959218906'), 'wb') as f:
            f.write(b'SNSS' + struct.pack('<I', 3))
            for command in commands:
                f.write(command)
        chrome = Chrome(self.profile, timezone=UTC, no_copy=True)
        chrome.get_sessions(self.profile, 'Sessions')
        return chrome.session_structure

    def _windows(self, structure):
        session = _session()
        session.session_structures = [{'profile': self.profile, **structure}]
        return {w['window_id']: w for w in session.session_window_records()}

    def _close_the_first_of_three(self):
        return self._parse(
            set_tab_window(7, 1), set_tab_window(7, 2), set_tab_window(7, 3),
            set_tab_index(1, 0), set_tab_index(2, 1), set_tab_index(3, 2),
            set_selected_tab(7, 0),
            tab_closed(1),
            set_tab_index(2, 0), set_tab_index(3, 1),
            set_selected_tab(7, 0),
        )

    def test_a_closed_tab_is_left_out_of_its_window(self):
        window = self._windows(self._close_the_first_of_three())[7]
        self.assertEqual([2, 3], [t['tab_id'] for t in window['tabs']])
        self.assertEqual(2, window['tab_count'])
        self.assertEqual([0, 1], [t['index'] for t in window['tabs']])

    def test_only_the_open_tab_at_the_selected_index_is_selected(self):
        window = self._windows(self._close_the_first_of_three())[7]
        self.assertEqual([2], [t['tab_id'] for t in window['tabs'] if t['selected']])

    def test_the_closed_tab_keeps_its_window_for_its_timeline_rows(self):
        # The "tab closed" row still names the window it was closed from.
        tab = self._close_the_first_of_three()['tabs'][1]
        self.assertTrue(tab['closed'])
        self.assertEqual(7, tab['window_id'])

    def test_a_tab_placed_in_a_window_again_is_open(self):
        structure = self._parse(
            set_tab_window(7, 1), set_tab_index(1, 0),
            tab_closed(1),
            set_tab_window(8, 1), set_tab_index(1, 0),
        )
        windows = self._windows(structure)
        self.assertEqual([1], [t['tab_id'] for t in windows[8]['tabs']])
        self.assertEqual([], windows[7]['tabs'])

    def test_closed_tabs_are_left_out_of_the_jsonl_window_records(self):
        session = _session()
        session.session_structures = [{'profile': self.profile, **self._close_the_first_of_three()}]
        path = os.path.join(self.profile, 'report.jsonl')
        session.generate_jsonl(path)
        with open(path, encoding='utf-8') as f:
            windows = [json.loads(line) for line in f
                       if '"chrome:session:window"' in line]
        self.assertEqual([[2, 3]], [[t['tab_id'] for t in w['tabs']] for w in windows])


if __name__ == '__main__':
    unittest.main()
