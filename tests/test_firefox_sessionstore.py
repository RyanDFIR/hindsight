import copy
import datetime
import os
import unittest

from pyhindsight.browsers.firefox import Firefox


FIXTURE_DIR = os.path.join('tests', 'fixtures', 'firefox')


def _make_firefox():
    ff = Firefox(FIXTURE_DIR, no_copy=True, temp_dir=None,
                 timezone=datetime.timezone.utc)
    ff.parsed_artifacts = []
    return ff


def _empty_structure():
    return {
        'windows': {}, 'tabs': {}, 'tab_groups': {},
        'active_window': None, 'tab_current_urls': {}, 'tab_nav_stacks': {},
        'entries_seen': 0,
    }


# A tab whose back/forward stack walks a shop: index -> product -> index -> product,
# ending somewhere innocuous. Only the tab carries a time (lastAccessed), so before
# this split every entry but the last was dated to the epoch and hidden.
SESSIONSTORE_DOC = {
    'selectedWindow': 1,
    'windows': [{
        'selected': 1,
        'sizemode': 'maximized',
        'width': 1244, 'height': 823, 'screenX': 4, 'screenY': 4,
        'tabs': [{
            'index': 4,  # 1-based -> nav_index 3 is current
            'lastAccessed': 1655000000000,
            'pinned': True,
            'entries': [
                {'url': 'https://shop.example/', 'title': 'Shop'},
                {'url': 'https://shop.example/product/a', 'title': 'Product A'},
                {'url': 'https://shop.example/product/b', 'title': 'Product B'},
                {'url': 'about:home', 'title': 'New Tab'},
            ],
        }],
        '_closedTabs': [
            {'closedAt': 1655000111000,
             'state': {'entries': [{'url': 'https://closed.example/', 'title': 'Closed'}]}},
            # No closedAt -> no time to report at all.
            {'state': {'entries': [{'url': 'https://undated.example/', 'title': 'Undated'}]}},
        ],
    }],
}


class TestFirefoxSessionstoreSplit(unittest.TestCase):
    """Nav entries are structural and go to the Sessions sheet; only entries that
    carry a real timestamp are also emitted to the Timeline."""

    def setUp(self):
        self.ff = _make_firefox()
        self.structure = _empty_structure()
        self.seen_windows = {}
        self.results = []
        self.ff._walk_sessionstore(
            SESSIONSTORE_DOC, 'current', 'sessionstore.jsonlz4',
            self.results, self.structure, self.seen_windows)

    def test_only_timestamped_entries_reach_the_timeline(self):
        # The selected open-tab entry (has lastAccessed) and the closed tab that has a
        # closedAt -- but not the other three nav entries, and not the undated closed tab.
        urls = sorted(item.url for item in self.results)
        self.assertEqual(urls, ['about:home', 'https://closed.example/'])

        # Nothing reaches the Timeline with a fabricated epoch timestamp.
        epoch = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
        for item in self.results:
            self.assertNotEqual(item.timestamp, epoch)

    def test_row_types_do_not_carry_the_snapshot_filename(self):
        # Each upgrade.jsonlz4-<ts> used to mint its own row_type, so the column had
        # unbounded cardinality. The snapshot is reported in Source Item instead.
        types = {item.row_type for item in self.results}
        self.assertEqual(types, {'session (open tab)', 'session (closed tab)'})
        for item in self.results:
            self.assertEqual(item.source_item, 'sessionstore.jsonlz4')

    def test_full_nav_stack_is_kept_for_the_sessions_sheet(self):
        tab_id = 'w0.t0'
        stack = self.structure['tab_nav_stacks'][tab_id]
        self.assertEqual(
            [stack[i][0] for i in sorted(stack)],
            ['https://shop.example/', 'https://shop.example/product/a',
             'https://shop.example/product/b', 'about:home'])
        # The Sessions sheet orders by nav index, so entries carry no timestamp.
        self.assertTrue(all(entry[2] is None for entry in stack.values()))

    def test_tab_and_window_metadata(self):
        tab = self.structure['tabs']['w0.t0']
        self.assertEqual(tab['window_id'], 'w0')
        self.assertEqual(tab['index'], 0)
        self.assertTrue(tab['pinned'])
        self.assertEqual(tab['selected_nav_index'], 3)  # 1-based 4 -> 0-based 3

        window = self.structure['windows']['w0']
        self.assertEqual(window['show_state'], 'Maximized')
        self.assertEqual(window['bounds'], '1244x823 at (4,4)')
        self.assertEqual(window['selected_tab_index'], 0)
        self.assertEqual(window['sources'], ['current'])

        self.assertEqual(self.structure['tab_current_urls']['w0.t0'],
                         ('about:home', 'New Tab'))


class TestFirefoxSessionstoreDedupe(unittest.TestCase):
    """Snapshots overlap heavily; the same layout must be recorded once, with every
    snapshot it survives in named -- but differing timestamps are still real events."""

    def _walk(self, docs):
        ff = _make_firefox()
        structure = _empty_structure()
        seen_windows = {}
        results = []
        for label, doc in docs:
            ff._walk_sessionstore(doc, label, f'{label}-file', results, structure,
                                  seen_windows)
        return ff, structure, results

    def test_identical_layout_recorded_once_with_provenance(self):
        _, structure, _ = self._walk([
            ('current', SESSIONSTORE_DOC),
            ('recovery.jsonlz4', SESSIONSTORE_DOC),
            ('previous.jsonlz4', SESSIONSTORE_DOC),
        ])
        self.assertEqual(list(structure['windows']), ['w0'])
        self.assertEqual(structure['windows']['w0']['sources'],
                         ['current', 'recovery.jsonlz4', 'previous.jsonlz4'])
        self.assertEqual(list(structure['tabs']), ['w0.t0'])
        self.assertEqual(list(structure['tab_nav_stacks']), ['w0.t0'])

    def test_different_layout_gets_its_own_window(self):
        other = copy.deepcopy(SESSIONSTORE_DOC)
        other['windows'][0]['tabs'][0]['entries'].append(
            {'url': 'https://elsewhere.example/', 'title': 'Elsewhere'})
        _, structure, _ = self._walk([
            ('current', SESSIONSTORE_DOC),
            ('upgrade.jsonlz4-20240101000000', other),
        ])
        # An upgrade snapshot weeks apart is a different state, not a re-save of this one.
        self.assertEqual(sorted(structure['windows']), ['w0', 'w1'])

    def test_refocused_tab_keeps_both_timestamps(self):
        later = copy.deepcopy(SESSIONSTORE_DOC)
        later['windows'][0]['tabs'][0]['lastAccessed'] = 1655009999000
        ff, structure, results = self._walk([
            ('recovery.baklz4', SESSIONSTORE_DOC),
            ('recovery.jsonlz4', later),
        ])
        # Same layout -> one window ...
        self.assertEqual(list(structure['windows']), ['w0'])
        # ... but the tab was focused again between saves, so both times survive.
        collapsed = ff._collapse_duplicate_session_items(results)
        open_tabs = [i for i in collapsed if i.row_type == 'session (open tab)']
        self.assertEqual(len(open_tabs), 2)
        self.assertEqual(len({i.timestamp for i in open_tabs}), 2)

    def test_identical_rows_collapse_and_list_every_snapshot(self):
        ff, _, results = self._walk([
            ('recovery.baklz4', SESSIONSTORE_DOC),
            ('recovery.jsonlz4', SESSIONSTORE_DOC),
        ])
        collapsed = ff._collapse_duplicate_session_items(results)
        self.assertEqual(len(results), 4)      # 2 rows per snapshot
        self.assertEqual(len(collapsed), 2)    # nothing distinguishes them but the file
        for item in collapsed:
            self.assertEqual(item.source_item, 'recovery.baklz4-file, recovery.jsonlz4-file')


if __name__ == '__main__':
    unittest.main()
