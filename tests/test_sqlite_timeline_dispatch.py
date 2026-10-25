import datetime
import logging
import os
import sqlite3
import tempfile
import unittest

from pyhindsight.analysis import AnalysisSession
from pyhindsight.browsers.chrome import Chrome


class _ErrorCapture:
    """Capture what pyhindsight.analysis logs at ERROR during a block."""

    def __enter__(self):
        self.messages = []
        capture = self

        class _Handler(logging.Handler):
            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    capture.messages.append(record.getMessage())

        self.handler = _Handler(level=logging.DEBUG)
        self.logger = logging.getLogger('pyhindsight.analysis')
        self.previous_level = self.logger.level
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.previous_level)
        return False


class TestSqliteTimelineDispatch(unittest.TestCase):
    """A timeline row_type with no INSERT branch must not vanish.

    `generate_sqlite`'s storage loop grew a final else that counts and reports what it
    cannot place. The timeline loop had no such else, so an artifact whose row_type no
    branch matched was dropped with nothing said -- the same defect, in the dispatcher
    that did not get the fix.
    """

    def _write(self, row_types):
        session = AnalysisSession.__new__(AnalysisSession)
        session.parsed_artifacts = []
        session.parsed_storage = []
        session.parsed_extension_data = []
        session.parsed_sync_data = []
        session.preferences = []
        session.installed_extensions = []

        for row_type in row_types:
            item = Chrome.PreferenceItem(
                '/profile', url='abcdefghijklmnopabcdefghijklmnop',
                timestamp=datetime.datetime(2026, 1, 1), key='An Extension [abc]',
                value='Install source: unpacked', interpretation='')
            item.row_type = row_type
            item.source_item = 'Secure Preferences'
            session.parsed_artifacts.append(item)

        # NamedTemporaryFile/TemporaryDirectory cannot clean up a file sqlite3 still
        # holds open on Windows, so the path is built by hand and removed best-effort.
        directory = tempfile.mkdtemp()
        db_path = os.path.join(directory, 'output.sqlite')
        with _ErrorCapture() as captured:
            session.generate_sqlite(db_path)

        connection = sqlite3.connect(db_path)
        try:
            written = [row[0] for row in connection.execute('SELECT type FROM timeline')]
        finally:
            connection.close()
        return written, captured.messages

    def test_extension_install_events_reach_the_timeline_table(self):
        # get_extension_settings appends `extension (installed)` / `(updated)` to
        # parsed_artifacts, and the XLSX writer has a branch for them. The SQLite
        # timeline had none, so every extension install and update event was dropped.
        written, _ = self._write(['extension (installed)', 'extension (updated)'])

        self.assertEqual(
            ['extension (installed)', 'extension (updated)'], sorted(written))

    def test_an_unhandled_row_type_is_reported_rather_than_dropped_silently(self):
        written, errors = self._write(['a row_type no branch handles'])

        self.assertEqual([], written)
        matching = [m for m in errors if 'a row_type no branch handles' in m]
        self.assertTrue(matching, errors)
        self.assertIn('MISSING from the SQLite timeline table', matching[0])

    def test_unhandled_rows_are_counted_not_reported_once_each(self):
        # The storage loop reports one line per row_type with a count; the timeline
        # loop matches it, so a million dropped rows are one line, not a million.
        written, errors = self._write(['unknown kind'] * 3)

        matching = [m for m in errors if 'unknown kind' in m]
        self.assertEqual(1, len(matching), errors)
        self.assertIn('3 "unknown kind"', matching[0])

    def test_a_handled_row_type_is_not_reported_as_missing(self):
        written, errors = self._write(['preference', 'site setting'])

        self.assertEqual(2, len(written))
        self.assertEqual(
            [], [m for m in errors if 'MISSING from the SQLite timeline' in m], errors)


if __name__ == '__main__':
    unittest.main()
