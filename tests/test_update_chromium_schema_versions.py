"""The offline parts of tools/update_chromium_schema_versions.py: nothing here touches the network."""
import importlib.util
import pathlib
import tempfile
import unittest
import unittest.mock

TOOL = pathlib.Path(__file__).resolve().parent.parent / 'tools' / 'update_chromium_schema_versions.py'
spec = importlib.util.spec_from_file_location('update_chromium_schema_versions', TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class TestPickReleaseTags(unittest.TestCase):

    def test_the_last_release_is_the_most_patched_build(self):
        # 5.0.396.0 is a later build than any Chrome 5 release, tagged before the version
        # number moved to 6. The release branch is 5.0.375, which has the patch releases.
        tags = [(5, 0, 342, 0), (5, 0, 375, 0), (5, 0, 375, 99), (5, 0, 375, 127), (5, 0, 396, 0),
                (6, 0, 472, 0), (6, 0, 472, 63)]
        self.assertEqual({5: '5.0.375.127', 6: '6.0.472.63'}, tool.pick_release_tags(tags))

    def test_a_version_with_only_canary_builds_uses_its_newest_build(self):
        tags = [(156, 0, 8050, 0), (156, 0, 8066, 0)]
        self.assertEqual({156: '156.0.8066.0'}, tool.pick_release_tags(tags))


class TestSchemaVersionIn(unittest.TestCase):

    def test_the_forms_chromium_has_used(self):
        for source, expected in [
            ('static constexpr int kCurrentVersionNumber = 153;', 153),
            ('const int WebDatabase::kCurrentVersionNumber = 82;', 82),
            ('constexpr int kCurrentVersionNumber = 43;\nconstexpr int kCompatibleVersionNumber = 40;', 43),
            ('static constexpr int kLatestSchemaVersion = 11;\n'
             'static constexpr int kMinCompatibleSchemaVersion = 11;', 11),
        ]:
            with self.subTest(source=source):
                self.assertEqual(expected, tool.schema_version_in(source))

    def test_commented_out_values_are_ignored(self):
        source = '// const int kCurrentVersionNumber = 5;\nconst int kCurrentVersionNumber = 6;'
        self.assertEqual(6, tool.schema_version_in(source))

    def test_no_single_value_gives_none(self):
        self.assertIsNone(tool.schema_version_in('int x = 1;'))
        self.assertIsNone(tool.schema_version_in(
            'const int kCurrentVersionNumber = 5;\nconst int kCurrentVersionNumber = 6;'))


class TestDataModule(unittest.TestCase):

    RELEASE_TAGS = {109: '109.0.5414.120', 110: '110.0.5481.213'}
    SCHEMA_VERSIONS = {109: {'History': 59, 'Web Data': 107}, 110: {'History': 59, 'DIPS': 2}}
    SOURCE_PATHS = {'History': {'components/history/core/browser/history_database.cc': (109, 110)}}

    def test_what_is_written_reads_back_the_same(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'data.py'
            path.write_text(tool.render(self.RELEASE_TAGS, self.SCHEMA_VERSIONS, self.SOURCE_PATHS),
                            encoding='utf-8')
            data = tool.load_data(path)
        self.assertEqual(self.RELEASE_TAGS, data['RELEASE_TAGS'])
        self.assertEqual(self.SCHEMA_VERSIONS, data['SCHEMA_VERSIONS'])
        self.assertEqual(self.SOURCE_PATHS['History'], data['SOURCE_PATHS']['History'])

    def test_known_results_keep_absences_only_from_before_a_database_existed(self):
        data = {
            'RELEASE_TAGS': {108: '108.tag', 109: '109.tag', 110: '110.tag'},
            'SCHEMA_VERSIONS': {108: {'History': 58}, 109: {'History': 59, 'DIPS': 1}, 110: {'DIPS': 2}},
        }
        known = tool.known_results(data)
        self.assertEqual(58, known[('108.tag', 'History')])
        self.assertEqual(2, known[('110.tag', 'DIPS')])
        # DIPS didn't exist before 109: settled, never read again.
        self.assertIsNone(known[('108.tag', 'DIPS')])
        # History went missing after it had been found: a moved file, so read it again.
        self.assertNotIn(('110.tag', 'History'), known)
        # A database never found anywhere is settled as absent everywhere.
        self.assertIsNone(known[('110.tag', 'Cookies')])


class TestCollect(unittest.TestCase):
    """collect() with fetching replaced by a fake source tree."""

    RELEASE_TAGS = {100: 't100', 101: 't101', 102: 't102', 103: 't103'}

    def _collect(self, files, known=None):
        # files: {(tag, path): source}
        def fake_fetch(tag, path):
            return files.get((tag, path))
        databases = {'History': ['new/history.cc', 'old/history.cc']}
        with unittest.mock.patch.object(tool, 'fetch', fake_fetch), \
                unittest.mock.patch.object(tool, 'DATABASES', databases):
            return tool.collect(self.RELEASE_TAGS, known or {}, lambda: None)

    def test_a_moved_file_is_followed_and_older_releases_stop_at_the_first_miss(self):
        files = {
            ('t103', 'new/history.cc'): 'const int kCurrentVersionNumber = 12;',
            ('t102', 'new/history.cc'): 'const int kCurrentVersionNumber = 11;',
            ('t101', 'old/history.cc'): 'const int kCurrentVersionNumber = 10;',
            # t100 has no History at all: the database begins at 101.
        }
        schema_versions, source_paths, unresolved = self._collect(files)
        self.assertEqual({101: {'History': 10}, 102: {'History': 11}, 103: {'History': 12}}, schema_versions)
        self.assertEqual({'new/history.cc': (102, 103), 'old/history.cc': (101, 101)}, source_paths['History'])
        self.assertEqual({}, unresolved)

    def test_missing_from_the_newest_releases_is_reported(self):
        files = {
            ('t101', 'old/history.cc'): 'const int kCurrentVersionNumber = 10;',
            ('t100', 'old/history.cc'): 'const int kCurrentVersionNumber = 9;',
        }
        _, _, unresolved = self._collect(files)
        self.assertEqual({'History': [102, 103]}, unresolved)

    def test_known_results_are_not_read_again(self):
        files = {('t103', 'new/history.cc'): 'const int kCurrentVersionNumber = 12;'}
        known = {('t102', 'History'): 11, ('t101', 'History'): 10, ('t100', 'History'): None}
        schema_versions, _, unresolved = self._collect(files, known)
        self.assertEqual({101: {'History': 10}, 102: {'History': 11}, 103: {'History': 12}}, schema_versions)
        self.assertEqual({}, unresolved)


if __name__ == '__main__':
    unittest.main()
