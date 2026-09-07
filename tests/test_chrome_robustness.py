import json
import os
import pathlib
import tempfile
import unittest

from pyhindsight.browsers.chrome import Chrome


class TestExtensionVersionDirectories(unittest.TestCase):
    """A malformed version directory must not abort the whole Extensions parse.

    Version directories are named `<version>_<n>`, and the newest is picked by sorting
    on the numeric components. A directory whose name has a non-numeric component (a
    stray folder, a beta build) used to raise ValueError inside the sort key, which
    took down the entire parse rather than that one extension.
    """

    def _extension(self, tmp, versions):
        ext = pathlib.Path(tmp, 'abcdefghijklmnopabcdefghijklmnop')
        for name, manifest in versions.items():
            version_dir = ext / name
            version_dir.mkdir(parents=True)
            (version_dir / 'manifest.json').write_text(
                json.dumps(manifest), encoding='utf-8')
        return ext

    def test_a_non_numeric_version_directory_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp, {'beta.x_0': {'name': 'Odd', 'version': 'beta'}})
            manifest, version = Chrome.load_extension_manifest(ext)
            self.assertEqual('Odd', manifest['name'])

    def test_a_real_version_is_preferred_over_a_malformed_one(self):
        # The sort runs newest-first, so a malformed name must rank last rather than
        # being mistaken for the newest version.
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp, {
                '1.2.3_0': {'name': 'Good', 'version': '1.2.3'},
                'beta.x_0': {'name': 'Odd', 'version': 'beta'},
            })
            manifest, version = Chrome.load_extension_manifest(ext)
            self.assertEqual('Good', manifest['name'])
            self.assertEqual('1.2.3_0', version)

    def test_highest_numeric_version_still_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp, {
                '1.2.3_0': {'name': 'Old', 'version': '1.2.3'},
                '1.10.0_0': {'name': 'New', 'version': '1.10.0'},
            })
            manifest, version = Chrome.load_extension_manifest(ext)
            # 10 > 2 numerically, which is the reason for the numeric sort in the
            # first place (a string sort would pick 1.2.3).
            self.assertEqual('New', manifest['name'])

    def test_a_single_component_version_directory_is_found(self):
        # `7_0` carries no dot, so the old "*.*_*" glob never listed it and the
        # extension was reported unreadable with its manifest.json sitting there.
        # Single-component versions were common in early Chrome, so this skews toward
        # older profiles.
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp, {'7_0': {'name': 'Mail', 'version': '7'}})
            manifest, version = Chrome.load_extension_manifest(ext)
            self.assertEqual('Mail', manifest['name'])
            self.assertEqual('7_0', version)

    def test_the_unpack_counter_does_not_contaminate_the_last_component(self):
        # The `_<n>` suffix is an unpack counter, not part of the version. Splitting on
        # '.' without stripping it first left the last component as '3_0' rather than
        # '3', which is not a digit, so *every* ordinary name fell to the non-numeric
        # branch there and was compared as a string: '3_0' > '10_0' picked 1.2.3.
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp, {
                '1.2.3_0': {'name': 'Old', 'version': '1.2.3'},
                '1.2.10_0': {'name': 'New', 'version': '1.2.10'},
            })
            manifest, version = Chrome.load_extension_manifest(ext)
            self.assertEqual('New', manifest['name'])
            self.assertEqual('1.2.10_0', version)

    def test_single_and_multi_component_versions_order_together(self):
        # Widening the glob means both shapes can now appear side by side, so they have
        # to compare against each other and not just among themselves: 7 > 1.2.3.
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp, {
                '7_0': {'name': 'Single', 'version': '7'},
                '1.2.3_0': {'name': 'Multi', 'version': '1.2.3'},
            })
            manifest, version = Chrome.load_extension_manifest(ext)
            self.assertEqual('Single', manifest['name'])
            self.assertEqual('7_0', version)

    def test_a_non_directory_matching_the_glob_is_ignored(self):
        # The old glob's dot also kept out extraneous files such as $I30 from FTK.
        # Widening it to "*_*" gives that job to the is_dir() filter instead.
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp, {'1.0.0_0': {'name': 'Good', 'version': '1.0.0'}})
            (ext / '9.9.9_0.tmp').write_text('not a directory', encoding='utf-8')
            (ext / '$I30_junk').write_text('not a directory', encoding='utf-8')
            manifest, version = Chrome.load_extension_manifest(ext)
            self.assertEqual('Good', manifest['name'])
            self.assertEqual('1.0.0_0', version)

    def test_missing_manifest_returns_none_rather_than_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            ext = pathlib.Path(tmp, 'abcdefghijklmnopabcdefghijklmnop')
            (ext / '1.0.0_0').mkdir(parents=True)
            manifest, version = Chrome.load_extension_manifest(ext)
            self.assertIsNone(manifest)


class TestFileSystemOrphanedChildRecords(unittest.TestCase):
    """A CHILD_OF entry can name a file_id whose own record was deleted.

    Deleted file_id records are skipped when `backing_files` is built, so the lookup
    for such an entry used to raise KeyError and abort the entire File System parse.
    The node is still worth keeping -- its name and logical path are recoverable even
    though the backing-file metadata is not.
    """

    def test_the_lookup_is_guarded(self):
        import ast
        import inspect
        source = inspect.getsource(Chrome.get_file_system)
        tree = ast.parse(source.lstrip().replace('\n    ', '\n'))
        unguarded = []
        for node in ast.walk(tree):
            # backing_files[...] as a *load* is the unguarded form; .get() is fine.
            if (isinstance(node, ast.Subscript)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == 'backing_files'
                    and isinstance(node.ctx, ast.Load)):
                unguarded.append(node.lineno)
        self.assertEqual(
            [], unguarded,
            'backing_files must be read with .get(); a CHILD_OF entry pointing at a '
            f'deleted file_id would raise KeyError (lines {unguarded})')


if __name__ == '__main__':
    unittest.main()
