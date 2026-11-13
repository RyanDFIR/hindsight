"""Custom plugins are loaded from two known directories, not from all of sys.path.

Every directory on sys.path used to be searched for a "plugins" subfolder, and each
.py file in one was imported and run. That reached site-packages, where an unrelated
package can install a top-level "plugins" package, and everything on PYTHONPATH.
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import pyhindsight.plugins
from pyhindsight.plugins import (
    CUSTOM_MODULE_PREFIX,
    custom_plugin_dirs,
    find_custom_plugins,
    load_custom_plugin,
)

PACKAGE_DIR = os.path.realpath(os.path.dirname(pyhindsight.plugins.__file__))

PLUGIN_SOURCE = '''
friendlyName = "Example"
version = "20260101"
import {helper}


def plugin(session):
    return "ran"
'''


def write_plugin(directory, name, helper='os'):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, f'{name}.py'), 'w', encoding='utf-8') as f:
        f.write(PLUGIN_SOURCE.format(helper=helper))


class CustomPluginDirTests(unittest.TestCase):

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.program_dir = os.path.join(self.root, 'program')
        os.makedirs(self.program_dir)
        # As if Hindsight were started from a script in program_dir.
        patcher = mock.patch.object(sys, 'argv', [os.path.join(self.program_dir, 'hindsight.py')])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._forget_modules)

    @staticmethod
    def _forget_modules():
        for name in [name for name in sys.modules if name.startswith(CUSTOM_MODULE_PREFIX)]:
            del sys.modules[name]

    def test_only_the_package_directory_when_there_is_no_plugins_folder(self):
        self.assertEqual([PACKAGE_DIR], custom_plugin_dirs())

    def test_plugins_folder_beside_the_program_is_searched_first(self):
        beside = os.path.join(self.program_dir, 'plugins')
        os.makedirs(beside)
        self.assertEqual([beside, PACKAGE_DIR], custom_plugin_dirs())

    def test_packaged_build_uses_the_folder_beside_the_exe(self):
        exe_dir = os.path.join(self.root, 'exe')
        beside = os.path.join(exe_dir, 'plugins')
        os.makedirs(beside)
        with mock.patch.object(sys, 'frozen', True, create=True), \
                mock.patch.object(sys, 'executable', os.path.join(exe_dir, 'hindsight.exe')):
            self.assertEqual([beside, PACKAGE_DIR], custom_plugin_dirs())

    def test_plugins_folder_elsewhere_on_sys_path_is_ignored(self):
        # The old search would have imported this file.
        elsewhere = os.path.join(self.root, 'site-packages')
        write_plugin(os.path.join(elsewhere, 'plugins'), 'planted')
        with mock.patch.object(sys, 'path', [elsewhere] + sys.path):
            self.assertNotIn(os.path.join(elsewhere, 'plugins'), custom_plugin_dirs())
            self.assertNotIn('planted', [name for name, _ in find_custom_plugins()])

    def test_find_lists_plugin_files_without_importing_them(self):
        beside = os.path.join(self.program_dir, 'plugins')
        write_plugin(beside, 'mine')
        write_plugin(beside, '_private')
        write_plugin(beside, 'google_searches')  # a built-in's name
        with open(os.path.join(beside, 'notes.txt'), 'w') as f:
            f.write('not a plugin')

        found = find_custom_plugins()

        self.assertIn(('mine', beside), found)
        names = [name for name, _ in found]
        self.assertNotIn('_private', names)
        self.assertNotIn('google_searches', names)
        self.assertNotIn('notes', names)
        self.assertNotIn(CUSTOM_MODULE_PREFIX + 'mine', sys.modules)

    def test_built_in_plugins_are_not_listed_as_custom(self):
        self.assertEqual([], find_custom_plugins())

    def test_load_runs_the_file_it_was_given(self):
        beside = os.path.join(self.program_dir, 'plugins')
        write_plugin(beside, 'mine')
        module = load_custom_plugin('mine', beside)
        self.assertEqual('Example', module.friendlyName)
        self.assertEqual('ran', module.plugin(None))
        # Loaded once: the GUI lists a plugin and later runs it.
        self.assertIs(module, load_custom_plugin('mine', beside))

    def test_plugin_named_like_a_loaded_module_is_still_the_plugin(self):
        # __import__('json') returned the standard library's json, not the plugin.
        beside = os.path.join(self.program_dir, 'plugins')
        write_plugin(beside, 'json')
        module = load_custom_plugin('json', beside)
        self.assertEqual('Example', module.friendlyName)
        import json
        self.assertTrue(hasattr(json, 'loads'))

    def test_plugin_can_import_a_helper_beside_it_and_sys_path_is_restored(self):
        beside = os.path.join(self.program_dir, 'plugins')
        with open(os.path.join(self.root, 'unused'), 'w'):
            pass
        os.makedirs(beside)
        with open(os.path.join(beside, '_hindsight_test_helper.py'), 'w') as f:
            f.write('VALUE = 1\n')
        self.addCleanup(sys.modules.pop, '_hindsight_test_helper', None)
        write_plugin(beside, 'mine', helper='_hindsight_test_helper')
        before = list(sys.path)
        load_custom_plugin('mine', beside)
        self.assertEqual(before, sys.path)


if __name__ == '__main__':
    unittest.main()
