"""Firefox cache resolution must depend on the evidence, not on the workstation.

Firefox keeps its cache outside the profile on Windows (`Roaming` profile, `Local`
cache) and on macOS (`Application Support` profile, `Caches` cache), so Hindsight
redirects the profile path to find it. Both redirects used to be written in one OS's
separator, so each only fired when the analyst's machine happened to match the target's:
a Windows profile silently lost its whole cache when parsed on Linux, and a macOS
profile lost it when parsed on Windows. The artifact was not reported as failed or
partial, it simply vanished. See issue #309.

The two halves are tested separately on purpose:

* `redirected_cache_paths` is pure string work, so every separator combination can be
  checked on every platform. This is where the cross-platform guarantee actually lives.
* `_resolve_cache_dir` touches the filesystem, so it can only be given paths the host
  can genuinely open. A backslash path means nothing on Linux, where it is one long
  filename rather than a path, and no amount of correct redirect logic would make it
  resolve. Asserting otherwise tests an arrangement that cannot occur.
"""

import os
import pathlib
import tempfile
import unittest

from pyhindsight.browsers.firefox import Firefox, redirected_cache_paths

BACKSLASH = chr(92)

WINDOWS_PROFILE = 'C:/Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default'
WINDOWS_CACHE = 'C:/Users/bob/AppData/Local/Mozilla/Firefox/Profiles/abc.default'
MAC_PROFILE = '/Users/bob/Library/Application Support/Firefox/Profiles/abc.default'
MAC_CACHE = '/Users/bob/Library/Caches/Firefox/Profiles/abc.default'


def _styles(forward_path):
    """The ways a real invocation can write one path.

    A path can legitimately mix separators: the input carries whatever the user typed
    and every level discovered below it is joined with os.sep, so the two styles meet
    at a point that moves with how deep the user pointed. A pattern insisting on one
    separator throughout passes the uniform cases and fails the mixed ones.
    """
    cases = {'all forward slashes': forward_path,
             'all backslashes': forward_path.replace('/', BACKSLASH)}
    for marker in ('/Mozilla/', '/Firefox/', '/Profiles/'):
        head, found, tail = forward_path.partition(marker)
        if found:
            cases[f'joined from {marker}'] = head + (found + tail).replace('/', BACKSLASH)
    return cases


class TestRedirectedCachePaths(unittest.TestCase):
    """The path rewriting, with no filesystem involved."""

    def _assert_redirects(self, profile, expected_cache):
        for label, written in _styles(profile).items():
            with self.subTest(path=label):
                produced = list(redirected_cache_paths(written))
                self.assertEqual(
                    1, len(produced),
                    f'expected exactly one redirect for {written}, got {produced}')
                # Compare separator-insensitively: which separator comes back is a
                # cosmetic property of the input, not part of the guarantee.
                self.assertEqual(expected_cache.replace('/', BACKSLASH),
                                 produced[0].replace('/', BACKSLASH))

    def test_a_windows_profile_redirects_to_local(self):
        self._assert_redirects(WINDOWS_PROFILE, WINDOWS_CACHE)

    def test_a_mac_profile_redirects_to_caches(self):
        self._assert_redirects(MAC_PROFILE, MAC_CACHE)

    def test_an_unrelated_profile_redirects_nowhere(self):
        self.assertEqual([], list(redirected_cache_paths('/home/bob/.mozilla/firefox/abc')))

    def test_the_match_is_case_insensitive(self):
        # Evidence paths arrive with whatever casing the image carried.
        produced = list(redirected_cache_paths(
            'C:/USERS/BOB/APPDATA/ROAMING/MOZILLA/FIREFOX/Profiles/abc.default'))
        self.assertEqual(1, len(produced))
        self.assertIn('Local', produced[0])


class TestResolveCacheDirOnDisk(unittest.TestCase):
    """End to end against real directories, using paths this host can open."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _tree(self, profile_parts, cache_parts):
        profile = pathlib.Path(self.tmp.name, *profile_parts)
        profile.mkdir(parents=True, exist_ok=True)
        entries = pathlib.Path(self.tmp.name, *cache_parts, 'cache2', 'entries')
        entries.mkdir(parents=True, exist_ok=True)
        return profile, entries

    def test_a_windows_layout_resolves(self):
        profile, entries = self._tree(
            ('Users', 'bob', 'AppData', 'Roaming', 'Mozilla', 'Firefox',
             'Profiles', 'abc.default'),
            ('Users', 'bob', 'AppData', 'Local', 'Mozilla', 'Firefox',
             'Profiles', 'abc.default'))
        for label, written in (('native', str(profile)),
                               ('forward slashes', str(profile).replace(os.sep, '/'))):
            with self.subTest(path=label):
                resolved = Firefox(written)._resolve_cache_dir()
                self.assertIsNotNone(resolved, f'cache not found for {written}')
                self.assertEqual(entries.resolve(), pathlib.Path(resolved).resolve())

    def test_a_mac_layout_resolves(self):
        profile, entries = self._tree(
            ('Users', 'bob', 'Library', 'Application Support', 'Firefox',
             'Profiles', 'abc.default'),
            ('Users', 'bob', 'Library', 'Caches', 'Firefox',
             'Profiles', 'abc.default'))
        for label, written in (('native', str(profile)),
                               ('forward slashes', str(profile).replace(os.sep, '/'))):
            with self.subTest(path=label):
                resolved = Firefox(written)._resolve_cache_dir()
                self.assertIsNotNone(resolved, f'cache not found for {written}')
                self.assertEqual(entries.resolve(), pathlib.Path(resolved).resolve())

    def test_a_cache_inside_the_profile_wins(self):
        profile, _outside = self._tree(
            ('Users', 'bob', 'AppData', 'Roaming', 'Mozilla', 'Firefox',
             'Profiles', 'abc.default'),
            ('Users', 'bob', 'AppData', 'Local', 'Mozilla', 'Firefox',
             'Profiles', 'abc.default'))
        inside = profile / 'cache2' / 'entries'
        inside.mkdir(parents=True)
        resolved = Firefox(str(profile))._resolve_cache_dir()
        self.assertEqual(inside.resolve(), pathlib.Path(resolved).resolve())

    def test_a_profile_with_no_cache_anywhere_resolves_to_nothing(self):
        profile = pathlib.Path(self.tmp.name, 'Users', 'bob', 'AppData', 'Roaming',
                               'Mozilla', 'Firefox', 'Profiles', 'abc.default')
        profile.mkdir(parents=True)
        self.assertIsNone(Firefox(str(profile))._resolve_cache_dir())


if __name__ == '__main__':
    unittest.main()
