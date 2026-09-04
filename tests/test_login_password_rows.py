"""A saved credential must be reported whether or not its value can be read.

The password row used to be emitted only when Windows decryption was available, and the
gate wrapped the `append` as well as the decryption, so off Windows the row did not exist
at all. That a credential was saved for a site is a finding in its own right, and it was
disappearing based on which OS the examiner happened to use. See issue #310.

Cookies and autofill already keep the row and mark the value `<encrypted>`; these assert
that logins now follow the same convention rather than a new one.
"""

import datetime
import os
import sqlite3
import tempfile
import unittest

from pyhindsight.browsers.chrome import Chrome

UTC = datetime.timezone.utc

# A plausible Chrome timestamp (Webkit microseconds) and an encrypted-looking blob. The
# 'v10' prefix is what Chromium writes ahead of an AES-encrypted value.
CREATED = 13300000000000000
ENCRYPTED_BLOB = b'v10' + bytes(range(32))

# available_decrypts['windows'] is only ever 1 because this import succeeded, and
# Chrome.__init__ re-imports it on that flag, so the two cannot be separated in a test.
try:
    import win32crypt  # noqa: F401
    WIN32CRYPT_AVAILABLE = True
except ImportError:
    WIN32CRYPT_AVAILABLE = False


def _make_login_db(directory):
    path = os.path.join(directory, 'Login Data')
    con = sqlite3.connect(path)
    con.execute('''CREATE TABLE logins (
                     origin_url TEXT, action_url TEXT, username_element TEXT,
                     username_value TEXT, password_element TEXT, password_value BLOB,
                     date_created INTEGER, date_last_used INTEGER,
                     blacklisted_by_user INTEGER, times_used INTEGER)''')
    con.execute('INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?,?)',
                ('https://example.test/login', 'https://example.test/auth',
                 'username', 'bob', 'password', ENCRYPTED_BLOB,
                 CREATED, 0, 0, 3))
    con.commit()
    con.close()
    return path


def _parse(directory, windows_decrypt):
    browser = Chrome(directory, version=[78], timezone=UTC, no_copy=True,
                     available_decrypts={'windows': windows_decrypt, 'mac': 0, 'linux': 0})
    browser.get_login_data(directory, 'Login Data', [78])
    return browser.parsed_artifacts


class TestPasswordRowIsAlwaysEmitted(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        _make_login_db(self.tmp.name)

    def _password_rows(self, windows_decrypt):
        return [item for item in _parse(self.tmp.name, windows_decrypt)
                if getattr(item, 'row_type', None) == 'login (password)']

    def test_a_password_row_exists_without_windows_decryption(self):
        # The regression: this list used to be empty on Linux and macOS.
        rows = self._password_rows(windows_decrypt=0)
        self.assertEqual(1, len(rows), 'saved credential not reported at all')

    def test_the_unreadable_value_is_marked_rather_than_omitted(self):
        row = self._password_rows(windows_decrypt=0)[0]
        self.assertEqual('<encrypted>', row.value)

    def test_the_row_still_carries_its_context(self):
        # The value is the part that cannot be recovered; everything an examiner needs
        # to say a credential existed is in the clear and must survive.
        row = self._password_rows(windows_decrypt=0)[0]
        self.assertEqual('https://example.test/login', row.url)
        self.assertEqual('password', row.name)
        self.assertEqual(3, row.count)
        self.assertIsNotNone(row.timestamp)

    def test_the_row_count_is_the_same_with_decryption_available(self):
        # The property itself, and the reason the corpus baselines differed by platform:
        # same profile, same rows, different totals. Only runs where Windows decryption
        # genuinely exists: available_decrypts['windows'] is 1 only because win32crypt
        # imported, so asserting it on Linux would be testing a state that cannot occur
        # (and Chrome.__init__ imports the module on that flag, so it raises).
        if not WIN32CRYPT_AVAILABLE:
            self.skipTest('win32crypt not importable, so this state cannot arise here')
        self.assertEqual(len(_parse(self.tmp.name, 1)), len(_parse(self.tmp.name, 0)),
                         'row count still depends on Windows decryption being available')


class TestNeverSaveEntriesAreUnaffected(unittest.TestCase):
    """A "never save" entry has no password and must not gain a password row."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = os.path.join(self.tmp.name, 'Login Data')
        con = sqlite3.connect(path)
        con.execute('''CREATE TABLE logins (
                         origin_url TEXT, action_url TEXT, username_element TEXT,
                         username_value TEXT, password_element TEXT, password_value BLOB,
                         date_created INTEGER, date_last_used INTEGER,
                         blacklisted_by_user INTEGER, times_used INTEGER)''')
        con.execute('INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?,?)',
                    ('https://example.test/login', '', '', '', '', None,
                     CREATED, 0, 1, 0))
        con.commit()
        con.close()

    def test_a_null_password_produces_no_password_row(self):
        rows = [item for item in _parse(self.tmp.name, 0)
                if getattr(item, 'row_type', None) == 'login (password)']
        self.assertEqual([], rows)

    def test_the_never_save_row_is_still_reported(self):
        rows = [item for item in _parse(self.tmp.name, 0)
                if getattr(item, 'row_type', None) == 'login (never save)']
        self.assertEqual(1, len(rows))


if __name__ == '__main__':
    unittest.main()
