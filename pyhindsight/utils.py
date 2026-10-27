import datetime
import functools
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import struct
import sys
import zoneinfo
from pyhindsight import __version__

log = logging.getLogger(__name__)

# Seconds between the Windows/Webkit epoch (1601-01-01) and the Unix epoch.
WEBKIT_EPOCH_OFFSET_SECONDS = 11644473600

WEBKIT_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC)
UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)

# Above this, a Webkit microsecond value is past datetime.max even after the epoch
# offset is applied, so there is no date to convert it to and it gets clamped.
#
# The bound is deliberately the *Webkit-adjusted* limit rather than the raw
# epoch-microsecond one ((253402300800 + 11644473600) * 1e6, not 253402300800 * 1e6).
# Those two differ by exactly the epoch offset, and values in that gap are unrepresentable
# only if the integer is read as microseconds since 1970 -- read as Webkit microseconds,
# which is what Chrome actually writes and what the conversion below applies, they are
# ordinary (if absurd) dates in the years 9631-9999. Using the lower bound clamped those
# away before the Webkit branch ever saw them.
MAX_CONVERTIBLE_WEBKIT_MICROSECONDS = 265046774400000000


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def text_factory(row_data):
    try:
        return row_data.decode('utf-8')
    except UnicodeDecodeError:
        return row_data


def sha256_file(file_path, chunk_size=1024 * 1024):
    """Return the SHA-256 of a file as hex, or None if it cannot be read.

    Read in chunks so a large file does not have to fit in memory. A hash is
    supplementary to the record it annotates, so an unreadable file returns None
    rather than raising and costing the caller the whole artifact.
    """
    digest = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                digest.update(chunk)
    except OSError as e:
        log.debug(f' - Could not hash {file_path}: {e}')
        return None
    return digest.hexdigest()


def long_path(path):
    """`path` in the form Windows will open past MAX_PATH; unchanged elsewhere.

    Unless long paths are enabled machine-wide (they are off by default), Windows
    refuses any path of 260 characters or more, and a browser profile reaches that
    easily: Service Worker CacheStorage files sit five directories below the profile,
    so evidence kept at an ordinary depth is enough. The extended-length form,
    \\\\?\\C:\\..., is exempt. It has to be absolute and use backslashes, which
    abspath() provides; Windows does no further normalization on it.
    """
    if os.name != 'nt' or not path:
        return path
    path = os.fspath(path)
    if path.startswith('\\\\?\\'):
        return path
    path = os.path.abspath(path)
    if path.startswith('\\\\.\\'):
        # A device path (\\.\C:\..., or \\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\...
        # for a shadow copy) only needs its prefix changed. Taken for UNC, it would name a
        # server called ".", and nothing under it would open.
        return '\\\\?\\' + path[4:]
    if path.startswith('\\\\'):
        return '\\\\?\\UNC\\' + path[2:]  # \\server\share\... -> \\?\UNC\server\share\...
    return '\\\\?\\' + path


def short_path(path):
    """The ordinary form of an extended-length path (see long_path); others unchanged.

    Only a drive or UNC path has an ordinary form. One such as \\\\?\\GLOBALROOT\\... or
    \\\\?\\Volume{...}\\... has none, and is left as it is.
    """
    if isinstance(path, str):
        if path.startswith('\\\\?\\UNC\\'):
            return '\\\\' + path[8:]
        drive = path[4:5]
        if (path.startswith('\\\\?\\') and drive.isascii() and drive.isalpha()
                and path[5:6] == ':' and path[6:7] in ('', '\\')):
            return path[4:]
    return path


def relpath(path, start):
    """os.path.relpath() for two paths that may differ in being extended-length.

    Windows treats \\\\?\\C: and C: as different drives, so relpath() raises when only
    one of the two went through long_path(), as when a caller hands a parser its own
    path rather than the browser's.
    """
    return os.path.relpath(long_path(path), long_path(start))


def note_open_failure(browser, database_path, database_name, reason):
    """Remember why a database could not be opened, for the caller to report.

    The parser that asked for the database usually turns a failure into `return None`,
    which reaches the driver as "this artifact could not be read" -- true, but with the
    reason left behind in an unrelated log line. Stashing it here lets the artifact's own
    summary line name the file and the reason, so the log can be read top-down.
    """
    try:
        browser.last_open_failure = (
            short_path(os.path.join(database_path, database_name)), str(reason))
    except AttributeError:
        pass


def open_sqlite_db(chrome, database_path, database_name):
    log.info(f' - Reading from {database_name} in {database_path}')

    if not os.path.exists(os.path.join(database_path, database_name)):
        log.info(f'   - Failed; {database_name} does not exist in {database_path}')
        note_open_failure(chrome, database_path, database_name, 'file does not exist')
        return False

    if chrome.no_copy:
        db_path_to_open = os.path.join(database_path, database_name)

    else:
        try:
            # Copy database and any WAL/SHM files to this browser's own temp directory
            db_path_to_open = os.path.join(chrome.copy_dir(), database_name)
            for suffix in ['', '-wal', '-shm']:
                src = os.path.join(database_path, database_name + suffix)
                if os.path.exists(src):
                    shutil.copyfile(src, db_path_to_open + suffix)
        except Exception as e:
            log.error(f' - Error copying {database_name}: {e}')
            note_open_failure(chrome, database_path, database_name, f'could not be copied ({e})')
            return None

    db_conn = None
    try:
        # Connect to copied database
        db_conn = sqlite3.connect(db_path_to_open)

        # Use a dictionary cursor
        db_conn.row_factory = dict_factory
        db_conn.text_factory = text_factory

        # Execute a test query to make sure the database is not corrupted
        db_conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")

    except Exception as e:
        log.error(f' - Error opening {database_name}: {e}')
        note_open_failure(chrome, database_path, database_name, str(e))
        if db_conn is not None:
            db_conn.close()
        return None

    return db_conn


def format_plugin_output(name, version, items):
    width = 80
    left_side = width * 0.55
    full_plugin_name = "{} (v{})".format(name, version)
    pretty_name = f"{full_plugin_name:>{int(left_side)}}:{' '.join(['-', items, '-']):^{(width - int(left_side) - 2)}}"
    return pretty_name


def format_meta_output(name, content):
    left_side = 17
    pretty_name = "{name:>{left_width}}: {content}" \
        .format(name=name, left_width=int(left_side), content=content)
    return pretty_name


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return str(obj, encoding='utf-8', errors='replace')
        else:
            return obj.__dict__


def to_datetime(timestamp, timezone=None, quiet=False, none_if_unset=False,
                none_on_failure=False):
    """Convert a variety of timestamp formats to a datetime object.

    If none_if_unset is True, the common Chrome "unset" sentinels -- 0 and the
    all-ones value (0xffffffffffffffff / UINT64_MAX) -- return None instead of being
    converted to 1601/1970 or datetime.max. Off by default to preserve existing behavior
    (callers and the Timeline rely on 0 -> epoch, and sorting requires a real datetime).

    If none_on_failure is True, a value that cannot be converted at all returns None
    rather than the epoch. The epoch is a real date that browsers do record, so using it
    as the "could not parse" marker makes a genuine 1970 timestamp indistinguishable from
    a corrupt one. Callers that opt in should keep the raw value themselves -- None says
    only that no time could be read, not what was actually stored.
    """
    def unconvertible():
        return None if none_on_failure else datetime.datetime.fromtimestamp(0, datetime.UTC)

    try:
        if none_if_unset:
            if timestamp is None:
                return None
            try:
                if int(timestamp) in (0, 0xffffffffffffffff):
                    return None
            except (TypeError, ValueError):
                pass  # not an integer-like value (e.g. a datetime or unparseable string)

        if isinstance(timestamp, datetime.datetime):
            if timezone is not None:
                return timestamp.astimezone(timezone)
            return timestamp

        # Keep an integer as an integer. A WebKit microsecond value of today's size has
        # more digits than a double holds (float(13363303391354559) is ...560), and
        # dividing down to float seconds loses more, so a float conversion lands a
        # microsecond or two off the stored value. A float input (some Preferences values
        # are fractional seconds) has no more precision to keep and is used as-is.
        value = None
        if isinstance(timestamp, (int, str, bytes)):
            try:
                value = int(timestamp)
            except ValueError:
                pass  # e.g. '1.5'; falls back to the float below

        try:
            timestamp = float(timestamp)
        except Exception as e:
            if not quiet:
                log.warning(f'Exception parsing {timestamp} to datetime: {e}')
            return unconvertible()
        if value is None:
            value = timestamp

        # The sub-second units below are added to their epoch as a timedelta, which takes
        # an int exactly (and rounds a float to the nearest microsecond), rather than
        # divided down to float seconds first.

        # Very big Webkit microseconds (18 digits), most often cookie expiry dates.
        if timestamp >= MAX_CONVERTIBLE_WEBKIT_MICROSECONDS and not quiet:
            new_timestamp = datetime.datetime.max
            log.warning(f'Timestamp value {timestamp} is too large to convert; replaced with {datetime.datetime.max}')

        # Webkit microseconds (17 digits)
        elif timestamp > 12000000000000000:  # ts > 1981
            new_timestamp = WEBKIT_EPOCH + datetime.timedelta(microseconds=value)

        # Epoch microseconds (16 digits)
        elif 2500000000000000 > timestamp > 1280000000000000:  # 2049 > ts > 2010
            new_timestamp = UNIX_EPOCH + datetime.timedelta(microseconds=value)

        # Epoch milliseconds (13 digits)
        elif 2500000000000 > timestamp > 1280000000000:  # 2049 > ts > 2010
            new_timestamp = UNIX_EPOCH + datetime.timedelta(milliseconds=value)

        # Webkit milliseconds (14 digits)
        elif 15000000000000 > timestamp > 12906777600000:  # 2076 > ts > 2009
            new_timestamp = WEBKIT_EPOCH + datetime.timedelta(milliseconds=value)

        # Webkit seconds (11 digits)
        elif 15000000000 > timestamp >= 12900000000:  # 2076 > ts > 2009
            new_timestamp = datetime.datetime.fromtimestamp(timestamp - 11644473600, datetime.UTC)

        # Epoch seconds (10 digits typically, but could be less)
        else:
            try:
                new_timestamp = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
            except OSError as e:
                log.warning(f'Exception parsing {timestamp} to datetime: {e}; '
                            f'common issue is value is too big for the OS to convert it')
                return unconvertible()

        if timezone is not None:
            try:
                return new_timestamp.replace(tzinfo=datetime.UTC).astimezone(timezone)
            except NameError:
                return new_timestamp
        else:
            return new_timestamp
    except Exception as e:
        if not quiet:
            log.warning(f'Exception parsing {timestamp} to datetime: {e}')
        return unconvertible()


def decode_page_transition(raw):
    """Decode a Chrome page transition integer into a human-readable string.

    Args:
        raw: Integer transition value (core type in lower 8 bits, qualifiers in upper bits).

    Returns:
        String like 'typed; From Address Bar; ' or None if raw is None.
    """
    if raw is None:
        return None

    # If the transition has already been translated to a string, just use that
    if isinstance(raw, str):
        return raw

    # Source: https://source.chromium.org/chromium/chromium/src/+/main:ui/base/page_transition_types.h
    transition_friendly = {
        0: 'link',                 # User got to this page by clicking a link on another page.
        1: 'typed',                # User got this page by typing the URL in the URL bar.  This should not be
                                   #  used for cases where the user selected a choice that didn't look at all
                                   #  like a URL; see GENERATED below.
                                   # We also use this for other 'explicit' navigation actions.
        2: 'auto bookmark',        # User got to this page through a suggestion in the UI, for example
                                   #  through the destinations page.
        3: 'auto subframe',        # This is a subframe navigation. This is any content that is automatically
                                   #  loaded in a non-toplevel frame. For example, if a page consists of
                                   #  several frames containing ads, those ad URLs will have this transition
                                   #  type. The user may not even realize the content in these pages is a
                                   #  separate frame, so may not care about the URL (see MANUAL below).
        4: 'manual subframe',      # For subframe navigations that are explicitly requested by the user and
                                   #  generate new navigation entries in the back/forward list. These are
                                   #  probably more important than frames that were automatically loaded in
                                   #  the background because the user probably cares about the fact that this
                                   #  link was loaded.
        5: 'generated',            # User got to this page by typing in the URL bar and selecting an entry
                                   #  that did not look like a URL.  For example, a match might have the URL
                                   #  of a Google search result page, but appear like 'Search Google for ...'.
                                   #  These are not quite the same as TYPED navigations because the user
                                   #  didn't type or see the destination URL.
                                   #  See also KEYWORD.
        6: 'start page',           # This is a toplevel navigation. This is any content that is automatically
                                   #  loaded in a toplevel frame.  For example, opening a tab to show the ASH
                                   #  screen saver, opening the devtools window, opening the NTP after the safe
                                   #  browsing warning, opening web-based dialog boxes are examples of
                                   #  AUTO_TOPLEVEL navigations.
        7: 'form submit',          # The user filled out values in a form and submitted it. NOTE that in
                                   #  some situations submitting a form does not result in this transition
                                   #  type. This can happen if the form uses script to submit the contents.
        8: 'reload',               # The user 'reloaded' the page, either by hitting the reload button or by
                                   #  hitting enter in the address bar.  NOTE: This is distinct from the
                                   #  concept of whether a particular load uses 'reload semantics' (i.e.
                                   #  bypasses cached data).  For this reason, lots of code needs to pass
                                   #  around the concept of whether a load should be treated as a 'reload'
                                   #  separately from their tracking of this transition type, which is mainly
                                   #  used for proper scoring for consumers who care about how frequently a
                                   #  user typed/visited a particular URL.
                                   #  SessionRestore and undo tab close use this transition type too.
        9: 'keyword',              # The url was generated from a replaceable keyword other than the default
                                   #  search provider. If the user types a keyword (which also applies to
                                   #  tab-to-search) in the omnibox this qualifier is applied to the transition
                                   #  type of the generated url. TemplateURLModel then may generate an
                                   #  additional visit with a transition type of KEYWORD_GENERATED against the
                                   #  url 'http://' + keyword. For example, if you do a tab-to-search against
                                   #  wikipedia the generated url has a transition qualifer of KEYWORD, and
                                   #  TemplateURLModel generates a visit for 'wikipedia.org' with a transition
                                   #  type of KEYWORD_GENERATED.
        10: 'keyword generated'    # Corresponds to a visit generated for a keyword. See description of
                                   #  KEYWORD for more details.
    }

    qualifiers_friendly = {
        0x00800000: 'Blocked',                # A managed user attempted to visit a URL but was blocked.
        0x01000000: 'Forward or Back',        # User used the Forward or Back button to navigate among browsing
                                              #  history.
        0x02000000: 'From Address Bar',       # User used the address bar to trigger this navigation.
        0x04000000: 'Home Page',              # User is navigating to the home page.
        0x08000000: 'From API',               # The transition originated from an external application; the
                                              #  exact definition of this is embedder dependent.
        0x10000000: 'Navigation Chain Start', # The beginning of a navigation chain.
        0x20000000: 'Navigation Chain End',   # The last transition in a redirect chain.
        0x40000000: 'Client Redirect',        # Redirects caused by JavaScript or a meta refresh tag on the page
        0x80000000: 'Server Redirect'         # Redirects sent from the server by HTTP headers. It might be nice
                                              #  to break this out into 2 types in the future, permanent or
                                              #  temporary, if we can get that information from WebKit.
    }

    core_mask = 0xff
    code = raw & core_mask

    result = None
    if code in list(transition_friendly.keys()):
        result = transition_friendly[code] + '; '

    for qualifier in qualifiers_friendly:
        if raw & qualifier == qualifier:
            if not result:
                result = ""
            result += qualifiers_friendly[qualifier] + '; '

    return result


@functools.lru_cache(maxsize=None)
def _zone_names():
    """Map each IANA zone name, lowercased, to its proper spelling."""
    return {name.lower(): name for name in zoneinfo.available_timezones()}


def parse_timezone(value):
    """Return the tzinfo a timezone setting names, or None if it names none.

    Accepts an IANA name ("Asia/Kolkata", "America/New_York", "UTC") or a fixed offset
    from UTC ("UTC+5:30", "UTC+05:30", "+0530", "GMT-3"). IANA has fixed-offset zones
    only for whole hours (Etc/GMT-5, and nothing for +5:30), so without the second form
    the only way to ask for a half- or quarter-hour offset was to know a city in it.

    The sign means what it says: "GMT-3" is three hours behind UTC. IANA's Etc zones
    invert it ("Etc/GMT-3" is three hours ahead), and that form still goes to zoneinfo
    and keeps its IANA meaning.
    """
    if isinstance(value, datetime.tzinfo):
        return value
    if not isinstance(value, str) or not value.strip():
        return None

    match = re.fullmatch(r'(?:UTC|GMT)?([+-])(\d{1,2})(?::?(\d{2}))?',
                         value.replace(' ', ''), re.IGNORECASE)
    if match:
        sign, hours, minutes = match.groups()
        offset = datetime.timedelta(hours=int(hours), minutes=int(minutes or 0))
        # Offsets in use run from -12:00 to +14:00. Accept up to 14 hours either way;
        # anything past that is a typo.
        if int(minutes or 0) > 59 or offset > datetime.timedelta(hours=14):
            return None
        return datetime.timezone(-offset if sign == '-' else offset)

    # Names are matched without regard to case. Otherwise "asia/kolkata" works only on a
    # case-insensitive filesystem, and when it does the header says "asia/kolkata".
    name = value.strip()
    name = _zone_names().get(name.lower(), name)
    try:
        return zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):
        # OSError: on Windows, a name with a character no path can hold (a tab, say)
        # fails in the file lookup rather than as "not found".
        return None


def friendly_date(timestamp):
    if isinstance(timestamp, (str, int)):
        return to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    elif timestamp is None:
        return ''
    else:
        return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def describe_exception(e):
    """Name an exception for a failure reason: 'TypeName: message', or 'TypeName'.

    `str(e)` alone is blank for a bare `raise ValueError()`, which ccl does, and which
    would leave a reason reading 'unexpected exception ()'.
    """
    message = str(e)
    return f'{type(e).__name__}: {message}' if message else type(e).__name__


def iterate_leveldb_records(ldb_records, unparsed):
    """Yield the raw records of a RawLevelDb, one file at a time, reporting damage.

    ccl_leveldb skips damage in a .log file and reads on, as LevelDB does, listing
    each skip in the file's `damage`; a file with any is reported as an unparsed
    source after its readable records are yielded. Zero-filled space, which Chrome
    leaves at the end of a .log file after an abrupt shutdown, holds no records and
    is not damage. A table (.ldb) file can still raise, and raised from
    RawLevelDb.iterate_records_raw() that would end the run; instead the records
    read before it are kept, the file is reported, and the remaining files are read.
    """
    # Same order as RawLevelDb.iterate_records_raw(), which offers no per-file hook.
    for ldb_file in sorted(ldb_records._files, key=lambda f: f.file_no):
        try:
            yield from ldb_file
        except (ValueError, IndexError, struct.error) as e:
            unparsed.source(ldb_file.path, f'damaged LevelDB data ({describe_exception(e)})')
            continue
        damage = getattr(ldb_file, 'damage', None)
        if damage:
            skipped = sum(d.length for d in damage)
            unparsed.source(ldb_file.path, f'damaged LevelDB data ({skipped} bytes skipped in '
                                           f'{len(damage)} place{"s" if len(damage) > 1 else ""}; '
                                           f'first at offset {damage[0].offset}: {damage[0].reason})')


def get_ldb_records(ldb_path, unparsed, prefix=''):
    """Open a LevelDB at given path and return a list of records, optionally
    filtered by a prefix string. Key and value are kept as byte strings.

    A LevelDB that cannot be opened, and a file in it that is damaged, is reported to
    `unparsed` (a ParseFailures), so the artifact shows as partial rather than as a
    clean read of fewer records."""

    try:
        from pyhindsight.lib.ccl_chromium_reader.storage_formats import ccl_leveldb
    except ImportError:
        log.warning(f' - Failed to import ccl_leveldb; unable to process {ldb_path}')
        return []

    # The ldb key and value are both bytearrays, so the prefix must be too. We allow
    # passing the prefix into this function as a string for convenience.
    if isinstance(prefix, str):
        prefix = prefix.encode()

    try:
        db = ccl_leveldb.RawLevelDb(ldb_path)
    except Exception as e:
        unparsed.source(ldb_path, f'could not open as LevelDB ({e})')
        return []

    cleaned_records = []

    try:
        for record in iterate_leveldb_records(db, unparsed):
            cleaned_record = record.__dict__

            if record.file_type.name == 'Ldb':
                cleaned_record['key'] = record.key[:-8]

            if cleaned_record['key'].startswith(prefix):
                cleaned_record['key'] = cleaned_record['key'][len(prefix):]
                cleaned_record['state'] = cleaned_record['state'].name
                cleaned_record['file_type'] = cleaned_record['file_type'].name

                cleaned_records.append(cleaned_record)

    except Exception as e:
        unparsed.source(ldb_path, f'error reading LevelDB ({describe_exception(e)})')

    db.close()
    return cleaned_records


def read_varint(source):
    result = 0
    bytes_used = 0
    for read in source:
        result |= ((read & 0x7F) << (bytes_used * 7))
        bytes_used += 1
        if (read & 0x80) != 0x80:
            return result, bytes_used


def read_string(input_bytes, ptr):
    length = struct.unpack('<i', input_bytes[ptr:ptr+4])[0]
    ptr += 4
    end_ptr = ptr+length
    string_value = input_bytes[ptr:end_ptr]
    while end_ptr % 4 != 0:
        end_ptr += 1

    return string_value.decode(), end_ptr


def read_int32(input_bytes, ptr):
    value = struct.unpack('<i', input_bytes[ptr:ptr + 4])[0]
    return value, ptr + 4


def read_int64(input_bytes, ptr):
    value = struct.unpack('<Q', input_bytes[ptr:ptr + 8])[0]
    return value, ptr + 8


def _get_banner(triangle_char='▼'):
    return r'''
 _                 _             _     _
| |    {t}          | |    {t}      | |   | |
| |__  _ _ __   __| |___ _  __ _| |__ | |_
| '_ \| | '_ \ / _` / __| |/ _` | '_ \| __|
| | | | | | | | (_| \__ \ | (_| | | | | |_
|_| |_|_|_| |_|\__,_|___/_|\__, {t}_| |_|\__|
                            __/ |
     by ryan@hindsig.ht    |___/  v{v}
'''.format(t=triangle_char, v=__version__)


banner = _get_banner('▼')


def _supports_unicode():
    """Check if stdout encoding supports Unicode characters like ▼."""
    import sys
    try:
        encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
        '▼'.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def make_stdout_resilient():
    """Degrade unencodable characters on stdout instead of raising.

    A redirected stdout on Windows is cp1252, and the progress display renders from
    inside whatever parser is running, so a write that raises there is caught by that
    parser's `except` and reported as an unreadable artifact. That silently cost 954
    Session Storage records. Returns whether the stream was adjusted.
    """
    if not hasattr(sys.stdout, 'reconfigure'):
        return False
    try:
        sys.stdout.reconfigure(errors='backslashreplace')
    except (AttributeError, ValueError, OSError):
        return False
    return True


def get_rich_banner():
    """
    Returns a colored version of the banner using Rich Text.
    - Dim for outline characters
    - White for attribution text
    - Green for ▼ (or • if Unicode not supported) and . characters
    """
    import rich.text
    import re

    # Use cp1252-safe '•' if the console doesn't support Unicode
    triangle_char = '▼' if _supports_unicode() else '•'
    current_banner = _get_banner(triangle_char)

    banner_lines = current_banner.rstrip('\n').split('\n')[1:]  # [1:] to skip first empty line from triple quote
    colored_text = rich.text.Text()

    for line in banner_lines:
        if 'by ryan@' in line:
            # Special handling for attribution line
            match = re.match(r'^(\s*)(by ryan@hindsig)(\.)(ht)(\s+)(\|___/)(\s+)(v\S+)(\s*)$', line)
            if match:
                colored_text.append(match.group(1), style="dim")      # leading spaces
                colored_text.append(match.group(2), style="white")    # by ryan@hindsig
                colored_text.append(match.group(3), style="green")    # .
                colored_text.append(match.group(4), style="white")    # ht
                colored_text.append(match.group(5), style="dim")      # spaces
                colored_text.append(match.group(6), style="dim")      # |___/
                colored_text.append(match.group(7), style="dim")      # spaces
                colored_text.append(match.group(8), style="white")    # version
                colored_text.append(match.group(9), style="dim")      # trailing spaces
            else:
                colored_text.append(line, style="dim")
        else:
            for char in line:
                if char in ('▼', '•'):
                    colored_text.append(char, style="green")
                else:
                    colored_text.append(char, style="dim")
        colored_text.append('\n')

    return colored_text