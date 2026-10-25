import re
import sys
import typing
import collections.abc as col_abc
import pathlib
import urllib.parse

KeySearch = typing.Union[str, re.Pattern, col_abc.Collection[str], col_abc.Callable[[str], bool]]


# derived from the version in aleapp credit:
def make_sqlite_readonly_uri(db_path: pathlib.Path):
    if sys.platform == "win32":
        path_string = str(db_path.absolute())
        if path_string.startswith("\\\\?\\UNC\\"):  # UNC long path
            remainder = path_string[4:]
        elif path_string.startswith("\\\\?\\"):     # normal long path
            remainder = path_string[4:]
        elif path_string.startswith("\\\\"):        # UNC path
            remainder = r"\UNC" + path_string[1:]
        else:                                       # normal path
            remainder = path_string
            # Encode special URI characters (e.g. '#', space) so SQLite doesn't
            # treat them as fragment delimiters or query separators. Keep ':'
            # and '/' safe so the drive letter and forward slashes are preserved.
        return "file:" + "%5C%5C%3F%5C" + urllib.parse.quote(remainder, safe=":/") + "?mode=ro"
    return db_path.as_uri() + "?mode=ro"


def is_keysearch_hit(search: KeySearch, value: str):
    if isinstance(search, str):
        return value == search
    elif isinstance(search, re.Pattern):
        return search.search(value) is not None
    elif isinstance(search, col_abc.Collection):
        return value in set(search)
    elif isinstance(search, col_abc.Callable):
        return search(value)
    else:
        raise TypeError(f"Unexpected type: {type(search)} (expects: {KeySearch})")