"""
Copyright 2024, CCL Forensics
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import dataclasses
import datetime
import math
import pathlib
import sqlite3
import enum
import re
import struct
import typing
import collections.abc as col_abc

from .common import KeySearch, is_keysearch_hit, make_sqlite_readonly_uri
from .structures import ArtifactLocation
from .download_common import Download, DownloadSource

__version__ = "0.7"
__description__ = "Module to access the chrom(e|ium) history database"
__contact__ = "Alex Caithness"

EPOCH = datetime.datetime(1601, 1, 1)


def parse_chromium_time(microseconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(microseconds=microseconds)


def encode_chromium_time(datetime_value: datetime.datetime) -> int:
    return math.floor((datetime_value - EPOCH).total_seconds() * 1000000)


class PageTransitionCoreEnum(enum.IntEnum):
    # chrome/common/page_transition_types.h
    link = 0
    typed = 1
    auto_bookmark = 2
    auto_subframe = 3
    manual_subframe = 4
    generated = 5
    start_page = 6
    form_submit = 7
    reload = 8
    keyword = 9
    keyword_generated = 10


class PageTransitionQualifierEnum(enum.IntFlag):
    blocked = 0x00800000
    forward_back = 0x01000000
    from_address_bar = 0x02000000
    home_page = 0x04000000
    from_api = 0x08000000
    chain_start = 0x10000000
    chain_end = 0x20000000
    client_redirect = 0x40000000
    server_redirect = 0x80000000


@dataclasses.dataclass(frozen=True)
class PageTransition:
    core: PageTransitionCoreEnum
    qualifier: PageTransitionQualifierEnum

    @classmethod
    def from_int(cls, val):
        # database stores values signed, python needs unsigned
        if val < 0:
            val, = struct.unpack(">I", struct.pack(">i", val))

        core = PageTransitionCoreEnum(val & 0xff)
        qual = PageTransitionQualifierEnum(val & 0xffffff00)

        return cls(core, qual)


@dataclasses.dataclass(frozen=True)
class HistoryRecord:
    _owner: "HistoryDatabase" = dataclasses.field(repr=False)
    file: str
    rec_id: int
    url: str
    title: str
    visit_time: datetime.datetime
    visit_duration: datetime.timedelta
    transition: PageTransition
    from_visit_id: int
    opener_visit_id: int

    @property
    def record_location(self) -> ArtifactLocation:
        return ArtifactLocation(self.file, None, f"SQLite Rowid: {self.rec_id}")

    @property
    def has_parent(self) -> bool:
        return self.from_visit_id != 0 or self.opener_visit_id != 0

    @property
    def parent_visit_id(self) -> int:
        return self.opener_visit_id or self.from_visit_id

    def get_parent(self) -> typing.Optional["HistoryRecord"]:
        """
        Get the parent visit for this record (based on the from_visit field in the database),
        or None if there isn't one.
        """

        return self._owner.get_parent_of(self)

    def get_children(self) -> col_abc.Iterable["HistoryRecord"]:
        """
        Get the children visits for this record (based on their from_visit field in the database).
        """
        return self._owner.get_children_of(self)


class HistoryDatabase:
    _HISTORY_QUERY = """
    SELECT
      "visits"."id",
      "urls"."url",
      "urls"."title",
      "visits"."visit_time",
      "visits"."from_visit",
      "visits"."opener_visit",
      "visits"."transition",
      "visits"."visit_duration",
      CASE 
          WHEN "visits"."opener_visit" != 0 THEN "visits"."opener_visit"
          ELSE "visits"."from_visit"
      END "parent_id"
      
    FROM "visits"
      LEFT JOIN "urls" ON "visits"."url" = "urls"."id"
    """

    _HISTORY_LEGACY_QUERY = """
        SELECT
          "visits"."id",
          "urls"."url",
          "urls"."title",
          "visits"."visit_time",
          "visits"."from_visit",
          0 AS "opener_visit",
          "visits"."transition",
          "visits"."visit_duration",
          "visits"."from_visit" AS "parent_id"

        FROM "visits"
          LEFT JOIN "urls" ON "visits"."url" = "urls"."id"
        """

    _WHERE_URL_EQUALS_PREDICATE = """"urls"."url" = ?"""

    _WHERE_URL_REGEX_PREDICATE = """"urls"."url" REGEXP ?"""

    _WHERE_URL_IN_PREDICATE = """"urls"."url" IN ({parameter_question_marks})"""

    _WHERE_VISIT_TIME_EARLIEST_PREDICATE = """"visits"."visit_time" >= ?"""

    _WHERE_VISIT_TIME_LATEST_PREDICATE = """"visits"."visit_time" <= ?"""

    _WHERE_VISIT_ID_EQUALS_PREDICATE = """"visits"."id" = ?"""

    #_WHERE_FROM_VISIT_EQUALS_PREDICATE = """"visits"."from_visit" = ?"""

    #_WHERE_OPENER_VISIT_EQUALS_PREDICATE = """"visits"."opener_visit" = ?"""

    _WHERE_PARENT_ID_EQUALS_PREDICATE = """"parent_id" = ?"""

    _DOWNLOADS_QUERY = """
    SELECT 
      "downloads"."id",
      "downloads"."guid",
      "downloads"."current_path",
      "downloads"."target_path",
      "downloads"."start_time",
      "downloads"."received_bytes",
      "downloads"."total_bytes",
      "downloads"."state",
      "downloads"."danger_type",
      "downloads"."interrupt_reason",
      "downloads"."hash",
      "downloads"."end_time",
      "downloads"."opened",
      "downloads"."last_access_time",
      "downloads"."transient",
      "downloads"."referrer",
      "downloads"."site_url",
      --"downloads"."embedder_download_data",
      "downloads"."tab_url",
      "downloads"."tab_referrer_url",
      "downloads"."http_method",
      "downloads"."mime_type",
      "downloads"."original_mime_type"
    FROM "downloads";
    """

    _DOWNLOADS_URL_CHAINS_QUEREY = """
    SELECT "downloads_url_chains"."id",
      "downloads_url_chains"."chain_index",
      "downloads_url_chains"."url"
    FROM "downloads_url_chains"
    WHERE "downloads_url_chains"."id" = ?
    ORDER BY "downloads_url_chains"."chain_index";
    """

    def __init__(self, db_path: pathlib.Path):
        self._db_path = db_path
        self._conn = sqlite3.connect(make_sqlite_readonly_uri(db_path), uri=True)
        self._conn.row_factory = sqlite3.Row
        self._conn.create_function("regexp", 2, lambda y, x: 1 if re.search(y, x) is not None else 0)
        self._is_modern = self._check_is_modern_db()

    def _check_is_modern_db(self) -> bool:
        cur = self._conn.cursor()
        cur.execute("PRAGMA table_info(\"visits\");")
        modern = "opener_visit" in {x["name"] for x in cur}
        cur.close()
        return modern

    def _row_to_record(self, row: sqlite3.Row) -> HistoryRecord:
        return HistoryRecord(
            self,
            str(self._db_path),
            row["id"],
            row["url"],
            row["title"],
            parse_chromium_time(row["visit_time"]),
            datetime.timedelta(microseconds=row["visit_duration"]),
            PageTransition.from_int(row["transition"]),
            row["from_visit"],
            row["opener_visit"]
        )

    def get_parent_of(self, record: HistoryRecord) -> typing.Optional[HistoryRecord]:
        if record.from_visit_id == 0 and record.opener_visit_id == 0:
            return None

        parent_id = record.opener_visit_id if record.opener_visit_id != 0 else record.from_visit_id

        query = HistoryDatabase._HISTORY_QUERY if self._is_modern else HistoryDatabase._HISTORY_LEGACY_QUERY
        query += f" WHERE {HistoryDatabase._WHERE_VISIT_ID_EQUALS_PREDICATE};"
        cur = self._conn.cursor()
        cur.execute(query, (parent_id,))
        row = cur.fetchone()
        cur.close()
        if row:
            return self._row_to_record(row)

    def get_children_of(self, record: HistoryRecord) -> col_abc.Iterable[HistoryRecord]:
        query = HistoryDatabase._HISTORY_QUERY if self._is_modern else HistoryDatabase._HISTORY_LEGACY_QUERY
        predicate = HistoryDatabase._WHERE_PARENT_ID_EQUALS_PREDICATE
        query += f" WHERE {predicate};"
        cur = self._conn.cursor()
        cur.execute(query, (record.rec_id,))
        for row in cur:
            yield self._row_to_record(row)

        cur.close()

    def get_record_with_id(self, visit_id: int) -> typing.Optional[HistoryRecord]:
        query = HistoryDatabase._HISTORY_QUERY if self._is_modern else HistoryDatabase._HISTORY_LEGACY_QUERY
        query += f" WHERE {HistoryDatabase._WHERE_VISIT_ID_EQUALS_PREDICATE};"
        cur = self._conn.cursor()
        cur.execute(query, (visit_id,))
        row = cur.fetchone()
        cur.close()
        if row:
            return self._row_to_record(row)

    def iter_history_records(
            self, url: typing.Optional[KeySearch], *,
            earliest: typing.Optional[datetime.datetime]=None, latest: typing.Optional[datetime.datetime]=None
    ) -> col_abc.Iterable[HistoryRecord]:

        predicates = []
        parameters = []

        if url is None:
            pass  # no predicate
        elif isinstance(url, str):
            predicates.append(HistoryDatabase._WHERE_URL_EQUALS_PREDICATE)
            parameters.append(url)
        elif isinstance(url, re.Pattern):
            predicates.append(HistoryDatabase._WHERE_URL_REGEX_PREDICATE)
            parameters.append(url.pattern)
        elif isinstance(url, col_abc.Collection):
            predicates.append(
                HistoryDatabase._WHERE_URL_IN_PREDICATE.format(
                    parameter_question_marks=",".join("?" for _ in range(len(url)))))
            parameters.extend(url)
        elif isinstance(url, col_abc.Callable):
            pass  # we have to call this function across every
        else:
            raise TypeError(f"Unexpected type: {type(url)} (expects: {KeySearch})")

        if earliest is not None:
            predicates.append(HistoryDatabase._WHERE_VISIT_TIME_EARLIEST_PREDICATE)
            parameters.append(encode_chromium_time(earliest))

        if latest is not None:
            predicates.append(HistoryDatabase._WHERE_VISIT_TIME_LATEST_PREDICATE)
            parameters.append(encode_chromium_time(latest))

        query = HistoryDatabase._HISTORY_QUERY if self._is_modern else HistoryDatabase._HISTORY_LEGACY_QUERY
        if predicates:
            query += f" WHERE {' AND '.join(predicates)}"

        query += ";"
        cur = self._conn.cursor()
        for row in cur.execute(query, parameters):
            if not isinstance(url, col_abc.Callable) or url(row["url"]):
                yield self._row_to_record(row)

        cur.close()

    def iter_downloads(
            self,
            download_url: typing.Optional[KeySearch]=None,
            tab_url: typing.Optional[KeySearch]=None) -> col_abc.Iterable[Download]:
        downloads_cur = self._conn.cursor()
        chain_cur = self._conn.cursor()

        downloads_cur.execute(HistoryDatabase._DOWNLOADS_QUERY)

        for download in downloads_cur:
            chain_cur.execute(HistoryDatabase._DOWNLOADS_URL_CHAINS_QUEREY, (download["id"],))
            chain = tuple(x["url"] for x in chain_cur)

            if download_url is not None and not any(is_keysearch_hit(download_url, x) for x in chain):
                continue

            if (tab_url is not None and
                    not is_keysearch_hit(tab_url, download["tab_url"]) and
                    not is_keysearch_hit(tab_url, download["tab_referrer_url"])):
                continue

            yield Download(
                str(self._db_path),
                DownloadSource.history_db,
                download["id"],
                download["guid"],
                download["hash"].hex(),
                chain,
                download["tab_url"],
                download["tab_referrer_url"],
                download["target_path"],
                download["mime_type"],
                download["original_mime_type"],
                download["total_bytes"],
                parse_chromium_time(download["start_time"]),
                parse_chromium_time(download["end_time"])
            )

        downloads_cur.close()
        chain_cur.close()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

