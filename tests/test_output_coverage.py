import datetime
import json
import unittest

from pyhindsight.analysis import HindsightEncoder
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.browsers.firefox import Firefox
from pyhindsight.browsers.webbrowser import WebBrowser

UTC = datetime.timezone.utc
REF = datetime.datetime(2024, 1, 15, 12, 0, tzinfo=UTC)


def encode(item):
    return json.loads(json.dumps(item, cls=HindsightEncoder))


class TestNothingIsDroppedFromJsonl(unittest.TestCase):
    """No parsed record may serialize to null.

    A record the encoder returns None for is written as the literal `null` and then
    skipped, so it is absent from the output while the run still counts it -- the report
    is short by an amount nothing states. Service Worker data (five classes) and Firefox
    history/downloads were lost that way, on every profile, for a long time.
    """

    # Classes that had no branch at all, plus the two Firefox ones that fell through
    # because Chrome *defines* URLItem and DownloadItem while inheriting everything else.
    PREVIOUSLY_DROPPED = [
        (WebBrowser, 'ServiceWorkerItem', 'service worker (registration)'),
        (WebBrowser, 'ServiceWorkerResourceItem', 'service worker (resource)'),
        (WebBrowser, 'ServiceWorkerScriptItem', 'service worker (script body)'),
        (WebBrowser, 'ServiceWorkerCacheStorageItem', 'service worker (cache storage)'),
        (WebBrowser, 'ServiceWorkerUserDataItem', 'service worker (push subscription)'),
        (Firefox, 'URLItem', 'url'),
        (Firefox, 'DownloadItem', 'download'),
    ]

    def _bare(self, owner, name, row_type):
        cls = getattr(owner, name)
        obj = cls.__new__(cls)           # only the fields matter to the encoder
        obj.__dict__.update(profile='p', row_type=row_type, key='k', value='v',
                            state='Live', source_path='s')
        return obj

    def test_the_previously_dropped_classes_now_encode(self):
        for owner, name, row_type in self.PREVIOUSLY_DROPPED:
            with self.subTest(cls=f'{owner.__name__}.{name}'):
                obj = self._bare(owner, name, row_type)
                self.assertNotEqual('null', json.dumps(obj, cls=HindsightEncoder))

    def test_each_of_them_has_a_branch_of_its_own(self):
        # Not merely caught by the generic fallback -- their shape was chosen.
        for owner, name, row_type in self.PREVIOUSLY_DROPPED:
            with self.subTest(cls=f'{owner.__name__}.{name}'):
                data_type = encode(self._bare(owner, name, row_type))['data_type']
                self.assertFalse(
                    data_type.startswith('hindsight:'),
                    f'{name} is only handled by the generic fallback ({data_type})')

class TestFirefoxHistoryAndDownloads(unittest.TestCase):
    """Firefox URLItem and DownloadItem used to be dropped.

    Chrome *defines* only URLItem and DownloadItem; every other `Chrome.X` in the
    encoder chain resolves to the inherited `WebBrowser.X`, so Firefox's siblings
    matched by accident everywhere else -- and were dropped for exactly these two.
    """

    def test_a_firefox_url_record_encodes(self):
        item = Firefox.URLItem(
            profile='p', visit_id=1, url='https://example.com', title='Example',
            visit_time=REF, last_visit_time=REF, visit_count=2, typed_count=0,
            from_visit=None, transition=1, hidden=False, favicon_id=None)
        item.timestamp = REF
        item.row_type = 'url'
        encoded = encode(item)
        self.assertEqual('chrome:history:page_visited', encoded['data_type'])
        self.assertIn('example.com', encoded['message'])

    def test_a_firefox_download_encodes_without_byte_counts(self):
        # places.sqlite records no received/total bytes. base_encoder drops None, so a
        # branch that indexed those keys unconditionally raised KeyError.
        item = Firefox.DownloadItem(
            profile='p', download_id=1, url='https://example.com/f.zip',
            received_bytes=None, total_bytes=None, state=None,
            full_path='C:/Users/t/Downloads/f.zip')
        item.timestamp = REF
        item.row_type = 'download'
        encoded = encode(item)
        self.assertEqual('chrome:history:file_downloaded', encoded['data_type'])
        self.assertIn('f.zip', encoded['message'])
        self.assertNotIn('bytes', encoded['message'])


class TestServiceWorkerRecords(unittest.TestCase):
    """All five Service Worker classes had no branch at all."""

    def _item(self, cls_name, **fields):
        cls = getattr(WebBrowser, cls_name)
        obj = cls.__new__(cls)
        obj.__dict__.update(profile='p', key='k', value='v', state='Live',
                            source_path='s', **fields)
        return obj

    def test_registration_uses_its_own_timestamp(self):
        # These carry their time in a field of their own, not in `timestamp`, so
        # without promotion every one of them lands at the epoch.
        encoded = encode(self._item(
            'ServiceWorkerItem', row_type='service worker (registration)',
            last_modified=REF, scope_url='https://example.com/', script_url='sw.js'))
        self.assertEqual('chrome:service_worker:registration', encoded['data_type'])
        self.assertEqual('Registration Last Modified', encoded['timestamp_desc'])
        self.assertTrue(encoded['datetime'].startswith('2024-01-15'))

    def test_cache_entry_uses_its_entry_time(self):
        encoded = encode(self._item(
            'ServiceWorkerCacheStorageItem', row_type='service worker (cache storage)',
            entry_time=REF, request_url='https://example.com/a.js', cache_name='v1'))
        self.assertEqual('chrome:service_worker:cache_entry', encoded['data_type'])
        self.assertTrue(encoded['datetime'].startswith('2024-01-15'))

    def test_a_record_with_no_time_is_labelled_as_timeless(self):
        # Rather than asserting a 1970 event that never happened.
        encoded = encode(self._item(
            'ServiceWorkerResourceItem', row_type='service worker (resource)',
            resource_id=288, resource_state='purgeable', origin=''))
        self.assertEqual('Not a time', encoded['timestamp_desc'])

    def test_a_resource_message_survives_a_missing_origin(self):
        # ~1% of them are orphaned from any registration and carry no origin.
        encoded = encode(self._item(
            'ServiceWorkerResourceItem', row_type='service worker (resource)',
            resource_id=288, resource_state='purgeable', origin=''))
        self.assertIn('288', encoded['message'])
        self.assertIn('purgeable', encoded['message'])
        self.assertFalse(encoded['message'].rstrip().endswith('for'))


class TestEncoderToleratesMissingOptionalFields(unittest.TestCase):
    """No branch may index a field the record might not have.

    base_encoder drops keys whose value is None, so a record that didn't record an
    optional field arrives without that key. Indexing it raises KeyError, and that
    escapes write_jsonl_record and aborts the *whole* JSONL file -- every remaining
    record lost, not the one that was odd. Realistic triggers: a visited page with a
    NULL title, or Firefox formhistory on a schema with no timesUsed.
    """

    def _minimal(self, owner, name, row_type):
        """A record carrying only what every record has -- nothing optional."""
        cls = getattr(owner, name)
        obj = cls.__new__(cls)
        obj.__dict__.update(profile='p', row_type=row_type, timestamp=REF)
        return obj

    def _record_classes(self):
        for owner in (WebBrowser, Chrome, Firefox):
            for name in sorted(dir(owner)):
                if not name.endswith(('Item', 'Setting', 'Extension')):
                    continue
                cls = getattr(owner, name)
                if isinstance(cls, type):
                    yield owner, name, cls

    def test_no_branch_raises_on_a_record_with_only_required_fields(self):
        failures = []
        for owner, name, _cls in self._record_classes():
            obj = self._minimal(owner, name, 'test')
            try:
                json.dumps(obj, cls=HindsightEncoder)
            except Exception as exc:
                failures.append(f'{owner.__name__}.{name}: '
                                f'{type(exc).__name__}: {exc}')
        self.assertEqual([], failures, '\n' + '\n'.join(failures))

    def test_a_visited_page_with_no_title_still_encodes(self):
        # The concrete case: Chrome/Firefox both record NULL titles.
        item = Chrome.URLItem.__new__(Chrome.URLItem)
        item.__dict__.update(profile='p', row_type='url', timestamp=REF,
                             url='https://example.com', title=None, visit_count=1)
        encoded = encode(item)
        self.assertEqual('chrome:history:page_visited', encoded['data_type'])
        self.assertIn('example.com', encoded['message'])

    def test_a_cookie_with_no_host_still_encodes(self):
        item = Chrome.CookieItem.__new__(Chrome.CookieItem)
        item.__dict__.update(profile='p', row_type='cookie (created)', timestamp=REF)
        encoded = encode(item)
        self.assertEqual('chrome:cookie:entry', encoded['data_type'])


class TestUnhandledRecordsAreStillWritten(unittest.TestCase):
    """An unknown class is written generically, not dropped.

    Dropping is what made the original bug invisible: the run counted the records and
    the output simply didn't contain them.
    """

    def test_an_unknown_class_still_produces_a_record(self):
        class Invented:
            def __init__(self):
                self.profile = 'p'
                self.row_type = 'brand new artifact'
                self.key = 'k'
                self.value = 'v'
                self.timestamp = REF

        encoded = encode(Invented())
        self.assertEqual('hindsight:brand_new_artifact', encoded['data_type'])
        self.assertIn('datetime', encoded)


class TestOddValuesDoNotAbortTheFile(unittest.TestCase):
    """json calls default() for values, not only for records.

    The object fallback reads `obj.__dict__`, so a value without one raised
    AttributeError out of json.dumps and killed the whole file. On one test profile
    a single set on a ccl CachedMetadata record cost 8,492 of 12,293 records: every
    cache entry, and the cookies, history and sessions that came after it.
    """

    def test_a_set_field_is_written_as_a_list(self):
        class WithASet:
            def __init__(self):
                self.profile = 'p'
                self.row_type = 'cache entry'
                self.declarations = {'HTTP/1.1 200', 'HTTP/1.1 204'}
                self.timestamp = REF

        encoded = encode(WithASet())
        self.assertEqual(['HTTP/1.1 200', 'HTTP/1.1 204'], encoded['declarations'])

    def test_a_set_is_sorted_so_two_runs_can_be_compared(self):
        self.assertEqual(['a', 'b', 'c'], encode({'c', 'a', 'b'}))

    def test_a_frozenset_encodes_too(self):
        self.assertEqual(['x', 'y'], encode(frozenset({'y', 'x'})))

    def test_a_value_with_no_dict_does_not_raise(self):
        class Slotted:
            __slots__ = ('a',)

            def __init__(self):
                self.a = 1

        # The record itself is ordinary; the odd value is nested inside it, which
        # is how the real one arrived.
        class Holder:
            def __init__(self):
                self.profile = 'p'
                self.row_type = 'holder'
                self.odd = Slotted()
                self.timestamp = REF

        encoded = encode(Holder())
        self.assertIn('odd', encoded)


class TestNestedValuesAreNotDressedUpAsRecords(unittest.TestCase):
    """A foreign object in a record's field is a value, not a record of its own.

    ccl's CacheKey and CachedMetadata hang off every cache entry. Encoding them
    through the record path stamped each with source_long 'Chrome History', a 1970
    datetime, its own data_type and an empty message, nested inside the entry that
    owned them, and leaked their private field names verbatim. Records are the
    things with a row_type; every Hindsight item base sets one and no ccl class does.
    """

    ENVELOPE = ('source_short', 'source_long', 'parser', 'data_type',
                'timestamp_desc', 'datetime', 'message')

    class _Foreign:
        """Shaped like ccl's CacheKey: no row_type, private attribute names."""

        def __init__(self):
            self._url = 'https://example.test/a.svg'
            self._isolation_key_top_frame_site = 'https://top.test'

    def _record_with(self, value):
        class Owner:
            def __init__(self):
                self.profile = 'p'
                self.row_type = 'cache'
                self.nested = value
                self.timestamp = REF

        return encode(Owner())['nested']

    def test_a_nested_foreign_object_carries_no_envelope(self):
        nested = self._record_with(self._Foreign())
        for field in self.ENVELOPE:
            with self.subTest(field=field):
                self.assertNotIn(field, nested)

    def test_private_field_names_are_presented_unprefixed(self):
        nested = self._record_with(self._Foreign())
        self.assertEqual('https://example.test/a.svg', nested['url'])
        self.assertEqual('https://top.test', nested['isolation_key_top_frame_site'])

    def test_a_nested_mapping_stays_a_mapping(self):
        import types
        nested = self._record_with(types.MappingProxyType({'server': ['sffe']}))
        self.assertEqual({'server': ['sffe']}, nested)

    def test_the_record_itself_keeps_its_envelope(self):
        class Unknown:
            def __init__(self):
                self.profile = 'p'
                self.row_type = 'brand new artifact'
                self.timestamp = REF

        encoded = encode(Unknown())
        self.assertEqual('hindsight:brand_new_artifact', encoded['data_type'])
        self.assertEqual('WEBHIST', encoded['source_short'])


if __name__ == '__main__':
    unittest.main()
