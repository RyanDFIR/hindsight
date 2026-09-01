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


if __name__ == '__main__':
    unittest.main()
