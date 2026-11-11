"""Decoding the records in the Sync Data LevelDB (Chromium's DataTypeStore).

Each data type's sync bridge picks the message it stores, so the key's data type decides
the proto: most older types are SyncableServices and store PersistedEntityData, while some
store their specifics directly or wrap them in a local message (send_tab_to_self). A record
with no vendored .proto (Edge's own data types, for one) is decoded without a schema rather
than left as hex.

Fields a .proto does not define are written out by number. protobuf's own
print_unknown_fields reads a short string such as "t" as an empty nested message and drops
it, so the printer is pinned here on exactly that case.
"""

import base64
import json
import pathlib
import sqlite3
import struct
import tempfile
import unittest

from pyhindsight import utils
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.lib.proto.components.autofill.core.browser.proto.autofill_sync_pb2 import AutofillSyncStorageKey
from pyhindsight.lib.proto.components.send_tab_to_self.proto.send_tab_to_self_pb2 import SendTabToSelfLocal
from pyhindsight.lib.proto.components.sync.protocol.bookmark_model_metadata_pb2 import BookmarkModelMetadata
from pyhindsight.lib.proto.components.sync.protocol.data_type_state_pb2 import DataTypeState
from pyhindsight.lib.proto.components.sync.protocol.entity_metadata_pb2 import EntityMetadata
from pyhindsight.lib.proto.components.sync.protocol.persisted_entity_data_pb2 import PersistedEntityData


def _varint(n):
    out = b''
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def _log_entry(seq, key, value):
    """One LevelDB log block (a "full" entry) holding a write batch with one value."""
    batch = struct.pack('<QI', seq, 1) + b'\x01' + _varint(len(key)) + key + _varint(len(value)) + value
    return struct.pack('<IHB', 0, len(batch), 1) + batch


class TestProtoToText(unittest.TestCase):

    def test_unknown_fields_keep_short_strings_nested_messages_and_bytes(self):
        raw = b'\x0a\x01t' + b'\x12\x02ab' + b'\x1a\x03\x0a\x01x' + b'\x22\x02\xff\x00' + b'\x28\x96\x01'
        self.assertEqual(
            utils.proto_to_text(utils.schemaless_proto(raw)),
            '1: "t"\n2: "ab"\n3 {\n  1: "x"\n}\n4: "\\377\\000"\n5: 150')

    def test_bytes_that_are_not_a_message_are_rejected(self):
        self.assertIsNone(utils.schemaless_proto(b't'))
        self.assertIsNone(utils.schemaless_proto(b''))

    def test_known_and_unknown_fields_together(self):
        message = PersistedEntityData.FromString(PersistedEntityData(name='x').SerializeToString() + b'\x18\x01')
        self.assertEqual(utils.proto_to_text(message), 'name: "x"\n3: 1')


class TestSyncDataRecords(unittest.TestCase):

    def _parse(self, records):
        with tempfile.TemporaryDirectory() as tmp:
            ldb = pathlib.Path(tmp, 'Sync Data', 'LevelDB')
            ldb.mkdir(parents=True)
            (ldb / '000003.log').write_bytes(
                b''.join(_log_entry(seq, key, value) for seq, (key, value) in enumerate(records, 1)))
            chrome = Chrome(tmp, no_copy=True)
            chrome.get_sync_data(tmp, 'Sync Data')
            return {item.key: item for item in chrome.parsed_sync_data}

    def test_records_decode_with_the_proto_their_data_type_stores(self):
        app = PersistedEntityData(name='Web Store')
        app.specifics.app.extension.id = 'ahfgeienlihckogmohjhadlkjgocpleb'
        sent = SendTabToSelfLocal()
        sent.specifics.url = 'https://example.com/'
        rows = self._parse([
            (b'apps-dt-abc=', app.SerializeToString()),
            (b'send_tab_to_self-dt-guid', sent.SerializeToString()),
            (b'collection-dt-ROOT', b'\x0a\x04ROOT\x18\x01'),
        ])

        self.assertEqual(rows['apps-dt-abc='].row_type, 'apps')
        self.assertIn('id: "ahfgeienlihckogmohjhadlkjgocpleb"', rows['apps-dt-abc='].value)
        self.assertEqual(rows['send_tab_to_self-dt-guid'].row_type, 'send tab to self')
        self.assertIn('url: "https://example.com/"', rows['send_tab_to_self-dt-guid'].value)
        # Edge's Collections have no public .proto; decoded without a schema, not shown as hex
        self.assertEqual(rows['collection-dt-ROOT'].row_type, 'collection')
        self.assertEqual(rows['collection-dt-ROOT'].value, '1: "ROOT"\n3: 1')

    def test_account_storage_keys_decode_like_local_ones(self):
        # A data type kept in account storage has its keys prefixed with "A-"
        rows = self._parse([(b'A-reading_list-GlobalMetadata', b'\x2a\x04abcd')])
        row = rows['A-reading_list-GlobalMetadata']
        self.assertEqual(row.row_type, 'global metadata')
        self.assertEqual(row.value, 'cache_guid: "abcd"')


class TestSyncMetadataOutsideSyncData(unittest.TestCase):
    """Autofill, passwords, history and bookmarks keep their sync metadata in their own files."""

    @staticmethod
    def _state(data_type_id):
        state = DataTypeState(cache_guid='guid')
        state.progress_marker.data_type_id = data_type_id
        return state.SerializeToString()

    @staticmethod
    def _entity(creation_time):
        return EntityMetadata(client_tag_hash='hash', creation_time=creation_time).SerializeToString()

    def _parse(self, file_name, build):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, file_name)
            if file_name.endswith('Bookmarks'):
                path.write_text(json.dumps({'roots': {}, 'sync_metadata': build}), encoding='utf-8')
            else:
                conn = sqlite3.connect(path)
                build(conn)
                conn.commit()
                conn.close()
            chrome = Chrome(tmp, no_copy=True)
            chrome.get_sync_metadata(tmp, file_name)
            return {item.key: item for item in chrome.parsed_sync_data}

    def test_web_data_types_are_named_from_their_data_type_state(self):
        autofill_key = AutofillSyncStorageKey(name='email', value='someone@example.com').SerializeToString()

        def build(conn):
            conn.execute('CREATE TABLE autofill_model_type_state (model_type INTEGER, value BLOB)')
            conn.execute('CREATE TABLE autofill_sync_metadata (model_type INTEGER, storage_key VARCHAR, value BLOB)')
            # model_type is Chromium's internal histogram number; the state names the type
            conn.execute('INSERT INTO autofill_model_type_state VALUES (7, ?)', (self._state(31729),))
            conn.execute('INSERT INTO autofill_model_type_state VALUES (6, ?)', (self._state(63951),))
            conn.execute('INSERT INTO autofill_sync_metadata VALUES (7, ?, ?)', (autofill_key, self._entity(1)))
            conn.execute('INSERT INTO autofill_sync_metadata VALUES (6, ?, ?)', ('3a5b-guid', self._entity(2)))

        rows = self._parse('Web Data', build)
        self.assertEqual(rows['autofill-GlobalMetadata'].row_type, 'global metadata')
        self.assertIn('autofill_profiles-GlobalMetadata', rows)
        # An autocomplete entry's storage key is the entry itself
        entry = rows['autofill-md-name: "email" value: "someone@example.com"']
        self.assertEqual(entry.row_type, 'entity metadata')
        self.assertIn('creation_time: 1', entry.value)
        self.assertIn('creation_time: 2', rows['autofill_profiles-md-3a5b-guid'].value)

    def test_web_data_from_before_model_type_holds_only_autofill(self):
        def build(conn):
            conn.execute('CREATE TABLE autofill_model_type_state (id INTEGER, value BLOB)')
            conn.execute('CREATE TABLE autofill_sync_metadata (storage_key VARCHAR, value BLOB)')
            conn.execute('INSERT INTO autofill_model_type_state VALUES (1, ?)', (b'',))
            conn.execute('INSERT INTO autofill_sync_metadata VALUES (?, ?)', (
                AutofillSyncStorageKey(name='q', value='x').SerializeToString(), self._entity(3)))

        rows = self._parse('Web Data', build)
        self.assertEqual(sorted(rows), ['autofill-GlobalMetadata', 'autofill-md-name: "q" value: "x"'])

    def test_password_metadata_is_encrypted_and_account_storage_is_prefixed(self):
        def build(conn):
            conn.execute('CREATE TABLE sync_model_metadata (id INTEGER, model_metadata VARCHAR)')
            conn.execute('CREATE TABLE sync_entities_metadata (storage_key INTEGER, metadata VARCHAR)')
            conn.execute('INSERT INTO sync_model_metadata VALUES (1, ?)', (self._state(45873),))
            conn.execute('INSERT INTO sync_entities_metadata VALUES (4, ?)', (b'v20' + b'\x01' * 40,))

        rows = self._parse('Login Data For Account', build)
        self.assertIn('cache_guid: "guid"', rows['A-passwords-GlobalMetadata'].value)
        self.assertEqual(rows['A-passwords-md-4'].value, '<encrypted>')

    def test_history_sync_metadata_and_its_state_in_meta(self):
        def build(conn):
            conn.execute('CREATE TABLE meta (key LONGVARCHAR, value LONGVARCHAR)')
            conn.execute('CREATE TABLE history_sync_metadata (storage_key INTEGER, value BLOB)')
            conn.execute("INSERT INTO meta VALUES ('history_model_type_state', ?)", (self._state(963985),))
            conn.execute("INSERT INTO meta VALUES ('version', '70')")
            conn.execute('INSERT INTO history_sync_metadata VALUES (13409858964816266, ?)', (self._entity(4),))

        rows = self._parse('History', build)
        self.assertEqual(sorted(rows), ['history-GlobalMetadata', 'history-md-13409858964816266'])

    def test_bookmark_sync_metadata_in_the_bookmarks_file(self):
        metadata = BookmarkModelMetadata()
        metadata.data_type_state.cache_guid = 'guid'
        bookmark = metadata.bookmarks_metadata.add(id=5)
        bookmark.metadata.creation_time = 1655571545604
        rows = self._parse('AccountBookmarks', base64.b64encode(metadata.SerializeToString()).decode())

        self.assertEqual(rows['A-bookmarks-GlobalMetadata'].value, 'cache_guid: "guid"')
        self.assertEqual(rows['A-bookmarks-md-5'].value, 'creation_time: 1655571545604')


if __name__ == '__main__':
    unittest.main()
