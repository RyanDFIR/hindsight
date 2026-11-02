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

import pathlib
import struct
import tempfile
import unittest

from pyhindsight import utils
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.lib.proto.components.send_tab_to_self.proto.send_tab_to_self_pb2 import SendTabToSelfLocal
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


if __name__ == '__main__':
    unittest.main()
