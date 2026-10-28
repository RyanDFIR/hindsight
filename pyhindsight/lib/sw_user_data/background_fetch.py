"""Background Fetch decoder.

Sources:
  - Schema: content/browser/background_fetch/background_fetch.proto
  - Writer: content/browser/background_fetch/background_fetch_data_manager.cc
  - Keys:   content/browser/background_fetch/storage/database_helpers.h

The Background Fetch API persists several record kinds per registration so
that an interrupted fetch can resume across browser restarts. Each kind has
its own key prefix:

  bgfetch_active_registration_unique_id_<developer_id>
        → UTF-8 string: the active unique_id for this developer-supplied id
  bgfetch_registration_<unique_id>           → BackgroundFetchMetadata
  bgfetch_ui_options_<unique_id>             → BackgroundFetchUIOptions
  bgfetch_pending_request_<unique_id>_<idx>  → BackgroundFetchPendingRequest
  bgfetch_active_request_<unique_id>_<idx>   → BackgroundFetchActiveRequest
  bgfetch_completed_request_<unique_id>_<idx>→ BackgroundFetchCompletedRequest
  bgfetch_storage_version_<unique_id>        → BackgroundFetchStorageVersion
                                                (single int enum value)
"""

import datetime

from pyhindsight import utils
from pyhindsight.lib.proto.content.browser.background_fetch.background_fetch_pb2 import (
    BackgroundFetchMetadata,
    BackgroundFetchUIOptions,
    BackgroundFetchPendingRequest,
    BackgroundFetchActiveRequest,
    BackgroundFetchCompletedRequest,
    BackgroundFetchRegistration,
    BackgroundFetchStorageVersion,
)


ACTIVE_REG_PREFIX = 'bgfetch_active_registration_unique_id_'
REGISTRATION_PREFIX = 'bgfetch_registration_'
UI_OPTIONS_PREFIX = 'bgfetch_ui_options_'
PENDING_REQ_PREFIX = 'bgfetch_pending_request_'
ACTIVE_REQ_PREFIX = 'bgfetch_active_request_'
COMPLETED_REQ_PREFIX = 'bgfetch_completed_request_'
STORAGE_VERSION_PREFIX = 'bgfetch_storage_version_'

_FAILURE_REASON = BackgroundFetchRegistration.BackgroundFetchFailureReason
_RESULT = BackgroundFetchRegistration.BackgroundFetchResult


def matches(user_data_key):
    return user_data_key.startswith('bgfetch_')


def _format_registration(reg):
    """Format the inner BackgroundFetchRegistration sub-message."""
    bits = []
    if reg.HasField('unique_id'):
        bits.append(f'unique_id={reg.unique_id}')
    if reg.HasField('developer_id'):
        try:
            bits.append(f'developer_id={reg.developer_id.decode("utf-8")!r}')
        except UnicodeDecodeError:
            bits.append(f'developer_id=0x{reg.developer_id.hex()}')
    if reg.HasField('upload_total'):
        bits.append(f'upload_total={reg.upload_total}')
    if reg.HasField('uploaded'):
        bits.append(f'uploaded={reg.uploaded}')
    if reg.HasField('download_total'):
        bits.append(f'download_total={reg.download_total}')
    if reg.HasField('downloaded'):
        bits.append(f'downloaded={reg.downloaded}')
    if reg.HasField('result'):
        bits.append(f'result={_RESULT.Name(reg.result)}')
    if reg.HasField('failure_reason'):
        bits.append(f'failure_reason={_FAILURE_REASON.Name(reg.failure_reason)}')
    return '; '.join(bits)


def decode(user_data_key, value, timezone):
    if user_data_key.startswith(ACTIVE_REG_PREFIX):
        # Value is just the UTF-8 unique_id this developer_id currently maps to.
        return ('background fetch (active registration)',
                f'unique_id={value.decode("utf-8", errors="replace")}', None)

    if user_data_key.startswith(STORAGE_VERSION_PREFIX):
        # Value is a serialized BackgroundFetchStorageVersion enum value.
        # Stored as a single varint (the int32 enum), so read it directly.
        try:
            # Treat as a tiny proto-encoded varint; safest path is to parse
            # via the descriptor or just decode the raw int.
            v = int.from_bytes(value, 'little') if value else 0
            # Best-effort enum name
            try:
                name = BackgroundFetchStorageVersion.Name(v)
            except ValueError:
                name = str(v)
            return ('background fetch (storage version)',
                    f'version={name} ({v})', None)
        except Exception as e:
            return ('background fetch (storage version)',
                    f'<storage version decode failed: {e}; len={len(value)}>', None)

    if user_data_key.startswith(REGISTRATION_PREFIX):
        meta = BackgroundFetchMetadata()
        try:
            meta.ParseFromString(value)
        except Exception as e:
            return ('background fetch',
                    f'<BackgroundFetchMetadata decode failed: {e}>', None)
        pieces = []
        if meta.HasField('storage_key') and meta.storage_key:
            pieces.append(f'storage_key={meta.storage_key}')
        if meta.HasField('isolation_info') and meta.isolation_info:
            pieces.append(f'isolation_info={meta.isolation_info!r}')
        if meta.HasField('num_fetches'):
            pieces.append(f'num_fetches={meta.num_fetches}')
        if meta.HasField('registration'):
            pieces.append('registration={' + _format_registration(meta.registration) + '}')
        if meta.HasField('options'):
            opt_bits = []
            if meta.options.HasField('title'):
                opt_bits.append(f'title={meta.options.title!r}')
            if meta.options.HasField('download_total'):
                opt_bits.append(f'download_total={meta.options.download_total}')
            if meta.options.icons:
                opt_bits.append(f'icon_count={len(meta.options.icons)}')
            if opt_bits:
                pieces.append('options={' + '; '.join(opt_bits) + '}')

        # creation_microseconds_since_unix_epoch is µs since Unix epoch.
        event_time = None
        if meta.HasField('creation_microseconds_since_unix_epoch') \
                and meta.creation_microseconds_since_unix_epoch:
            try:
                dt = utils.with_precision(utils.UNIX_EPOCH + datetime.timedelta(
                    microseconds=meta.creation_microseconds_since_unix_epoch), 'us')
                event_time = utils.to_datetime(dt, timezone)
            except OverflowError:
                pass
        return ('background fetch', '; '.join(pieces), event_time)

    if user_data_key.startswith(UI_OPTIONS_PREFIX):
        opts = BackgroundFetchUIOptions()
        try:
            opts.ParseFromString(value)
        except Exception as e:
            return ('background fetch (ui options)',
                    f'<BackgroundFetchUIOptions decode failed: {e}>', None)
        pieces = []
        if opts.HasField('title'):
            pieces.append(f'title={opts.title!r}')
        if opts.HasField('icon') and opts.icon:
            pieces.append(f'icon_bytes={len(opts.icon)}')
        return ('background fetch (ui options)', '; '.join(pieces), None)

    if user_data_key.startswith(PENDING_REQ_PREFIX):
        msg = BackgroundFetchPendingRequest()
        try:
            msg.ParseFromString(value)
        except Exception as e:
            return ('background fetch (pending request)',
                    f'<decode failed: {e}>', None)
        bits = []
        if msg.HasField('unique_id'):
            bits.append(f'unique_id={msg.unique_id}')
        if msg.HasField('request_index'):
            bits.append(f'request_index={msg.request_index}')
        if msg.HasField('request_body_size'):
            bits.append(f'request_body_size={msg.request_body_size}')
        if msg.HasField('serialized_request') and msg.serialized_request:
            sr = msg.serialized_request
            sr = sr if len(sr) <= 200 else sr[:200] + '…'
            bits.append(f'serialized_request={sr!r}')
        return ('background fetch (pending request)', '; '.join(bits), None)

    if user_data_key.startswith(ACTIVE_REQ_PREFIX):
        msg = BackgroundFetchActiveRequest()
        try:
            msg.ParseFromString(value)
        except Exception as e:
            return ('background fetch (active request)',
                    f'<decode failed: {e}>', None)
        bits = []
        if msg.HasField('unique_id'):
            bits.append(f'unique_id={msg.unique_id}')
        if msg.HasField('request_index'):
            bits.append(f'request_index={msg.request_index}')
        if msg.HasField('download_guid'):
            bits.append(f'download_guid={msg.download_guid}')
        if msg.HasField('request_body_size'):
            bits.append(f'request_body_size={msg.request_body_size}')
        return ('background fetch (active request)', '; '.join(bits), None)

    if user_data_key.startswith(COMPLETED_REQ_PREFIX):
        msg = BackgroundFetchCompletedRequest()
        try:
            msg.ParseFromString(value)
        except Exception as e:
            return ('background fetch (completed request)',
                    f'<decode failed: {e}>', None)
        bits = []
        if msg.HasField('unique_id'):
            bits.append(f'unique_id={msg.unique_id}')
        if msg.HasField('request_index'):
            bits.append(f'request_index={msg.request_index}')
        if msg.HasField('download_guid'):
            bits.append(f'download_guid={msg.download_guid}')
        if msg.HasField('failure_reason'):
            bits.append(
                f'failure_reason={_FAILURE_REASON.Name(msg.failure_reason)}')
        return ('background fetch (completed request)', '; '.join(bits), None)

    # bgfetch_* prefix matched but no specific kind recognized.
    return ('background fetch (unknown)',
            f'<unrecognized bgfetch key; len={len(value)}>', None)
