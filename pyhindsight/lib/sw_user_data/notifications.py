"""Scheduled Notification decoder.

Sources:
  - Schema: content/browser/notifications/notification_database_data.proto
  - Writer: content/browser/notifications/notification_database.cc

The Notifications subsystem stores one record per scheduled / displayed
notification under the key `_notification_:<notification_id>`. Forensically
notable: the full notification payload (title, body, icon URLs, scheduled
fire time, action buttons) sits in plaintext in the LDB.
"""

import datetime

from pyhindsight import utils
from pyhindsight.lib.proto.content.browser.notifications.notification_database_data_pb2 import (
    NotificationDatabaseDataProto)


KEY_PREFIX = '_notification_:'
SUBSYSTEM_LABEL = 'scheduled notification'


def matches(user_data_key):
    return user_data_key.startswith(KEY_PREFIX)


def _unix_ms_to_tz(ms, timezone):
    """Convert Unix-epoch milliseconds (e.g. JS Date.now()) to a datetime in
    the report's timezone. Returns None on overflow / bad input."""
    try:
        dt = utils.with_precision(
            datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc), 'ms')
        return utils.to_datetime(dt, timezone)
    except (OverflowError, OSError, ValueError):
        return None


def decode(user_data_key, value, timezone):
    ndata = NotificationDatabaseDataProto()
    try:
        ndata.ParseFromString(value)
    except Exception as e:
        return (SUBSYSTEM_LABEL,
                f'<NotificationDatabaseData decode failed: {e}; '
                f'len={len(value)}>', None)

    pieces = []
    if ndata.HasField('notification_id'):
        pieces.append(f'id={ndata.notification_id}')
    if ndata.HasField('origin'):
        pieces.append(f'origin={ndata.origin}')

    nd = ndata.notification_data
    if nd.HasField('title'):
        pieces.append(f'title={nd.title!r}')
    if nd.HasField('body'):
        body_text = nd.body if len(nd.body) <= 200 else nd.body[:200] + '…'
        pieces.append(f'body={body_text!r}')
    if nd.HasField('tag') and nd.tag:
        pieces.append(f'tag={nd.tag!r}')
    if nd.HasField('icon') and nd.icon:
        pieces.append(f'icon={nd.icon}')
    if nd.HasField('image') and nd.image:
        pieces.append(f'image={nd.image}')
    if nd.HasField('badge') and nd.badge:
        pieces.append(f'badge={nd.badge}')
    if nd.vibration_pattern:
        pieces.append(f'vibration_pattern={list(nd.vibration_pattern)}')
    if nd.HasField('silent') and nd.silent:
        pieces.append('silent=True')
    if nd.HasField('require_interaction') and nd.require_interaction:
        pieces.append('require_interaction=True')
    if nd.HasField('renotify') and nd.renotify:
        pieces.append('renotify=True')
    if nd.HasField('show_trigger_timestamp') and nd.show_trigger_timestamp:
        # Per proto comment: offset from Windows epoch in microseconds.
        pieces.append(
            f'show_trigger_timestamp='
            f'{utils.to_datetime(nd.show_trigger_timestamp, timezone)}')
    if ndata.HasField('has_triggered'):
        pieces.append(f'has_triggered={ndata.has_triggered}')
    if nd.actions:
        action_strs = []
        for a in nd.actions:
            bits = []
            if a.HasField('action'):
                bits.append(f'action={a.action!r}')
            if a.HasField('title'):
                bits.append(f'title={a.title!r}')
            if a.HasField('icon') and a.icon:
                bits.append(f'icon={a.icon}')
            if a.HasField('type'):
                type_name = NotificationDatabaseDataProto.NotificationAction.Type \
                    .Name(a.type)
                bits.append(f'type={type_name}')
            if a.HasField('placeholder') and a.placeholder:
                bits.append(f'placeholder={a.placeholder!r}')
            action_strs.append('{' + ', '.join(bits) + '}')
        pieces.append(f'actions=[{", ".join(action_strs)}]')
    if ndata.HasField('num_clicks') and ndata.num_clicks:
        pieces.append(f'num_clicks={ndata.num_clicks}')
    if ndata.HasField('num_action_button_clicks') \
            and ndata.num_action_button_clicks:
        pieces.append(f'num_action_button_clicks={ndata.num_action_button_clicks}')
    if ndata.HasField('closed_reason'):
        reason_name = NotificationDatabaseDataProto.ClosedReason.Name(
            ndata.closed_reason)
        pieces.append(f'closed_reason={reason_name}')
    if ndata.HasField('is_shown_by_browser') and ndata.is_shown_by_browser:
        pieces.append('is_shown_by_browser=True')
    if ndata.serialized_metadata:
        md_str = ', '.join(f'{k}={v!r}'
                           for k, v in sorted(ndata.serialized_metadata.items()))
        pieces.append(f'serialized_metadata={{{md_str}}}')

    if nd.HasField('timestamp') and nd.timestamp:
        spec_dt = _unix_ms_to_tz(nd.timestamp, timezone)
        if spec_dt:
            pieces.append(f'spec_timestamp={spec_dt}')

    # creation_time_millis (Unix epoch ms) drives the row's last_modified so
    # notifications sort by when they were scheduled.
    event_time = None
    if ndata.HasField('creation_time_millis') and ndata.creation_time_millis:
        event_time = _unix_ms_to_tz(ndata.creation_time_millis, timezone)

    return (SUBSYSTEM_LABEL, '; '.join(pieces), event_time)
