###################################################################################################
#
# generic_timestamps.py
#   If cookie data looks like it might be a timestamp, try to decode it
#
# Plugin Author: Ryan Benson (ryan@hindsig.ht)
#
###################################################################################################

# Config
friendlyName = "Generic Timestamp Decoder"
description = "Attempts to detect and decode potential epoch second, epoch millisecond, and Webkit timestamps"
artifactTypes = ("cookie (created)", "cookie (accessed)", "local storage", "indexeddb")
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20240428"
parsedItems = 0


def plugin(analysis_session=None):
    from pyhindsight.utils import friendly_date
    import re
    if analysis_session is None:
        return

    timestamp_re = re.compile(r'^(1(\d{9}|\d{12}|\d{16}))$')
    ls_timestamp_re = re.compile(r'timestamp.*?(\d{10,17})')
    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            if item.interpretation is None:
                m = re.search(timestamp_re, item.value)
                ls_m = re.search(ls_timestamp_re, item.value)
                if m:
                    item.interpretation = friendly_date(int(m.group(0))) + ' [potential timestamp]'
                    parsedItems += 1
                elif ls_m:
                    item.interpretation = friendly_date(int(ls_m.group(1))) + ' [potential timestamp]'
                    parsedItems += 1

    # Description of what the plugin did
    return "{} timestamps parsed".format(parsedItems)
