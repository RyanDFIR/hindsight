###################################################################################################
#
# quantcast_cookies.py
#   Interpret Quantcast cookies* (parsing partially complete)
#
# Plugin Author: Ryan Benson (ryan@hindsig.ht)
#
###################################################################################################

# Config
friendlyName = "Quantcast Cookie Parser"
description = "Parses Quantcast cookies"
artifactTypes = ["cookie (created)", "cookie (accessed)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20160907"
parsedItems = 0


def plugin(analysis_session=None):
    from pyhindsight.utils import friendly_date
    import re
    if analysis_session is None:
        return

    timestamp_re = re.compile(r'^(P0)-(\d+)-(\d{10,13})$')
    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_artifacts:
        if item.row_type in artifactTypes:
            if item.name == '__qca':
                m = re.search(timestamp_re, item.value)
                if m:
                    item.interpretation = friendly_date(int(m.group(3))) \
                                          + ' [Quantcast Cookie Timestamp]'
                    parsedItems += 1

    # Description of what the plugin did
    return "{} cookies parsed".format(parsedItems)
