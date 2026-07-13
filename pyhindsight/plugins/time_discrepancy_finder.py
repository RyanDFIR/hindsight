###################################################################################################
#
# time_discrepancy_finder.py
#   Attempts to find discrepancies between server-side and local timestamps
#
# References:
#   Lee Whitfield (https://web.archive.org/web/20110712151744/http://forensic4cast.com/2011/07/flashpost-google-plus-artefacts-url-forwarding/)
#   Vincent Toubiana and Helen Nissenbaum (https://web.archive.org/web/20160308023419/http://repository.cmu.edu/cgi/viewcontent.cgi?article=1058&context=jpc)
#
# Blog post explaining plugin:
#   https://web.archive.org/web/20131112222848/http://www.obsidianforensics.com/blog/detecting-clock-changes-using-cookies/
#
# Plugin Author: Ryan Benson (ryan@hindsig.ht)
#
###################################################################################################


# Config
friendlyName = "Time Discrepancy Finder"
description = "Attempts to find discrepancies between server-side and local timestamps"
artifactTypes = ("cookie (created)", "url")
remoteLookups = 0
browser = "any"
browserVersion = 1
version = "20170129"
parsedItems = 0


def plugin(analysis_session=None):
    from pyhindsight.utils import to_datetime
    import datetime
    import re
    if analysis_session is None:
        return

    global parsedItems
    parsedItems = 0

    cookie_set = [
        # website                   # cookie name            # regex for timestamp
        {'.pubmatic.com/':          {'name': '_curtime',     'regex': r'(\d{10})'}},
        {'.invitemedia.com/':       {'name': 'dp_rec',       'regex': r':(\d{10})}'}},
        {'.atdmt.com/':             {'name': 'AA002',        'regex': r'^(\d{10})-'}},
        {'.mathtag.com/':           {'name': 'mt_mop',       'regex': r'4:(\d{10})'}},
        {'.33across.com/':          {'name': '33x_ps',       'regex': r'ts%3D(\d{13})'}},
        {'.twitter.com/':           {'name': 'guest_id',     'regex': r'v1%3A(\d{13})'}},
        {'.twitter.com/':           {'name': 'pid',          'regex': r'v3:(\d{13})'}},
        {'www.yahoo.com/':          {'name': 'FBJSC',        'regex': r'(\d{10})'}},
        {'.scorecardresearch.com/': {'name': 'UIDR',         'regex': r'(\d{10})'}},
        {'.rubiconproject.com/':    {'name': 'put_3076',     'regex': r'(\d{10})'}},
        {'.mookie1.com/':           {'name': 'mdata',        'regex': r'\|(\d{10})$'}},
        {'*':                       {'name': 'PREF',         'regex': r'LM=(\d{10})'}},
        {'*':                       {'name': '__gads',       'regex': r'T=(1\d{9})'}},
        {'.cbsnews.com/':           {'name': 'apexLat',      'regex': r'^(1\d{12})$'}},
        {'.adblade.com/':           {'name': '__impt',       'regex': r'^(1\d{9})$'}},
        {'.wtp101.com/':            {'name': 'cookie_born',  'regex': r'^(1\d{9})$'}},
        {'.advertising.com/':       {'name': 'ACID',         'regex': r'^.{6}(1\d{9})'}},
        {'.bidswitch.net/':         {'name': 'c',            'regex': r'^(1\d{9})$'}},
        {'*':                       {'name': '__cfduid',     'regex': r'(1\d{9})$'}},
        {'.insightexpressai.com/':  {'name': 'DW_Time',      'regex': r'^(1\d{9})$'}},
        {'www.bose.com/':           {'name': 'bose_id',      'regex': r'^(1\d{12})'}},
        {'.liveperson.net/':        {'name': 'LivePersonID', 'regex': r'd=(1\d{9})'}},
        {'.baidu.com/':             {'name': 'PSTM',         'regex': r'^(1\d{9})$'}},
        {'.alexa.com/':             {'name': 'lv',           'regex': r'(1\d{9})$'}},
        {'.doubleclick.net/':       {'name': 'id',           'regex': r'\|t=(1\d{9})\|'}}
    ]

    url_set = [
        # regex for url and timestamp
        r'google\..*&n=(\d{13})'
    ]

    for item in analysis_session.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            if item.row_type == 'cookie (created)':
                for site in cookie_set:
                    if item.url in site or list(site.keys())[0] == '*':
                        if site[list(site.keys())[0]]['name'] == item.name:
                            m = re.search(site[list(site.keys())[0]]['regex'], item.value)
                            if m:
                                server = to_datetime(m.group(1), datetime.timezone.utc)
                                local = item.timestamp
                                delta = abs(server - local)
                                item.interpretation = 'Server-side Timestamp: {} | Local Timestamp: {} | ' \
                                                      'Difference: {} [Time Discrepancy]'.format(server, local, delta)
                                parsedItems += 1

            elif item.row_type == 'url' or item.row_type == 'url (archived)':
                for site in url_set:
                    m = re.search(site, item.url)
                    if m:
                        server = to_datetime(m.group(1), datetime.timezone.utc)
                        local = item.timestamp
                        delta = abs(server - local)
                        item.interpretation = 'Server-side Timestamp: {} | Local Timestamp: {} | ' \
                                              'Difference: {} [Time Discrepancy]'.format(server, local, delta)
                        parsedItems += 1

    # Description of what the plugin did
    return "{} differences parsed".format(parsedItems)
