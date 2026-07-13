###################################################################################################
#
# google_searches.py
#   Extracts parameters from Google search URLs
#
# Plugin Author: Ryan Benson (ryan@hindsig.ht)
#
###################################################################################################

# Config
friendlyName = 'Google Searches'
description = 'Extracts parameters from Google search URLs'
artifactTypes = ('url',)
remoteLookups = 0
browser = 'Chrome'
browserVersion = 1
version = '20160912'
parsedItems = 0


def plugin(analysis_session=None):
    import re
    import urllib.request, urllib.parse, urllib.error
    if analysis_session is None:
        return

    google_re = re.compile(r'^http(s)?://www\.google(\.[A-Za-z]{2,3})?(\.com)?(\.[A-Za-z]{2,3})?/(search\?|webhp\?|#q)(.*)$')
    extract_parameters_re = re.compile(r'(.+?)=(.+)')
    qdr_re = re.compile(r'(s|n|h|d|w|m|y)(\d{0,9})')
    tbs_qdr_re = re.compile(r'qdr:(s|n|h|d|w|m|y)(\d{0,9})')
    tbs_cd_re = re.compile(r'cd_min:(\d{1,2}/\d{1,2}/\d{2,4}),cd_max:(\d{1,2}/\d{1,2}/\d{2,4})')
    global parsedItems
    parsedItems = 0

    time_abbr = {'s': 'second', 'n': 'minute', 'h': 'hour', 'd': 'day', 
                 'w': 'week', 'm': 'month', 'y': 'year'}

    for item in analysis_session.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            m = re.search(google_re, item.url)
            if m:
                parameters = {}
                raw_parameters = m.group(6)

                if m.group(5) == '#q':
                    raw_parameters = 'q' + raw_parameters

                #Parse out search parameters
                # TODO: Figure out # vs & separators
                raw_parameters = raw_parameters.replace('#q=', '&q=')  # Replace #q with &q so it will split correctly
                for pair in raw_parameters.split('&'):          # Split the query on the '&' delimiter
                    # print pair
                    p = re.search(extract_parameters_re, pair)  # Split each parameter on the first '='
                    try:
                        parameters[p.group(1)] = urllib.parse.unquote_plus(p.group(2))  # Put parameter name and value in hash
                    except AttributeError:
                        pass

                if 'q' in parameters:  # 'q' parameter must be present for rest of parameters to be parsed
                    derived = 'Searched for "{}" [ '.format(parameters['q'])

                    if 'pws' in parameters:
                        derived += 'Google personalization turned '
                        derived += ('on | ' if parameters['pws'] == '1' else 'off | ')

                    if 'num' in parameters:
                        derived += 'Showing %s results per page' % (parameters['num'])

                    if 'filter' in parameters:
                        derived += 'Omitted/Similar results filter '
                        derived += ('on | ' if parameters['filter'] == '1' else 'off | ')

                    if 'btnl' in parameters:
                        derived += '"I\'m Feeling Lucky" search '
                        derived += ('on | ' if parameters['btnl'] == '1' else 'off | ')

                    if 'safe' in parameters:
                        derived += 'SafeSearch: {} | '.format(parameters['safe'])

                    if 'as_qdr' in parameters:
                        qdr = re.search(qdr_re, parameters['as_qdr'])
                        if qdr:
                            if qdr.group(1) and qdr.group(2):
                                derived += 'Results in the past {} {}s | '.format(qdr.group(2), time_abbr[qdr.group(1)])
                            elif qdr.group(1):
                                derived += 'Results in the past {} | '.format(time_abbr[qdr.group(1)])

                    if 'tbs' in parameters:
                        tbs_qdr = re.search(tbs_qdr_re, parameters['tbs'])
                        if tbs_qdr:
                            if tbs_qdr.group(1) and tbs_qdr.group(2):
                                derived += 'Results in the past {} {}s | '.format(tbs_qdr.group(2), time_abbr[tbs_qdr.group(1)])
                            elif tbs_qdr.group(1):
                                derived += 'Results in the past {} | '.format(time_abbr[tbs_qdr.group(1)])
                        elif parameters['tbs'][:3].lower() == 'cdr':
                            tbs_cd = re.search(tbs_cd_re, parameters['tbs'])
                            if tbs_cd:
                                derived += 'Results in custom range {} - {} | '.format(tbs_cd.group(1), tbs_cd.group(2))
                        elif parameters['tbs'][:3].lower() == 'dfn':
                            derived += 'Dictionary definition | '
                        elif parameters['tbs'][:3].lower() == 'img':
                            derived += 'Sites with images | '
                        elif parameters['tbs'][:4].lower() == 'clir':
                            derived += 'Translated sites | '
                        elif parameters['tbs'][:2].lower() == 'li':
                            derived += 'Verbatim results | '
                        elif parameters['tbs'][:3].lower() == 'vid':
                            derived += 'Video results | '
                        elif parameters['tbs'][:3].lower() == 'nws':
                            derived += 'News results | '
                        elif parameters['tbs'][:3].lower() == 'sbd':
                            derived += 'Sorted by date | '

                    if 'bih' in parameters and 'biw' in parameters:
                        derived += 'Browser screen {}x{} | '.format(parameters['biw'], parameters['bih'])

                    if 'pq' in parameters:
                        if parameters['pq'] != parameters['q']:  # Don't include PQ if same as Q to save space
                            derived += 'Previous query: "{}" | '.format(parameters['pq'])

                    if 'oq' in parameters:
                        if parameters['oq'] != parameters['q']:  # Don't include OQ if same as Q to save space
                            if 'aq' in parameters:
                                aq_re = re.compile(r'^\d$')
                                ordinals = ['first', 'second', 'third', 'fourth', 'fifth',
                                            'sixth', 'seventh', 'eighth', 'ninth']
                                if re.search(aq_re, parameters['aq']):
                                    derived += 'Typed "{}" before clicking on the {} suggestion | ' \
                                               .format(parameters['oq'], ordinals[int(parameters['aq'])])
                            else:
                                derived += 'Typed "{}" before clicking on a suggestion | '.format(parameters['oq'])

                    if 'as_sitesearch' in parameters:
                        derived += 'Search only {} | '.format(parameters['as_sitesearch'])

                    if 'as_filetype' in parameters:
                        derived += 'Show only {} files | '.format(parameters['as_filetype'])

                    if 'sourceid' in parameters:
                        derived += 'Using {}  | '.format(parameters['sourceid'])

                    # if u'ei' in parameters:
                    #     derived += u'Using %s  | ' % (parameters[u'sourceid'])

                    if derived[-2:] == '[ ':
                        derived = derived[:-2]
                    elif derived[-3:] == ' | ':
                        derived = derived[:-3] + ']'

                    item.interpretation = derived
                parsedItems += 1

    # Description of what the plugin did
    return '{} searches parsed'.format(parsedItems)
