###################################################################################################
#
# chrome_extensions.py
#   Adds the name and description of each Chrome extension found to the Interpretation field
#
# Plugin Author: Ryan Benson (ryan@hindsig.ht)
#
###################################################################################################

import re

# Config
friendlyName = "Chrome Extension Names"
description = "Adds the name and description of each Chrome extension found to the Interpretation field"
artifactTypes = ("url", "local storage", "indexeddb")
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20240428"
parsedItems = 0


def plugin(analysis_session=None):
    if analysis_session is None:
        return

    extension_re = re.compile(r'^chrome-extension(_|://)([a-z]{32})')
    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_artifacts:
        if not item.row_type.startswith(artifactTypes):
            continue

        if item.interpretation is not None:
            continue

        m = re.search(extension_re, item.url)
        if m:
            try:
                for ext in analysis_session.installed_extensions['data']:
                    if ext.ext_id == m.group(2):
                        item.interpretation = f'{ext.name} ({ext.description}) [Chrome Extension]'
                        parsedItems += 1
            except:
                pass

    for item in analysis_session.parsed_storage:
        if not item.row_type.startswith(artifactTypes):
            continue

        if item.interpretation is not None:
            continue

        m = re.search(extension_re, item.origin)
        if m:
            try:
                for ext in analysis_session.installed_extensions['data']:
                    if ext.ext_id == m.group(2):
                        item.interpretation = f'{ext.name} ({ext.description}) [Chrome Extension]'
                        parsedItems += 1
            except:
                pass

    # Description of what the plugin did
    return f'{parsedItems} extension URLs parsed'
