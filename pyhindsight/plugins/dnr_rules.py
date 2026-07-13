###################################################################################################
#
# dnr_rules.py
#   Summarizes each declarativeNetRequest dynamic rule (parsed from
#   DNR Extension Rules/<id>/rules.json by get_dnr_extension_rules) into the
#   Interpretation field: the rule's action plus its main condition target.
#
# Plugin Author: Ryan Benson (ryan@hindsig.ht)
#
###################################################################################################

import json

# Config
friendlyName = "DNR Rule Summary"
description = "Summarizes each DNR dynamic rule (action + condition target) into the Interpretation field"
artifactTypes = ("dnr extension rules",)  # row_type set by Chrome.get_dnr_extension_rules
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20260624"
parsedItems = 0


def _summarize_dnr_rule(rule):
    """One-line human summary of a declarativeNetRequest rule (action + main condition
    target). Domain lists are collapsed to a count when long so the summary stays
    readable (uBlock Origin Lite rules can carry thousands of initiatorDomains)."""
    action = rule.get('action') or {}
    a_type = action.get('type', '?')
    summary = a_type
    if a_type == 'redirect':
        redir = action.get('redirect') or {}
        dest = redir.get('url') or redir.get('extensionPath') or redir.get('regexSubstitution')
        if dest:
            summary = f'redirect → {dest}'
    elif a_type == 'modifyHeaders':
        parts = []
        for h in (action.get('requestHeaders') or []):
            parts.append(f"req {h.get('operation')} {h.get('header')}")
        for h in (action.get('responseHeaders') or []):
            parts.append(f"resp {h.get('operation')} {h.get('header')}")
        if parts:
            summary = 'modifyHeaders: ' + '; '.join(parts)

    cond = rule.get('condition') or {}
    target = ''
    if cond.get('urlFilter'):
        target = cond['urlFilter']
    elif cond.get('regexFilter'):
        target = f"re:{cond['regexFilter']}"
    else:
        for key in ('requestDomains', 'initiatorDomains'):
            vals = cond.get(key)
            if vals:
                target = ', '.join(vals) if len(vals) <= 3 else f'{len(vals)} {key}'
                break
    return f'{summary} [{target}]' if target else summary


def plugin(analysis_session=None):
    if analysis_session is None:
        return

    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_extension_data:
        if getattr(item, 'row_type', None) not in artifactTypes:
            continue
        if getattr(item, 'interpretation', None):
            continue
        try:
            rule = json.loads(item.value)
        except (ValueError, TypeError):
            continue
        if not isinstance(rule, dict):
            continue
        item.interpretation = _summarize_dnr_rule(rule)
        parsedItems += 1

    return f'{parsedItems} DNR rules summarized'
