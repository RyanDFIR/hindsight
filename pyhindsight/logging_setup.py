"""One place to configure logging, so the CLI and the web UI cannot drift apart.

Both entry points used to call `logging.basicConfig(..., level=logging.DEBUG)`
directly. That hardcoded DEBUG for every run, and because `basicConfig`
configures the *root* logger it also turned on debug output for every dependency
that logs.
"""

import logging

# Ordered loosest to strictest, which is the order a dropdown should show.
LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
}

# INFO keeps the per-artifact counts, the skip and failure lines and the
# "Not Parsed items" summary, and drops the directory listings and options dump.
DEFAULT_LOG_LEVEL = 'info'

LOG_FORMAT = '%(asctime)s.%(msecs).03d | %(levelname).01s | %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def normalize_log_level(name):
    """Map a user-supplied level name to a logging constant.

    Falls back to the default rather than raising: the value can arrive from a web
    form, where a bad value should not take the run down.
    """
    if not name:
        return LOG_LEVELS[DEFAULT_LOG_LEVEL]
    return LOG_LEVELS.get(str(name).strip().lower(), LOG_LEVELS[DEFAULT_LOG_LEVEL])


def configure_logging(log_path, level=DEFAULT_LOG_LEVEL, extra_loggers=()):
    """Send Hindsight's log to `log_path` at `level`, and leave dependencies quiet.

    The root logger stays at WARNING and Hindsight's own loggers carry the chosen
    level. Records from a child logger are handed to the root *handler*, which has
    no level of its own, so this filters third-party noise without filtering ours.

    `encoding` is explicit because the default is the platform's, cp1252 on
    Windows, which silently mangles anything outside it. logging swallows handler
    errors, so this never raised; it just lost characters from the record of the
    run.

    Returns the numeric level that was applied.
    """
    level_value = normalize_log_level(level)
    logging.basicConfig(
        filename=log_path, level=logging.WARNING, format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT, encoding='utf-8')
    # basicConfig is a no-op once the root logger has handlers, so set the level
    # directly too -- otherwise a second call (the GUI serves many runs) would
    # leave whatever the first one established.
    logging.getLogger().setLevel(logging.WARNING)
    for name in ('pyhindsight', *extra_loggers):
        logging.getLogger(name).setLevel(level_value)
    return level_value
