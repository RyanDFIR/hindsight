"""The log level is selectable, and only Hindsight's own loggers follow it.

Before this, both entry points hardcoded `level=logging.DEBUG` on `basicConfig`,
which is the *root* logger: every run wrote a full debug trace, there was no way
to ask for less, and every dependency was turned up to debug along with us.
"""

import io
import logging
import os
import tempfile
import unittest

from pyhindsight.logging_setup import (
    DEFAULT_LOG_LEVEL,
    LOG_LEVELS,
    configure_logging,
    normalize_log_level,
)


class _FreshLogging:
    """Give each case the root logger a new process would start with."""

    def __enter__(self):
        root = logging.getLogger()
        self._handlers = list(root.handlers)
        self._root_level = root.level
        for handler in self._handlers:
            root.removeHandler(handler)
        self._levels = {name: logging.getLogger(name).level
                        for name in ('pyhindsight', '__main__', 'urllib3.connectionpool')}
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'hindsight.log')
        return self

    def __exit__(self, *exc):
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        for handler in self._handlers:
            root.addHandler(handler)
        root.setLevel(self._root_level)
        for name, level in self._levels.items():
            logging.getLogger(name).setLevel(level)
        return False

    def emit_one_of_each(self):
        logging.getLogger('pyhindsight.browsers.webbrowser').debug('OURS-debug')
        logging.getLogger('pyhindsight.analysis').info('OURS-info')
        logging.getLogger('pyhindsight.analysis').warning('OURS-warning')
        logging.getLogger('pyhindsight.analysis').error('OURS-error')
        logging.getLogger('__main__').info('MAIN-info')
        logging.getLogger('urllib3.connectionpool').debug('THIRDPARTY-debug')
        logging.getLogger('urllib3.connectionpool').warning('THIRDPARTY-warning')
        for handler in logging.getLogger().handlers:
            handler.flush()

    def read(self):
        return io.open(self.path, encoding='utf-8').read()


class TestNormalizeLogLevel(unittest.TestCase):
    def test_every_documented_name_maps_to_a_level(self):
        for name, expected in LOG_LEVELS.items():
            self.assertEqual(expected, normalize_log_level(name))

    def test_case_and_surrounding_space_are_tolerated(self):
        self.assertEqual(logging.DEBUG, normalize_log_level('  DeBuG '))

    def test_an_unknown_or_missing_value_falls_back_to_the_default(self):
        # The value can arrive from a web form; a bad one must not take the run down.
        for value in (None, '', 'verbose', 'DEBUGGING', 5):
            self.assertEqual(LOG_LEVELS[DEFAULT_LOG_LEVEL], normalize_log_level(value))


class TestConfigureLogging(unittest.TestCase):
    def test_the_default_drops_debug_and_keeps_info(self):
        with _FreshLogging() as env:
            configure_logging(env.path, DEFAULT_LOG_LEVEL, extra_loggers=('__main__',))
            env.emit_one_of_each()
            body = env.read()
        self.assertNotIn('OURS-debug', body)
        self.assertIn('OURS-info', body)
        self.assertIn('OURS-warning', body)
        self.assertIn('MAIN-info', body)

    def test_debug_is_still_reachable(self):
        # The detail is worth having when diagnosing a parse, which is the reason it
        # should be selectable rather than always on.
        with _FreshLogging() as env:
            configure_logging(env.path, 'debug', extra_loggers=('__main__',))
            env.emit_one_of_each()
            body = env.read()
        self.assertIn('OURS-debug', body)
        self.assertIn('OURS-info', body)

    def test_a_stricter_level_drops_info_as_well(self):
        with _FreshLogging() as env:
            configure_logging(env.path, 'warning', extra_loggers=('__main__',))
            env.emit_one_of_each()
            body = env.read()
        self.assertNotIn('OURS-info', body)
        self.assertIn('OURS-warning', body)
        self.assertIn('OURS-error', body)

    def test_error_keeps_only_errors(self):
        with _FreshLogging() as env:
            configure_logging(env.path, 'error', extra_loggers=('__main__',))
            env.emit_one_of_each()
            body = env.read()
        self.assertNotIn('OURS-warning', body)
        self.assertIn('OURS-error', body)

    def test_dependencies_stay_at_warning_even_when_we_ask_for_debug(self):
        # basicConfig configures the root logger, so the old hardcoded DEBUG applied
        # to every third-party library too.
        with _FreshLogging() as env:
            configure_logging(env.path, 'debug', extra_loggers=('__main__',))
            env.emit_one_of_each()
            body = env.read()
        self.assertNotIn('THIRDPARTY-debug', body)
        self.assertIn('THIRDPARTY-warning', body)

    def test_a_second_run_takes_the_new_level(self):
        # The web UI serves many runs in one process, and basicConfig is a no-op once
        # the root logger has handlers.
        with _FreshLogging() as env:
            configure_logging(env.path, 'debug', extra_loggers=('__main__',))
            configure_logging(env.path, 'warning', extra_loggers=('__main__',))
            env.emit_one_of_each()
            body = env.read()
        self.assertNotIn('OURS-info', body)
        self.assertIn('OURS-warning', body)

    def test_the_log_is_written_as_utf8(self):
        # The default is the platform's, cp1252 on Windows, and logging swallows
        # handler errors, so a mangled character was lost silently.
        with _FreshLogging() as env:
            configure_logging(env.path, 'info', extra_loggers=('__main__',))
            logging.getLogger('pyhindsight.analysis').info('page title: 中文 — café')
            for handler in logging.getLogger().handlers:
                handler.flush()
            body = env.read()
        self.assertIn('中文', body)
        self.assertIn('café', body)


if __name__ == '__main__':
    unittest.main()
