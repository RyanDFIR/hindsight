"""The web UI refuses requests that did not come from its own pages.

The server binds to loopback, which keeps other machines out but not the pages open
in the operator's own browser. Any site could submit the run form blind, choosing
the input, log and temp paths, and a DNS rebinding page could run an analysis and
read the results back.
"""

import io
import os
import unittest
import urllib.parse
import wsgiref.util

import bottle

import hindsight_gui
import pyhindsight
from hindsight_gui import CSRF_TOKEN, request_rejection

GOOD_HOST = 'localhost:8080'


def call(method, path, host=GOOD_HOST, origin=None, form=None):
    """Send one request to the app; returns (status code, body text)."""
    body = urllib.parse.urlencode(form or {}).encode()
    environ = {
        'REQUEST_METHOD': method,
        'PATH_INFO': path,
        'CONTENT_TYPE': 'application/x-www-form-urlencoded',
        'CONTENT_LENGTH': str(len(body)),
        'wsgi.input': io.BytesIO(body),
    }
    wsgiref.util.setup_testing_defaults(environ)
    environ['HTTP_HOST'] = host
    if origin is not None:
        environ['HTTP_ORIGIN'] = origin
    seen = {}

    def start_response(status, headers, exc_info=None):
        seen['status'] = int(status.split()[0])

    chunks = bottle.default_app()(environ, start_response)
    return seen['status'], b''.join(chunks).decode('utf-8', 'replace')


class RequestRejectionTests(unittest.TestCase):

    def test_get_from_each_loopback_name_is_allowed(self):
        for host in ('localhost:8080', '127.0.0.1:8080', '[::1]:8080', 'LOCALHOST:8080'):
            with self.subTest(host=host):
                self.assertIsNone(request_rejection('GET', host))

    def test_other_hosts_are_refused(self):
        # The rebinding case: the request reaches 127.0.0.1 but names the attacker's host.
        for host in ('attacker.example:8080', 'localhost', 'localhost:9090',
                     'localhost:8080.attacker.example', '', None):
            with self.subTest(host=host):
                self.assertIsNotNone(request_rejection('GET', host))

    def test_post_needs_the_token(self):
        self.assertIsNotNone(request_rejection('POST', GOOD_HOST))
        self.assertIsNotNone(request_rejection('POST', GOOD_HOST, token='wrong'))
        self.assertIsNone(request_rejection('POST', GOOD_HOST, token=CSRF_TOKEN))

    def test_post_from_another_origin_is_refused_even_with_the_token(self):
        for origin in ('http://attacker.example', 'null', 'https://localhost:8080'):
            with self.subTest(origin=origin):
                self.assertIsNotNone(
                    request_rejection('POST', GOOD_HOST, origin=origin, token=CSRF_TOKEN))
        self.assertIsNone(request_rejection(
            'POST', GOOD_HOST, origin='http://localhost:8080', token=CSRF_TOKEN))


class AppTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # main() does this at startup, so the templates resolve.
        cls._template_path = list(bottle.TEMPLATE_PATH)
        bottle.TEMPLATE_PATH.insert(0, os.path.dirname(pyhindsight.__file__))

    @classmethod
    def tearDownClass(cls):
        bottle.TEMPLATE_PATH[:] = cls._template_path

    def test_run_form_carries_the_token(self):
        status, body = call('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(f'name="csrf_token" value="{CSRF_TOKEN}"', body)

    def test_wrong_host_is_refused_before_the_route_runs(self):
        hindsight_gui.analysis_session = None
        status, _ = call('GET', '/', host='attacker.example:8080')
        self.assertEqual(status, 403)
        # '/' creates the session; it must not have been reached.
        self.assertIsNone(hindsight_gui.analysis_session)

    def test_downloads_are_refused_for_a_wrong_host(self):
        for path in ('/jsonl', '/xlsx', '/sqlite', '/results'):
            with self.subTest(path=path):
                status, _ = call('GET', path, host='attacker.example:8080')
                self.assertEqual(status, 403)

    def test_run_without_the_token_is_refused(self):
        status, _ = call('POST', '/run', form={'profile_path': 'x', 'log_path': 'evil.log'})
        self.assertEqual(status, 403)
        self.assertFalse(os.path.exists('evil.log'))

    def test_run_from_another_origin_is_refused(self):
        status, _ = call('POST', '/run', origin='http://attacker.example',
                         form={'profile_path': 'x', 'csrf_token': CSRF_TOKEN})
        self.assertEqual(status, 403)


if __name__ == '__main__':
    unittest.main()
