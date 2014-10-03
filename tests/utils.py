# -*- coding: utf-8 -*-

import mock

import time
import random
import string
import httplib

from tornado import web
from tornado import httputil
from tornado import concurrent
from tornado import httpclient
from tornado import http1connection

from cloudstorm import sign
from cloudstorm import settings


def make_payload(**kwargs):
    payload = {
        'size': 1024 * 1024,
        'type': 'application/json',
        'startUrl': 'http://localhost:5000/start/',
        'finishUrl': 'http://localhost:5000/finish/',
        'expires': time.time() + 60,
    }
    payload.update(kwargs)
    return payload


def make_signed_payload(**kwargs):
    payload = make_payload(**kwargs)
    message, signature = sign.sign(
        payload,
        settings.UPLOAD_HMAC_SECRET,
        settings.UPLOAD_HMAC_DIGEST,
    )
    return payload, message, signature


def get_mock_connection():
    mock_connection = mock.Mock(spec=http1connection.HTTP1Connection)
    mock_connection.context = mock.Mock()
    mock_connection.remote_ip = None
    return mock_connection


def make_request(method='GET', uri='', body='', headers=None, connection=None):
    """Create a mock Tornado request object. Adapted from
    https://github.com/sloria/webargs/blob/dev/tests/test_tornadoparser.py
    """
    connection = connection or get_mock_connection()
    content_type = headers.get('Content-Type', u'') if headers else u''
    request = httputil.HTTPServerRequest(
        method=method, uri=uri, body=body, headers=headers,
        connection=connection,
    )
    httputil.parse_body_arguments(
        content_type=content_type,
        body=body.encode('latin-1'),  # Tornado expects bodies to be latin-1
        arguments=request.body_arguments,
        files=request.files
    )
    return request



def make_response(request, status):
    return httpclient.HTTPResponse(request, status)


def make_fetch_future(request, status):
    """Create a `Future` object that resolves to a stubbed `HTTPResponse`.
    """
    future = concurrent.Future()
    if status < 400:
        response = make_response(request, status)
        future.set_result(response)
    else:
        exception = web.HTTPError(status)
        future.set_exception(exception)
    return future


class StubFetch(object):
    """Context manager for stubbing asynchronous HTTP interactions with
    `AsyncHTTPClient`. Patch `AsyncHTTPClient#fetch` to return a `Future` that
    resolves to a stubbed `HTTPResponse`.
    """
    def __init__(self, client, method='GET', url='', body='', headers=None,
                 status=httplib.OK):
        self.client = client
        self._fetch = None
        request = make_request(
            method=method,
            uri=url,
            body=body,
            headers=headers,
        )
        request.url = request.uri
        self.future = make_fetch_future(request, status)

    def __enter__(self):
        stub_fetch = lambda *a, **kw: self.future
        self._fetch, self.client.fetch = self.client.fetch, stub_fetch

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.client.fetch = self._fetch


def build_random_string(nchar):
    return ''.join(random.choice(string.lowercase) for _ in range(nchar))

