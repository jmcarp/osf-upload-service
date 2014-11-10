#!/usr/bin/env python
# encoding: utf-8

import mock
import pytest

import os
import json
import time
import httplib
import functools

import furl

from werkzeug.local import LocalProxy

from tornado import gen
from tornado import web
from tornado import testing
from tornado import httputil
from tornado import concurrent
from tornado import httpclient

from cloudstorm import sign
from cloudstorm import settings

# Patch settings for testing
settings.CELERY_ALWAYS_EAGER = True
settings.SENTRY_DSN = None

from cloudstorm.app import main
from cloudstorm.app.handlers import upload

from tests import utils
from tests.fixtures import file_content, temp_file


TEST_FILE_PATH = os.path.join(settings.FILE_PATH_PENDING, 'test')
START_UPLOAD_URL = 'http://localhost:5000/start/'
PING_URL = 'http://localhost:5000/ping/'
PAYLOAD = {
    'startUrl': 'http://httpbin.org/start',
    'cachedUrl': 'http://httpbin.org/cached',
    'finishUrl': 'http://httpbin.org/finish',
    'pingUrl': 'http://httpbin.org/ping',
}
SIGNATURE = 'hancock'


def test_verify_file_size_valid(temp_file):
    assert upload.verify_file_size(temp_file, 1024)


def test_verify_file_size_invalid(temp_file):
    assert upload.verify_file_size(temp_file, 1025) is False


def test_delete_file(temp_file):
    upload.delete_file(temp_file)
    assert not os.path.exists(temp_file.name)


def test_delete_file_none():
    upload.delete_file(None)


def test_delete_file_deleted(temp_file):
    os.remove(temp_file.name)
    upload.delete_file(temp_file)


@pytest.fixture
def mock_http_client(monkeypatch):
    mock_client = mock.Mock()
    monkeypatch.setattr(upload, 'http_client', mock_client)
    return mock_client


def test_ping(mock_http_client):
    upload.ping(PING_URL, SIGNATURE)
    signature, body = sign.build_hook_body(
        sign.webhook_signer,
        {'uploadSignature': SIGNATURE},
    )
    mock_http_client.fetch.assert_called_with(
        PING_URL,
        method='POST',
        body=body,
        headers={
            'Content-Type': 'application/json',
            settings.SIGNATURE_HEADER_KEY: signature,
        },
        callback=upload.ping_callback,
    )


class TestWebHooks(testing.AsyncTestCase):

    @testing.gen_test
    def test_start_upload_success(self):
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CREATED):
            resp = yield upload.start_upload(START_UPLOAD_URL, SIGNATURE, PAYLOAD)
        assert resp.code == 201

    @testing.gen_test
    def test_start_upload_error(self):
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CONFLICT):
            with pytest.raises(web.HTTPError) as excinfo:
                resp = yield upload.start_upload(START_UPLOAD_URL, SIGNATURE, PAYLOAD)
            assert excinfo.value.status_code == 409


def make_producer(content=None, error=None):
    """Make a lazy content producer that optionally throws an error. Used to
    simulate a client disconnection during streaming requests.

    :param list content: Optional list of values to yield
    :param Exception error: Optional error to raise after yielding values
    """
    content = content or []
    @gen.coroutine
    def producer(write):
        for item in content:
            yield write(item)
        if error:
            raise error
    return producer


def count_cached_files():
    return len(os.listdir(settings.FILE_PATH_PENDING))


def file_count_increment(increment):
    """Decorator factory asserting that the number of files in the cache path
    has changed by `increment`.
    """
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            nfiles = count_cached_files()
            ret = func(*args, **kwargs)
            assert count_cached_files() == nfiles + increment
            return ret
        return wrapped
    return wrapper


class TestUploadUrlHandler(testing.AsyncHTTPTestCase):

    def get_app(self):
        return main.make_app()

    def setUp(self):
        super(TestUploadUrlHandler, self).setUp()
        self.size = 1024
        self.content_type = 'application/json'
        self.start_url = 'http://localhost:5000/start'
        self.cached_url = 'http://localhost:5000/cached'
        self.finish_url = 'http://localhost:5000/finish'
        self.ping_url = 'http://localhost:5000/ping'

    @testing.gen_test
    def test_options(self):
        resp = yield self.http_client.fetch(
            self.get_url('/files/'),
            method='OPTIONS',
        )
        assert resp.code == 204
        assert resp.headers['Access-Control-Allow-Origin'] == '*'
        assert resp.headers['Access-Control-Allow-Methods'] == 'PUT'

    @mock.patch('time.time')
    @testing.gen_test
    def test_create_upload_url(self, mock_time):
        mock_time.return_value = 15
        url, _ = sign.build_upload_url(
            sign.upload_signer,
            '/files/',
            **dict(
                size=self.size,
                type=self.content_type,
                startUrl=self.start_url,
                cachedUrl=self.cached_url,
                finishUrl=self.finish_url,
                pingUrl=self.ping_url,
            )
        )
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {
                'size': self.size,
                'type': self.content_type,
                'startUrl': self.start_url,
                'cachedUrl': self.cached_url,
                'finishUrl': self.finish_url,
                'pingUrl': self.ping_url,
            },
        )
        resp = yield self.http_client.fetch(
            self.get_url('/urls/upload/'),
            method='POST',
            body=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )
        resp_data = json.loads(resp.body)
        assert resp_data['status'] == 'success'
        assert resp_data['url'] == url

    @mock.patch('time.time')
    @testing.gen_test
    def test_create_upload_url_extra_params(self, mock_time):
        mock_time.return_value = 15
        url, _ = sign.build_upload_url(
            sign.upload_signer,
            '/files/',
            **dict(
                size=self.size,
                type=self.content_type,
                startUrl=self.start_url,
                cachedUrl=self.cached_url,
                finishUrl=self.finish_url,
                pingUrl=self.ping_url,
                extra={'user': 'freddie'},
            )
        )
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {
                'size': self.size,
                'type': self.content_type,
                'startUrl': self.start_url,
                'cachedUrl': self.cached_url,
                'finishUrl': self.finish_url,
                'pingUrl': self.ping_url,
                'extra': {'user': 'freddie'},
            },
        )
        resp = yield self.http_client.fetch(
            self.get_url('/urls/upload/'),
            method='POST',
            body=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )
        resp_data = json.loads(resp.body)
        assert resp_data['status'] == 'success'
        assert resp_data['url'] == url

    @testing.gen_test
    def test_create_upload_url_invalid_size(self):
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {
                'size': 'sobig',
                'type': self.content_type,
                'startUrl': self.start_url,
                'finishUrl': self.finish_url,
            },
        )
        with pytest.raises(httpclient.HTTPError) as excinfo:
            resp = yield self.http_client.fetch(
                self.get_url('/urls/upload/'),
                method='POST',
                body=body,
                headers={
                    'Content-Type': 'application/json',
                    settings.SIGNATURE_HEADER_KEY: signature,
                },
            )
        assert excinfo.value.code == 400

    @testing.gen_test
    def test_create_upload_url_invalid_urls(self):
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {
                'size': 'sobig',
                'type': self.content_type,
                'startUrl': 'invalidurl',
                'finishUrl': self.finish_url,
            },
        )
        with pytest.raises(httpclient.HTTPError) as excinfo:
            resp = yield self.http_client.fetch(
                self.get_url('/urls/upload/'),
                method='POST',
                body=body,
                headers={
                    'Content-Type': 'application/json',
                    settings.SIGNATURE_HEADER_KEY: signature,
                },
            )
        assert excinfo.value.code == 400


class TestDownloadUrlHandler(testing.AsyncHTTPTestCase):

    def setUp(self):
        super(TestDownloadUrlHandler, self).setUp()
        self.location = {
            'service': 'cloud',
            'container': 'albums',
            'object': 'the-works',
        }

    def get_app(self):
        return main.make_app()

    def check_mock_client(self, mock_client, filename, **kwargs):
        expected = dict(
            method='GET',
            container=self.location['container'],
            obj=self.location['object'],
            filename=filename,
        )
        expected.update(kwargs)
        mock_client.generate_signed_url.assert_called_with(
            settings.DOWNLOAD_EXPIRATION_SECONDS,
            **expected
        )

    @mock.patch('cloudstorm.storage.client_proxy._result')
    @testing.gen_test
    def test_get_download_url_with_filename(self, mock_client):
        mock_signed_url = 'http://secret.com/'
        mock_client.generate_signed_url.return_value = mock_signed_url
        url = self.get_url('/urls/download/')
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {
                'location': self.location,
                'filename': 'the-miracle.mp3',
            },
        )
        resp = yield self.http_client.fetch(
            url,
            method='POST',
            body=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )
        assert resp.code == 200
        resp_data = json.loads(resp.body)
        assert resp_data['url'] == mock_signed_url
        self.check_mock_client(mock_client, filename=u'the-miracle.mp3')

    @mock.patch('cloudstorm.storage.client_proxy._result')
    @testing.gen_test
    def test_get_download_url_with_unicode_filename(self, mock_client):
        mock_signed_url = 'http://secret.com/'
        mock_client.generate_signed_url.return_value = mock_signed_url
        url = self.get_url('/urls/download/')
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {
                'location': self.location,
                'filename': u'killer-qüeen.mp3',
            },
        )
        resp = yield self.http_client.fetch(
            url,
            method='POST',
            body=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )
        assert resp.code == 200
        resp_data = json.loads(resp.body)
        assert resp_data['url'] == mock_signed_url
        self.check_mock_client(mock_client, filename=u'killer-qüeen.mp3')

    @mock.patch('cloudstorm.storage.client_proxy._result')
    @testing.gen_test
    def test_get_download_url_without_filename(self, mock_client):
        mock_signed_url = 'http://secret.com/'
        mock_client.generate_signed_url.return_value = mock_signed_url
        url = self.get_url('/urls/download/')
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {'location': self.location},
        )
        resp = yield self.http_client.fetch(
            url,
            method='POST',
            body=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )
        assert resp.code == 200
        resp_data = json.loads(resp.body)
        assert resp_data['url'] == mock_signed_url
        self.check_mock_client(mock_client, filename=None)

    @testing.gen_test
    def test_get_download_url_invalid_location(self):
        url = self.get_url('/urls/download/')
        signature, body = sign.build_hook_body(
            sign.url_signer,
            {'location': {'service':  'cloud'}},
        )
        with pytest.raises(httpclient.HTTPError) as excinfo:
            resp = yield self.http_client.fetch(
                url,
                method='POST',
                body=body,
                headers={
                    'Content-Type': 'application/json',
                    settings.SIGNATURE_HEADER_KEY: signature,
                },
            )
        assert excinfo.value.code == 400


class TestUploadHandler(testing.AsyncHTTPTestCase):

    def get_app(self):
        return main.make_app()

    def get_upload_url(self, message, signature):
        url = furl.furl(self.get_url('/files/'))
        url.args['message'] = message
        url.args['signature'] = signature
        return url.url

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(TEST_FILE_PATH)
        except OSError:
            pass

    @file_count_increment(1)
    @mock.patch('cloudstorm.queue.tasks.send_hook')
    @mock.patch('cloudstorm.queue.tasks.push_file')
    @mock.patch('cloudstorm.app.handlers.upload.build_file_path')
    @testing.gen_test
    def test_upload_file(self, mock_build_path, mock_push_file, mock_send_hook):
        mock_build_path.return_value = TEST_FILE_PATH
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        body = utils.build_random_string(length)
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CREATED):
            resp = yield self.http_client.fetch(
                url,
                method='PUT',
                headers={'Content-Type': content_type},
                body=body,
            )
        assert body == open(TEST_FILE_PATH).read()
        mock_send_hook.assert_called_with(
            {
                'status': 'success',
                'uploadSignature': signature,
            },
            payload['cachedUrl'],
        )

    @mock.patch('cloudstorm.queue.tasks.push_file')
    @mock.patch('cloudstorm.app.handlers.upload.get_time')
    @mock.patch('cloudstorm.app.handlers.upload.ping')
    @mock.patch('cloudstorm.app.handlers.upload.build_file_path')
    @testing.gen_test
    def test_upload_file_no_ping_if_no_delay(self, mock_build_path, mock_ping, mock_time, mock_push_file):
        # Freeze time at epoch
        mock_time.return_value = 0
        mock_build_path.return_value = TEST_FILE_PATH
        producer = make_producer(content=['foo', 'bar', 'baz'])
        length = 9
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CREATED):
            resp = yield self.http_client.fetch(
                url,
                method='PUT',
                headers={'Content-Type': content_type, 'Content-Length': '9'},
                body_producer=producer,
            )
        assert not mock_ping.called

    @mock.patch('cloudstorm.queue.tasks.push_file')
    @mock.patch('cloudstorm.app.handlers.upload.ping')
    @mock.patch('cloudstorm.app.handlers.upload.get_time')
    @mock.patch('cloudstorm.app.handlers.upload.build_file_path')
    @testing.gen_test
    def test_upload_file_sends_ping_on_delay(self, mock_build_path, mock_time, mock_ping, mock_push_file):
        future = concurrent.Future()
        future._result = 'pong'
        future._set_done()
        mock_ping.return_value = future
        chunk_size = 65536
        chunks = 3
        # Time advances by debounce interval on each call
        def get_time():
            value = 0
            while True:
                yield value
                value += settings.PING_DEBOUNCE + 1
        mock_time.side_effect = get_time()
        mock_build_path.return_value = TEST_FILE_PATH
        length = chunk_size * chunks
        body = utils.build_random_string(length)
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CREATED):
            resp = yield self.http_client.fetch(
                url,
                method='PUT',
                headers={'Content-Type': content_type},
                body=body,
            )
        mock_ping.assert_called_with(payload['pingUrl'], signature)
        assert len(mock_ping.mock_calls) == chunks + 1

    @file_count_increment(0)
    @testing.gen_test
    def test_upload_file_invalid_signature_fails(self):
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature[::-1])
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CREATED):
            with pytest.raises(httpclient.HTTPError) as excinfo:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={'Content-Type': content_type},
                    body=utils.build_random_string(length),
                )
            assert excinfo.value.code == 400

    @file_count_increment(0)
    @testing.gen_test
    def test_upload_file_start_upload_error_fails(self):
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CONFLICT):
            with pytest.raises(httpclient.HTTPError) as excinfo:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={'Content-Type': content_type},
                    body=utils.build_random_string(length),
                )
            assert excinfo.value.code == 409

    @file_count_increment(0)
    @testing.gen_test
    def test_upload_file_start_upload_app_times_out(self):
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(upload.http_client, 'PUT', status=599):
            with pytest.raises(httpclient.HTTPError) as excinfo:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={'Content-Type': content_type},
                    body=utils.build_random_string(length),
                )
            assert excinfo.value.code == 408

    @mock.patch('cloudstorm.queue.tasks.send_hook')
    @file_count_increment(0)
    @testing.gen_test
    def test_upload_client_disconnects_calls_connection_closed(self, mock_send_hook):
        producer = make_producer(
            content=['about', 'to', 'crash'],
            error=ValueError('told you')
        )
        length = None
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CREATED):
            with pytest.raises(ValueError) as excinfo:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={
                        'Content-Type': content_type,
                    },
                    body_producer=producer,
                )
        mock_send_hook.assert_called_with(
            {
                'status': 'error',
                'reason': upload.MESSAGES['INTERRUPTED'],
                'uploadSignature': signature,
            },
            payload['finishUrl'],
        )

    @mock.patch('cloudstorm.queue.tasks.send_hook')
    @file_count_increment(0)
    @testing.gen_test
    def test_upload_file_spoofed_content_length(self, mock_send_hook):
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            sign.upload_signer,
            size=length,
            type=content_type,
        )
        producer = make_producer([utils.build_random_string(length / 2)])
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(upload.http_client, 'PUT', status=httplib.CREATED):
            try:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={
                        'Content-Type': content_type,
                        'Content-Length': str(length),
                    },
                    body_producer=producer,
                )
            except httputil.HTTPOutputError:
                pass
        mock_send_hook.assert_called_with(
            {
                'status': 'error',
                'reason': upload.MESSAGES['INTERRUPTED'],
                'uploadSignature': signature,
            },
            payload['finishUrl'],
        )
