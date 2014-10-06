# -*- coding: utf-8 -*-

import mock
import pytest

import os
import json
import time
import httplib
import functools

import furl

from tornado import gen
from tornado import web
from tornado import testing
from tornado import httputil
from tornado import httpclient

from cloudstorm import app
from cloudstorm import sign
from cloudstorm import settings

from tests import utils


TEST_FILE_PATH = '/tmp/test'
START_UPLOAD_URL = 'http://localhost:5000/'
SIGNATURE = 'hancock'


class TestStartUpload(testing.AsyncTestCase):

    @testing.gen_test
    def test_start_upload_success(self):
        with utils.StubFetch(app.http_client, 'PUT', status=httplib.CREATED):
            resp = yield app.start_upload(START_UPLOAD_URL, SIGNATURE)
        assert resp.code == httplib.CREATED

    @testing.gen_test
    def test_start_upload_error(self):
        with utils.StubFetch(app.http_client, 'PUT', status=httplib.CONFLICT):
            with pytest.raises(web.HTTPError) as excinfo:
                resp = yield app.start_upload(START_UPLOAD_URL, SIGNATURE)
            assert excinfo.value.status_code == httplib.CONFLICT


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
    return len(os.listdir(settings.FILE_CACHE_PATH))


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
        return app.make_app()

    def setUp(self):
        super(TestUploadUrlHandler, self).setUp()
        self.size = 1024
        self.content_type = 'application/json'
        self.start_url = 'http://localhost:5000/start/'
        self.finish_url = 'http://localhost:5000/finish/'

    @mock.patch('time.time')
    @testing.gen_test
    def test_create_upload_url(self, mock_time):
        mock_time.return_value = 15
        url, _ = sign.build_upload_url(
            '/urls/upload/',
            self.size,
            self.content_type,
            self.start_url,
            self.finish_url,
        )
        resp = yield self.http_client.fetch(
            self.get_url('/urls/upload/'),
            method='POST',
            headers={'Content-Type': 'application/json'},
            body=json.dumps({
                'size': self.size,
                'type': self.content_type,
                'startUrl': self.start_url,
                'finishUrl': self.finish_url,
            }),
        )
        resp_data = json.loads(resp.body)
        assert resp_data['status'] == 'success'
        assert resp_data['url'] == url

    @testing.gen_test
    def test_create_upload_url_invalid_size(self):
        with pytest.raises(httpclient.HTTPError) as excinfo:
            resp = yield self.http_client.fetch(
                self.get_url('/urls/upload/'),
                method='POST',
                headers={'Content-Type': 'application/json'},
                body=json.dumps({
                    'size': 'sobig',
                    'type': self.content_type,
                    'startUrl': self.start_url,
                    'finishUrl': self.finish_url,
                }),
            )
        assert excinfo.value.code == httplib.BAD_REQUEST

    @testing.gen_test
    def test_create_upload_url_invalid_urls(self):
        with pytest.raises(httpclient.HTTPError) as excinfo:
            resp = yield self.http_client.fetch(
                self.get_url('/urls/upload/'),
                method='POST',
                headers={'Content-Type': 'application/json'},
                body=json.dumps({
                    'size': 'sobig',
                    'type': self.content_type,
                    'startUrl': 'invalidurl',
                    'finishUrl': self.finish_url,
                }),
            )
        assert excinfo.value.code == httplib.BAD_REQUEST


class TestUploadHandler(testing.AsyncHTTPTestCase):

    def get_app(self):
        return app.make_app()

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

    @mock.patch('cloudstorm.app.build_file_path')
    @testing.gen_test
    def test_upload_file(self, mock_build_path):
        mock_build_path.return_value = TEST_FILE_PATH
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        body = utils.build_random_string(length)
        with utils.StubFetch(app.http_client, 'PUT', status=httplib.CREATED):
            resp = yield self.http_client.fetch(
                url,
                method='PUT',
                headers={'Content-Type': content_type},
                body=body,
            )
        assert body == open(TEST_FILE_PATH).read()

    @file_count_increment(0)
    @testing.gen_test
    def test_upload_file_invalid_signature_fails(self):
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature[::-1])
        with utils.StubFetch(app.http_client, 'PUT', status=httplib.CREATED):
            with pytest.raises(httpclient.HTTPError) as excinfo:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={'Content-Type': content_type},
                    body=utils.build_random_string(length),
                )
            assert excinfo.value.code == httplib.BAD_REQUEST

    @file_count_increment(0)
    @testing.gen_test
    def test_upload_file_start_upload_error_fails(self):
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(app.http_client, 'PUT', status=httplib.CONFLICT):
            with pytest.raises(httpclient.HTTPError) as excinfo:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={'Content-Type': content_type},
                    body=utils.build_random_string(length),
                )
            assert excinfo.value.code == httplib.CONFLICT

    @file_count_increment(0)
    @testing.gen_test
    def test_upload_client_disconnects_calls_connection_closed(self):
        producer = make_producer(
            content=['about', 'to', 'crash'],
            error=ValueError('told you')
        )
        length = None
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            size=length,
            type=content_type,
        )
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(app.http_client, 'PUT', status=httplib.CREATED):
            with pytest.raises(ValueError) as excinfo:
                resp = yield self.http_client.fetch(
                    url,
                    method='PUT',
                    headers={
                        'Content-Type': content_type,
                    },
                    body_producer=producer,
                )

    @file_count_increment(0)
    @testing.gen_test
    def test_upload_file_spoofed_content_length(self):
        length = 1024
        content_type = 'application/json'
        payload, message, signature = utils.make_signed_payload(
            size=length,
            type=content_type,
        )
        producer = make_producer([
            utils.build_random_string(length / 2),
        ])
        url = self.get_upload_url(message, signature)
        with utils.StubFetch(app.http_client, 'PUT', status=httplib.CREATED):
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

