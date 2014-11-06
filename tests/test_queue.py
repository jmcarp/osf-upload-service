#!/usr/bin/env python
# encoding: utf-8

import mock
import pytest
import httpretty
import pytest_httpretty

from tests import utils
from tests.fixtures import file_content, temp_file

import json
import hashlib
import httplib
import datetime
import tempfile

from celery.result import AsyncResult

from cloudstorm import sign
from cloudstorm import settings

# Patch settings for testing
settings.CELERY_ALWAYS_EAGER = True
settings.SENTRY_DSN = None

from cloudstorm.queue import tasks
from cloudstorm import storage


payload, message, signature = utils.make_signed_payload(sign.upload_signer)


@pytest.fixture
def mock_file_object(file_content):
    mock_object = mock.Mock()
    mock_object.size = 1024
    mock_object.date_modified = datetime.datetime.utcnow()
    mock_object.content_type = 'application/json'
    mock_object.md5 = hashlib.md5(file_content).hexdigest()
    mock_object.location = {
        'service': 'cloudfiles',
        'container': 'queencontainer',
        'object': 'albums/night-at-the-opera.mp3',
    }
    return mock_object


@pytest.fixture
def mock_container(mock_file_object, monkeypatch):
    container = mock.Mock()
    container.get_or_upload_file.return_value = mock_file_object
    monkeypatch.setattr(storage.container_proxy, '_result', container)
    return container


@pytest.fixture
def mock_finish_url():
    httpretty.register_uri(
        'PUT',
        payload['finishUrl'],
        status=httplib.OK,
        body='ack',
    )


def check_upload_file_call(mock_container, temp_file):
    hashes = tasks.get_hashes(
        temp_file,
        settings.UPLOAD_HASH_CHUNK_SIZE,
        [settings.UPLOAD_PRIMARY_HASH],
    )
    assert mock_container.get_or_upload_file.called
    call = mock_container.get_or_upload_file.call_args_list[0]
    assert call[0][0].name == temp_file.name
    assert call[0][1] == hashes[settings.UPLOAD_PRIMARY_HASH.__name__]


def check_hook_signature(request, payload):
    signature = request.headers.get(settings.SIGNATURE_HEADER_KEY)
    assert sign.upload_signer.verify_payload(signature, payload)


def test_get_hashes(file_content, temp_file):
    md5 = hashlib.md5(file_content).hexdigest()
    sha256 = hashlib.sha256(file_content).hexdigest()
    for chunk_size in [128, 1024, 2048]:
        temp_file.seek(0)
        hashes = tasks.get_hashes(
            temp_file,
            chunk_size,
            [hashlib.md5, hashlib.sha256],
        )
        assert hashes[hashlib.md5.__name__] == md5
        assert hashes[hashlib.sha256.__name__] == sha256


def test_push_file_main(file_content, temp_file, mock_container, monkeypatch):
    serialized = tasks._push_file_main(temp_file.name)
    md5 = hashlib.md5(file_content).hexdigest()
    assert serialized['metadata']['md5'] == md5
    check_upload_file_call(mock_container, temp_file)


def test_push_file_main_error_retry(temp_file, mock_container):
    # Mock `AsyncResult` to handle error retrieval
    error = TypeError('not my type')
    mock_container.get_or_upload_file.side_effect = error
    container = tasks._push_file_main.apply_async((temp_file.name,))
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_container.get_or_upload_file.call_count == expected_tries


@pytest.mark.httpretty
def test_send_hook_retry(mock_finish_url):
    tasks._send_hook_retry({'topping': 'peppers'}, payload)
    request = httpretty.last_request()
    request_body = json.loads(request.body)
    check_hook_signature(request, request_body)
    assert request_body['topping'] == 'peppers'


@mock.patch('cloudstorm.queue.tasks.requests')
def test_send_hook_retry_error_retry(mock_requests):
    mock_requests.put.side_effect = Exception
    tasks._send_hook_retry.apply_async(({'topping': 'peppers'}, payload))
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_requests.put.call_count == expected_tries


@pytest.mark.httpretty
def test_push_file_complete(mock_finish_url):
    response = {
        'location': {'service': 'cloud'},
        'metadata': {'size': 1024},
    }
    resp = tasks._push_file_complete(response, payload, signature)
    assert resp.status_code == httplib.OK
    request_body = json.loads(resp.request.body)
    check_hook_signature(resp.request, request_body)
    assert request_body['status'] == 'success'
    assert request_body['uploadSignature'] == signature


@mock.patch('cloudstorm.queue.tasks.requests')
def test_push_file_complete_error_retry(mock_requests):
    mock_requests.put.side_effect = Exception
    response = {
        'location': {'service': 'cloud'},
        'metadata': {'size': 1024},
    }
    resp = tasks._push_file_complete.apply_async((response, payload, signature))
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_requests.put.call_count == expected_tries


@pytest.mark.httpretty
def test_push_file_error(mock_finish_url, monkeypatch):
    error = Exception('disaster')
    monkeypatch.setattr(AsyncResult, 'result', error)
    resp = tasks._push_file_error(None, payload, signature)
    assert resp.status_code == httplib.OK
    # Success callback sends correct hook payload
    request_body = json.loads(resp.request.body)
    check_hook_signature(resp.request, request_body)
    assert request_body['status'] == 'error'
    assert 'disaster' in request_body['reason']
    assert request_body['uploadSignature'] == signature


@mock.patch('cloudstorm.queue.tasks.requests')
def test_push_file_error_retry(mock_requests, monkeypatch):
    error = Exception('disaster')
    monkeypatch.setattr(AsyncResult, 'result', error)
    mock_requests.put.side_effect = Exception
    resp = tasks._push_file_error.apply_async((None, payload, signature))
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_requests.put.call_count == expected_tries


@pytest.mark.httpretty
def test_push_file_integration_success(temp_file, mock_container, mock_finish_url):
    result = tasks.push_file(payload, signature, temp_file.name).get()
    check_upload_file_call(mock_container, temp_file)
    # Success callback sends correct hook payload
    request = httpretty.last_request()
    request_body = json.loads(request.body)
    check_hook_signature(request, request_body)
    assert request_body['status'] == 'success'
    assert request_body['uploadSignature'] == signature


@pytest.mark.httpretty
def test_push_file_integration_push_error(temp_file, mock_container, mock_finish_url, monkeypatch):
    # Mock `AsyncResult` to handle error retrieval
    error = TypeError('not my type')
    mock_container.get_or_upload_file.side_effect = error
    monkeypatch.setattr(AsyncResult, 'result', error)
    container = tasks.push_file(payload, signature, temp_file.name)
    # Task chain returns error raised during primary task
    result = container.get(propagate=False)
    assert result == error
    # Primary task is retried the right number of times
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_container.get_or_upload_file.call_count == expected_tries
    # Error callback sends correct hook payload
    request = httpretty.last_request()
    request_body = json.loads(request.body)
    check_hook_signature(request, request_body)
    assert request_body['status'] == 'error'
    assert 'not my type' in request_body['reason']
    assert request_body['uploadSignature'] == signature
