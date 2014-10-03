# -*- coding: utf-8 -*-

import mock
import pytest
import httpretty
import pytest_httpretty

from tests import utils

import json
import hashlib
import httplib
import tempfile

from celery.result import AsyncResult

from cloudstorm import settings

# Run Celery tasks synchronously for testing
settings.CELERY_ALWAYS_EAGER = True
from cloudstorm.queue import tasks


payload, message, signature = utils.make_signed_payload()


@pytest.fixture
def file_content():
    return utils.build_random_string(1024)


@pytest.yield_fixture
def temp_file(file_content):
    with tempfile.NamedTemporaryFile() as file_pointer:
        file_pointer.write(file_content)
        file_pointer.seek(0)
        yield file_pointer


@pytest.fixture
def mock_container(monkeypatch):
    container = mock.Mock()
    monkeypatch.setattr(tasks.container_proxy, '_result', container)
    return container


@pytest.fixture
def mock_finish_url():
    httpretty.register_uri(
        'PUT',
        payload['urls']['finish'],
        status=httplib.OK,
        body='ack',
    )


def check_upload_file_call(mock_container, temp_file):
    hash_str = tasks.get_hash(
        temp_file,
        settings.UPLOAD_HASH_CHUNK_SIZE,
        settings.UPLOAD_PRIMARY_HASH,
    )
    assert mock_container.upload_file.called
    call = mock_container.upload_file.call_args_list[0]
    assert call[0][0].name == temp_file.name
    assert call[0][1] == hash_str


def test_get_hash(file_content, temp_file):
    expected = hashlib.sha1(file_content).hexdigest()
    for chunk_size in [128, 1024, 2048]:
        temp_file.seek(0)
        observed = tasks.get_hash(temp_file, chunk_size, hashlib.sha1)
        assert expected == observed


def test_push_file_main(temp_file, mock_container, monkeypatch):
    tasks.push_file_main(temp_file.name)
    check_upload_file_call(mock_container, temp_file)


@pytest.mark.httpretty
def test_push_file_complete(mock_finish_url):
    resp = tasks.push_file_complete(None, payload, signature)
    assert resp.status_code == httplib.OK
    request_body = json.loads(resp.request.body)
    assert request_body['status'] == 'success'
    assert request_body['signature'] == signature


@pytest.mark.httpretty
def test_push_file_error(mock_finish_url, monkeypatch):
    error = Exception('disaster')
    monkeypatch.setattr(AsyncResult, 'result', error)
    resp = tasks.push_file_error(None, payload, signature)
    assert resp.status_code == httplib.OK
    # Success callback sends correct hook payload
    request_body = json.loads(resp.request.body)
    assert request_body['status'] == 'error'
    assert 'disaster' in request_body['reason']
    assert request_body['signature'] == signature


@pytest.mark.httpretty
def test_push_file_integration_success(temp_file, mock_container, mock_finish_url):
    result = tasks.push_file(payload, signature, temp_file.name).get()
    check_upload_file_call(mock_container, temp_file)
    # Success callback sends correct hook payload
    request = httpretty.last_request()
    request_body = json.loads(request.body)
    assert request_body['status'] == 'success'
    assert request_body['signature'] == signature


@pytest.mark.httpretty
def test_push_file_integration_error(temp_file, mock_container, mock_finish_url, monkeypatch):
    # Mock `AsyncResult` to handle error retrieval
    error = TypeError('not my type')
    mock_container.upload_file.side_effect = error
    monkeypatch.setattr(AsyncResult, 'result', error)
    container = tasks.push_file(payload, signature, temp_file.name)
    # Task chain returns error raised during primary task
    result = container.get(propagate=False)
    assert result == error
    # Primary task is retried the right number of times
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_container.upload_file.call_count == expected_tries
    # Error callback sends correct hook payload
    request = httpretty.last_request()
    request_body = json.loads(request.body)
    assert request_body['status'] == 'error'
    assert 'not my type' in request_body['reason']
    assert request_body['signature'] == signature

