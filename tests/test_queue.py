#!/usr/bin/env python
# encoding: utf-8

import mock
import pytest
import httpretty
import pytest_httpretty
import re

from tests import utils
from tests.fixtures import file_content, temp_file

import os
import json
import socket
import hashlib
import httplib
import datetime
import tempfile

from celery.result import AsyncResult

from cloudstorm import sign
from cloudstorm import errors
from cloudstorm import settings

# Patch settings for testing
settings.CELERY_ALWAYS_EAGER = True
settings.SENTRY_DSN = None

from cloudstorm import errors
from cloudstorm import storage
from cloudstorm.queue import tasks


payload, message, signature = utils.make_signed_payload(sign.upload_signer)

archive_name = '132c6c'


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
        'object': hashlib.sha256(file_content).hexdigest(),
    }
    return mock_object


@pytest.fixture
def mock_parity_container(mock_file_object, monkeypatch):
    container = mock.Mock()
    mock_file_object.md5 = mock.MagicMock()
    mock_file_object.md5.__eq__.return_value = True
    mock_file_object.md5.__ne__.return_value = False
    container.get_or_upload_file.return_value = (mock_file_object, True)
    monkeypatch.setattr(storage.parity_container_proxy, '_result', container)
    return container


@pytest.fixture
def mock_storage_container(mock_file_object, monkeypatch):
    container = mock.Mock()
    container.get_or_upload_file.return_value = (mock_file_object, True)
    monkeypatch.setattr(storage.storage_container_proxy, '_result', container)
    return container


@pytest.fixture
def mock_vault(monkeypatch):
    vault = mock.Mock()
    vault.name = settings.GLACIER_VAULT
    vault.upload_archive.return_value = archive_name
    monkeypatch.setattr(storage.vault_proxy, '_result', vault)
    return vault


@pytest.fixture
def mock_finish_url():
    httpretty.register_uri(
        'PUT',
        payload['finishUrl'],
        status=httplib.OK,
        body='ack',
    )


@pytest.fixture
def mock_archive_url():
    httpretty.register_uri(
        'PUT',
        payload['archiveUrl'],
        status=httplib.OK,
        body='ack',
    )


def check_upload_file_call(mock_storage_container, temp_file):
    hashes = tasks.get_hashes(
        temp_file,
        settings.UPLOAD_HASH_CHUNK_SIZE,
        [settings.UPLOAD_PRIMARY_HASH],
    )
    assert mock_storage_container.get_or_upload_file.called
    call = mock_storage_container.get_or_upload_file.call_args_list[0]
    assert call[0][0].name == temp_file.name
    assert call[0][1] == hashes[settings.UPLOAD_PRIMARY_HASH.__name__]


def check_hook_signature(request, payload):
    signature = request.headers.get(settings.SIGNATURE_HEADER_KEY)
    assert sign.webhook_signer.verify_payload(signature, payload)


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


def test_get_countdown():
    assert tasks.get_countdown(3, 30, 60, 1) == 30
    assert tasks.get_countdown(3, 2, 60, 2) == 16
    assert tasks.get_countdown(3, 2, 10, 2) == 10


def test_serialize_object(mock_file_object):
    serialized = tasks.serialize_object(
        mock_file_object,
        md5=mock_file_object.md5,
    )
    expected_location = mock_file_object.location
    expected_location['worker_url'] = sign.get_root_url()
    expected_location['worker_host'] = socket.gethostname()
    expected_metadata = {
        'size': mock_file_object.size,
        'date_modified': mock_file_object.date_modified.isoformat(),
        'content_type': mock_file_object.content_type,
        'md5': mock_file_object.md5,
    }
    assert serialized['location'] == expected_location
    assert serialized['metadata'] == expected_metadata


def test_parity_create_files_created(file_content, temp_file, mock_file_object, mock_parity_container, monkeypatch):
    mock_push_files = mock.Mock()
    monkeypatch.setattr(tasks, '_push_parity_files', mock_push_files)
    serialized = tasks.serialize_object(mock_file_object)
    file_path = tasks.copy_completed_file(temp_file.name, serialized['location']['object'])
    tasks._parity_create_files((serialized, True))
    assert mock_push_files.called
    file_paths = mock_push_files.call_args[0][0]
    for file_path in file_paths:
        assert os.path.exists(file_path)
    expected_main_file = os.path.join(
        settings.FILE_PATH_COMPLETE,
        '{0}.par2'.format(serialized['location']['object']),
    )
    assert expected_main_file in file_paths


def test_parity_create_files_not_created(file_content, temp_file, mock_file_object, mock_parity_container, monkeypatch):
    mock_push_files = mock.Mock()
    monkeypatch.setattr(tasks, '_push_parity_files', mock_push_files)
    serialized = tasks.serialize_object(mock_file_object)
    file_path = tasks.copy_completed_file(temp_file.name, serialized['location']['object'])
    completed_files = os.listdir(settings.FILE_PATH_COMPLETE)
    tasks._parity_create_files((serialized, False))
    assert not mock_push_files.called
    assert completed_files == os.listdir(settings.FILE_PATH_COMPLETE)


def test_parity_create_files_error(file_content, temp_file, mock_file_object, mock_parity_container, monkeypatch):
    monkeypatch.setattr('cloudstorm.utils.subprocess.call', mock.Mock(return_value=1))
    serialized = tasks.serialize_object(mock_file_object)
    with pytest.raises(errors.ParchiveError):
        tasks._parity_create_files((serialized, True))


def test_push_parity_file(temp_file, mock_parity_container):
    tasks._push_parity_file(temp_file.name)
    _, expected_name = os.path.split(temp_file.name)
    assert mock_parity_container.get_or_upload_file.called
    call = mock_parity_container.get_or_upload_file.call_args[0]
    assert call[0].name == temp_file.name
    assert call[1] == expected_name
    assert not os.path.exists(temp_file.name)


def test_push_parity_file_md5_mismatch(temp_file, mock_file_object, mock_parity_container):
    mock_file_object.md5 = 'wrong-hash'
    with pytest.raises(errors.HashMismatchError):
        tasks._push_parity_file(temp_file.name)
    _, expected_name = os.path.split(temp_file.name)
    assert mock_parity_container.get_or_upload_file.called
    call = mock_parity_container.get_or_upload_file.call_args[0]
    assert call[0].name == temp_file.name
    assert call[1] == expected_name
    assert os.path.exists(temp_file.name)


def test_push_file_main(file_content, temp_file, mock_storage_container, monkeypatch):
    serialized, created = tasks._push_file_main(temp_file.name)
    md5 = hashlib.md5(file_content).hexdigest()
    primary_hash = settings.UPLOAD_PRIMARY_HASH(file_content).hexdigest()
    assert serialized['metadata']['md5'] == md5
    check_upload_file_call(mock_storage_container, temp_file)
    destination = os.path.join(settings.FILE_PATH_COMPLETE, primary_hash)
    assert os.path.exists(destination)
    assert not os.path.exists(temp_file.name)


def test_push_file_main_md5_mismatch(file_content, temp_file, mock_file_object, mock_storage_container, monkeypatch):
    mock_file_object.md5 = 'wrong-hash'
    with pytest.raises(errors.HashMismatchError):
        tasks._push_file_main(temp_file.name)
    check_upload_file_call(mock_storage_container, temp_file)
    primary_hash = settings.UPLOAD_PRIMARY_HASH(file_content).hexdigest()
    destination = os.path.join(settings.FILE_PATH_COMPLETE, primary_hash)
    assert not os.path.exists(destination)
    assert os.path.exists(temp_file.name)


def test_push_file_main_error_retry(temp_file, mock_storage_container):
    # Mock `AsyncResult` to handle error retrieval
    error = TypeError('not my type')
    mock_storage_container.get_or_upload_file.side_effect = error
    container = tasks._push_file_main.apply_async((temp_file.name,))
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_storage_container.get_or_upload_file.call_count == expected_tries


@pytest.mark.httpretty
def test_send_hook_retry(mock_finish_url):
    tasks._send_hook_retry({'topping': 'peppers'}, payload['finishUrl'])
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
    obj = {
        'location': {'service': 'cloud'},
        'metadata': {'size': 1024},
    }
    resp = tasks._push_file_complete((obj, True), payload, signature)
    assert resp.status_code == httplib.OK
    request_body = json.loads(resp.request.body)
    check_hook_signature(resp.request, request_body)
    assert request_body['status'] == 'success'
    assert request_body['uploadSignature'] == signature


@mock.patch('cloudstorm.queue.tasks.requests')
def test_push_file_complete_error_retry(mock_requests):
    mock_requests.put.side_effect = Exception
    obj = {
        'location': {'service': 'cloud'},
        'metadata': {'size': 1024},
    }
    resp = tasks._push_file_complete.apply_async(((obj, False), payload, signature))
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


def test_push_file_archive_created(mock_file_object, mock_vault, monkeypatch):
    mock_push_complete = mock.Mock()
    monkeypatch.setattr(tasks, '_push_archive_complete', mock_push_complete)
    serialized = tasks.serialize_object(mock_file_object)
    tasks._push_file_archive((serialized, True), payload, signature)
    file_name = serialized['location']['object']
    file_path = os.path.join(settings.FILE_PATH_COMPLETE, file_name)
    mock_vault.upload_archive.assert_called_with(file_path, description=file_name)
    metadata = {
        'vault': settings.GLACIER_VAULT,
        'archive': archive_name,
    }
    mock_push_complete.delay.assert_called_with(metadata, payload, signature)


def test_push_file_archive_not_created(mock_file_object, mock_vault):
    serialized = tasks.serialize_object(mock_file_object)
    resp = tasks._push_file_archive((serialized, False), payload, signature)
    assert not mock_vault.upload_archive.called
    assert resp is None


@pytest.mark.httpretty
def test_push_archive_complete(mock_archive_url):
    metadata = {
        'vault': settings.GLACIER_VAULT,
        'archive': archive_name,
    }
    resp = tasks._push_archive_complete(metadata, payload, signature)
    assert resp.status_code == httplib.OK
    # Success callback sends correct hook payload
    request_body = json.loads(resp.request.body)
    check_hook_signature(resp.request, request_body)
    assert request_body['status'] == 'success'
    assert request_body['uploadSignature'] == signature
    assert request_body['metadata'] == metadata


@mock.patch('cloudstorm.queue.tasks.requests')
def test_push_file_error_retry(mock_requests, monkeypatch):
    error = Exception('disaster')
    monkeypatch.setattr(AsyncResult, 'result', error)
    mock_requests.put.side_effect = Exception
    resp = tasks._push_file_error.apply_async((None, payload, signature))
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_requests.put.call_count == expected_tries


@pytest.mark.httpretty
def test_push_file_integration_success(temp_file, mock_storage_container, mock_parity_container, mock_vault, mock_finish_url, mock_archive_url):
    result = tasks.push_file(payload, signature, temp_file.name).get()
    check_upload_file_call(mock_storage_container, temp_file)
    # Success callback sends correct hook payload
    request = httpretty.last_request()
    request_body = json.loads(request.body)
    check_hook_signature(request, request_body)
    assert request_body['status'] == 'success'
    assert request_body['uploadSignature'] == signature


@pytest.mark.httpretty
def test_push_file_integration_push_error(temp_file, mock_storage_container, mock_finish_url, monkeypatch):
    # Mock `AsyncResult` to handle error retrieval
    error = TypeError('not my type')
    mock_storage_container.get_or_upload_file.side_effect = error
    monkeypatch.setattr(AsyncResult, 'result', error)
    container = tasks.push_file(payload, signature, temp_file.name)
    # Task chain returns error raised during primary task
    result = container.get(propagate=False)
    assert result == error
    # Primary task is retried the right number of times
    expected_tries = settings.UPLOAD_RETRY_ATTEMPTS + 1
    assert mock_storage_container.get_or_upload_file.call_count == expected_tries
    # Error callback sends correct hook payload
    request = httpretty.last_request()
    request_body = json.loads(request.body)
    check_hook_signature(request, request_body)
    assert request_body['status'] == 'error'
    assert 'not my type' in request_body['reason']
    assert request_body['uploadSignature'] == signature
