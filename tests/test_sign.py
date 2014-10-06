# -*- coding: utf-8 -*-

import mock
import pytest

import hmac
import json
import time
import base64
import hashlib

import furl

from cloudstorm import sign
from cloudstorm import errors
from cloudstorm import settings

from tests import utils


payload = utils.make_payload()

key = 'secret'


def test_order_recursive():
    unordered = {
        'a': 1,
        'b': {
            'd': 2,
            'c': 3,
        }
    }
    ordered = sign.order_recursive(unordered)
    assert ordered.keys() == ['a', 'b']
    assert ordered['b'].keys() == ['c', 'd']


def test_serialize_payload():
    payload = sign.order_recursive(utils.make_payload())
    expected = base64.b64encode(json.dumps(payload))
    assert expected == sign.serialize_payload(payload)


def test_unserialize_payload():
    message = sign.serialize_payload(payload)
    expected = json.loads(base64.b64decode(message))
    assert expected == payload


def test_sign():
    message = sign.serialize_payload(payload)
    signature = hmac.new(
        key=key,
        msg=message,
        digestmod=hashlib.sha256,
    ).hexdigest()
    assert sign.sign(payload, key, hashlib.sha256) == (message, signature)


def tests_verify_valid():
    message, signature = sign.sign(payload, key, hashlib.sha1)
    assert sign.verify(signature, payload, key, hashlib.sha1)


def test_verify_invalid():
    message, signature = sign.sign(payload, key, hashlib.sha1)
    signature = signature[::-1]
    assert not sign.verify(signature, payload, key, hashlib.sha1)


def test_build_upload_url(monkeypatch):
    # The epoch happened 10 seconds ago
    mock_time = mock.Mock()
    mock_time.return_value = 10
    monkeypatch.setattr(time, 'time', mock_time)
    size = 1024 * 1024
    content_type = 'application/json'
    start_url = 'http://localhost:5000/start/'
    finish_url = 'http://localhost:5000/finish/'
    url, payload = sign.build_upload_url(
        '/urls/upload/',
        size,
        content_type,
        'http://localhost:5000/start/',
        'http://localhost:5000/finish/',
    )
    message, signature = sign.sign(
        payload,
        settings.UPLOAD_HMAC_SECRET,
        settings.UPLOAD_HMAC_DIGEST,
    )
    expected_url = furl.furl(settings.DOMAIN)
    expected_url.port = settings.PORT
    expected_url.path = '/urls/upload/'
    expected_url.args.update({
        'message': message,
        'signature': signature,
    })
    assert url == expected_url.url
    assert payload['size'] == size
    assert payload['type'] == content_type
    assert payload['startUrl'] == start_url
    assert payload['finishUrl'] == finish_url
    assert payload['expires'] == settings.UPLOAD_EXPIRATION_SECONDS + 10


def test_build_hook_body():
    payload = {'status': 'success'}
    _, signature = sign.sign(
        payload,
        settings.WEBHOOK_HMAC_SECRET,
        settings.WEBHOOK_HMAC_DIGEST,
    )
    body = sign.build_hook_body(payload)
    body_data = json.loads(body)
    assert body_data['payload'] == payload
    assert body_data['signature'] == signature


def test_get_payload_from_request():
    payload, message, signature = utils.make_signed_payload()
    url = furl.furl('http://localhost:5000/')
    url.args['message'] = message
    url.args['signature'] = signature
    request = utils.make_request(uri=url.url)
    retrieved_payload, retrieve_signature = sign.get_payload_from_request(request)
    assert payload == retrieved_payload
    assert signature == retrieve_signature


def test_get_payload_from_request_not_found():
    request = utils.make_request(uri='http://localhost:5000/')
    with pytest.raises(errors.SignedUrlError):
        sign.get_payload_from_request(request)


def test_get_payload_from_request_invalid():
    request = utils.make_request(uri='http://localhost:5000/?message=invalid')
    with pytest.raises(errors.SignedUrlError):
        sign.get_payload_from_request(request)


def test_verify_signature_valid():
    payload, message, signature = utils.make_signed_payload()
    request = utils.make_request()
    sign.verify_signature(request, payload, signature)


def test_verify_signature_invalid():
    payload, message, signature = utils.make_signed_payload()
    signature = signature[::-1]
    request = utils.make_request()
    with pytest.raises(errors.SignedUrlError):
        sign.verify_signature(request, payload, signature)


def test_verify_expiration_valid(monkeypatch):
    payload, message, signature = utils.make_signed_payload(expires=15)
    request = utils.make_request()
    # The epoch happened 10 seconds ago
    mock_time = mock.Mock()
    mock_time.return_value = 10
    monkeypatch.setattr(time, 'time', mock_time)
    sign.verify_expiration(request, payload, signature)


def test_verify_expiration_valid_if_none_specified():
    payload, message, signature = utils.make_signed_payload(expires=None)
    request = utils.make_request()
    sign.verify_expiration(request, payload, signature)


def test_verify_expiration_invalid(monkeypatch):
    payload, message, signature = utils.make_signed_payload(expires=5)
    request = utils.make_request()
    # The epoch happened 10 seconds ago
    mock_time = mock.Mock()
    mock_time.return_value = 10
    monkeypatch.setattr(time, 'time', mock_time)
    with pytest.raises(errors.SignedUrlError):
        sign.verify_expiration(request, payload, signature)


def test_verify_size_valid():
    payload, message, signature = utils.make_signed_payload(size=1024)
    request = utils.make_request(headers={'Content-Length': 1024})
    sign.verify_size(request, payload, signature)


def test_verify_size_valid_if_none_specified():
    payload, message, signature = utils.make_signed_payload(size=None)
    request = utils.make_request(headers={'Content-Length': 1025})
    sign.verify_size(request, payload, signature)


def test_verify_size_invalid():
    payload, message, signature = utils.make_signed_payload(size=1025)
    request = utils.make_request(headers={'Content-Length': 1024})
    with pytest.raises(errors.SignedUrlError):
        sign.verify_size(request, payload, signature)


def test_verify_content_type_valid():
    payload, message, signature = utils.make_signed_payload(type='application/json')
    request = utils.make_request(headers={'Content-Type': 'application/json'})
    sign.verify_content_type(request, payload, signature)


def test_verify_content_type_valid_if_none_specified():
    payload, message, signature = utils.make_signed_payload(type=None)
    request = utils.make_request(headers={'Content-Type': 'application/octet-stream'})
    sign.verify_content_type(request, payload, signature)


def test_verify_content_type_invalid():
    payload, message, signature = utils.make_signed_payload(type='application/json')
    request = utils.make_request(headers={'Content-Type': 'application/octet-stream'})
    with pytest.raises(errors.SignedUrlError):
        sign.verify_content_type(request, payload, signature)


@pytest.fixture
def Verifiers():
    return sign._Verifiers()


def test_verifiers_init(Verifiers):
    assert Verifiers.verifiers == []


def test_verifiers_register(Verifiers):
    verifier = lambda *a: None
    Verifiers.register(verifier)
    assert verifier in Verifiers.verifiers


def test_verifiers_verify(Verifiers):
    mock_verifiers = [mock.Mock() for _ in range(3)]
    for verifier in mock_verifiers:
        Verifiers.register(verifier)
    Verifiers.verify(1, 2, 3)
    for verifier in mock_verifiers:
        verifier.assert_called_once_with(1, 2, 3)

