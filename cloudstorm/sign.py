# -*- coding: utf-8 -*-

import hmac
import json
import time
import base64
import collections

import furl

from cloudstorm import errors
from cloudstorm import settings


def order_recursive(data):
    """Recursively sort keys of input data and all its nested dictionaries.
    Used to ensure consistent ordering of JSON payloads.
    """
    if isinstance(data, dict):
        return collections.OrderedDict(
            sorted(
                (
                    (key, order_recursive(value))
                    for key, value in data.items()
                ),
                key=lambda item: item[0]
            )
        )
    if isinstance(data, list):
        return [
            order_recursive(value)
            for value in data
        ]
    return data


def serialize_payload(payload):
    ordered = order_recursive(payload)
    return base64.b64encode(json.dumps(ordered))


def unserialize_payload(message):
    payload = json.loads(base64.b64decode(message))
    return order_recursive(payload)


class Signer(object):

    def __init__(self, secret, digest):
        assert callable(digest)
        self.secret = secret
        self.digest = digest

    def sign_message(self, message):
        return hmac.new(
            key=self.secret,
            digestmod=self.digest,
            msg=message,
        ).hexdigest()

    def sign_payload(self, payload):
        message = serialize_payload(payload)
        signature = self.sign_message(message)
        return message, signature

    def verify_message(self, signature, message):
        expected = self.sign_message(message)
        return signature == expected

    def verify_payload(self, signature, payload):
        _, expected = self.sign_payload(payload)
        return signature == expected


url_signer = Signer(settings.URLS_HMAC_SECRET, settings.URLS_HMAC_DIGEST)
upload_signer = Signer(settings.UPLOAD_HMAC_SECRET, settings.UPLOAD_HMAC_DIGEST)
webhook_signer = Signer(settings.WEBHOOK_HMAC_SECRET, settings.WEBHOOK_HMAC_DIGEST)


def build_upload_url(signer, base_url, size, content_type, start_url, finish_url, extra=None):
    extra = extra or {}
    payload = {
        'size': size,
        'type': content_type,
        'startUrl': start_url,
        'finishUrl': finish_url,
        'expires': time.time() + settings.UPLOAD_EXPIRATION_SECONDS,
        'extra': extra,
    }
    message, signature = signer.sign_payload(payload)
    url = furl.furl()
    url.scheme = settings.SCHEME
    url.host = settings.DOMAIN
    url.port = settings.PORT
    url.path = base_url
    url.args.update(dict(
        message=message,
        signature=signature,
    ))
    return url.url, payload


def build_hook_body(signer, payload):
    _, signature = signer.sign_payload(payload)
    return signature, json.dumps(payload)


class _Verifiers(object):

    def __init__(self):
        self.verifiers = []

    def register(self, verifier):
        self.verifiers.append(verifier)
        return verifier

    def verify(self, request, payload, signature):
        for verifier in self.verifiers:
            verifier(request, payload, signature)


Verifiers = _Verifiers()


@Verifiers.register
def verify_signature(request, payload, signature):
    if not upload_signer.verify_payload(signature, payload):
        raise errors.SignedUrlError('Invalid HMAC signature')


@Verifiers.register
def verify_expiration(request, payload, signature):
    expires = payload.get('expires', None)
    if expires and expires < time.time():
        raise errors.SignedUrlError('Signed URL is expired')


@Verifiers.register
def verify_size(request, payload, signature):
    size = payload.get('size', None)
    if size:
        content_length = request.headers.get('Content-Length')
        try:
            content_length = float(content_length)
        except (TypeError, ValueError):
            raise errors.SignedUrlError('Invalid Content-Length')
    if size and size != content_length:
        raise errors.SignedUrlError('File has incorrect content size')


@Verifiers.register
def verify_content_type(request, payload, signature):
    type_ = payload.get('type', None)
    if type_ and type_ != request.headers.get('Content-Type'):
        raise errors.SignedUrlError('File has incorrect content type')

