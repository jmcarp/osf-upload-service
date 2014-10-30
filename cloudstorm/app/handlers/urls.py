#!/usr/bin/env python
# encoding: utf-8

import json
import httplib
import urlparse
import functools

from webargs import Arg
from webargs.tornadoparser import parser

from tornado import web

from raven.contrib.tornado import SentryMixin

from cloudstorm import sign
from cloudstorm import storage
from cloudstorm import settings


def verify_signature(signer):
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(self, *args, **kwargs):
            parsed = parser.parse(hmac_args, self.request)
            payload = json.loads(self.request.body)
            valid = signer.verify_payload(
                parsed[settings.SIGNATURE_HEADER_KEY],
                payload,
            )
            if not valid:
                raise web.HTTPError(
                    httplib.BAD_REQUEST,
                    reason='Invalid signature',
                )
            return func(self, *args, **kwargs)
        return wrapped
    return wrapper


verify_signature_urls = verify_signature(sign.url_signer)


def validate_size(value):
    return value > 0


def validate_url(value):
    parsed = urlparse.urlparse(value)
    return all([
        getattr(parsed, part)
        for part in ['scheme', 'netloc']
    ])


hmac_args = {
    settings.SIGNATURE_HEADER_KEY: Arg(str, required=True, target='headers'),
}

upload_url_args = {
    'size': Arg(int, required=True, validate=validate_size),
    'type': Arg(unicode),
    'startUrl': Arg(unicode, required=True, validate=validate_url),
    'finishUrl': Arg(unicode, required=True, validate=validate_url),
    'extra': Arg(),
}


class UploadUrlHandler(SentryMixin, web.RequestHandler):

    @verify_signature_urls
    def post(self):
        args = parser.parse(upload_url_args, self.request, targets=('json',))
        base_url = self.reverse_url('upload_file')
        url, _ = sign.build_upload_url(
            sign.upload_signer,
            base_url,
            args['size'],
            args['type'],
            args['startUrl'],
            args['finishUrl'],
            args['extra'],
        )
        self.write({
            'status': 'success',
            'url': url,
        })


def validate_location(value):
    return 'container' in value and 'object' in value


download_url_args = {
    'location': Arg(dict, required=True, validate=validate_location),
    'filename': Arg(unicode, default=None),
}


def get_download_url(location, filename=None):
    client = storage.client_proxy.get()
    return client.generate_signed_url(
        settings.DOWNLOAD_EXPIRATION_SECONDS,
        method='GET',
        container=location['container'],
        obj=location['object'],
        filename=filename,
    )


class DownloadUrlHandler(SentryMixin, web.RequestHandler):

    @verify_signature_urls
    def post(self):
        args = parser.parse(download_url_args, self.request, targets=('json',))
        url = get_download_url(**args)
        self.write({'url': url})
