#!/usr/bin/env python
# encoding: utf-8

import os
import json
import uuid
import httplib
import logging
import urlparse
import functools

from webargs import Arg
from webargs.tornadoparser import parser

from tornado.ioloop import IOLoop
from tornado import web, gen, httpclient, httpserver

from cloudstorm import sign
from cloudstorm import utils
from cloudstorm import errors
from cloudstorm import storage
from cloudstorm import settings
from cloudstorm.queue import tasks


logger = logging.getLogger(__name__)

http_client = httpclient.AsyncHTTPClient()


CORS_ACCEPT_HEADERS = [
    'Content-Type',
    'Cache-Control',
    'X-Requested-With',
]


MESSAGES = {
    'INVALID_LENGTH': 'Unexpected content length',
    'INTERRUPTED': 'Connection interrupted',
}


def verify_upload(request):
    """Verify signed URL and upload request.

    :param request: Tornado request object
    :raise: `web.HTTPError` if signature or upload is invalid
    """
    try:
        payload, signature = sign.get_payload_from_request(request)
        sign.Verifiers.verify(request, payload, signature)
    except errors.SignedUrlError as error:
        raise web.HTTPError(
            httplib.BAD_REQUEST,
            reason=error.message,
        )
    return payload, signature


@gen.coroutine
def start_upload(url, signature, payload):
    """Notify metadata application that file upload has started. Catch and
    reraise errors.

    :param str url: Webhook start URL
    :param str signature: Signature from signed URL
    :param dict payload: Payload from signed URL
    :raise: `web.HTTPError` if error received from application
    """
    signature, body = sign.build_hook_body(
        sign.webhook_signer,
        {
            'uploadSignature': signature,
            'uploadPayload': payload,
        },
    )
    try:
        response = yield http_client.fetch(
            url,
            method='PUT',
            body=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )
        raise gen.Return(response)
    except httpclient.HTTPError as error:
        logger.error('Begin-upload request rejected. Aborting upload.')
        logger.exception(error)
        raise web.HTTPError(error.code)


def verify_file_size(file_pointer, content_length):
    """Verify that file has expected content length.

    :param file file_pointer: File object
    :param int content_length: Expected length
    :return: File has expected length
    """
    if file_pointer is None:
        return False
    file_pointer.seek(0, os.SEEK_END)
    size = file_pointer.tell()
    return size == content_length


def delete_file(file_pointer):
    try:
        os.remove(file_pointer.name)
    except (AttributeError, OSError):
        pass


def send_fail_hook(payload, signature, reasons=None):
    """Notify calling application that upload has failed.

    :param dict payload:
    :param str signature:
    :param list reasons: Error messages
    """
    reasons = reasons or []
    reason = '; '.join(reasons)
    signature, body = sign.build_hook_body(
        sign.webhook_signer,
        {
            'status': 'error',
            'reason': reason,
            'uploadSignature': signature,
        },
    )
    http_client.fetch(
        payload['finishUrl'],
        method='PUT',
        body=body,
        headers={
            'Content-Type': 'application/json',
            settings.SIGNATURE_HEADER_KEY: signature,
        },
    )


def build_file_path(request, payload):
    """Build path to save a cached file.
    """
    return os.path.join(
        settings.FILE_CACHE_PATH,
        str(uuid.uuid4())
    )


def int_or_none(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def validate_size(value):
    return value > 0


def validate_url(value):
    parsed = urlparse.urlparse(value)
    return all([
        getattr(parsed, part)
        for part in ['scheme', 'netloc']
    ])


upload_url_args = {
    'size': Arg(int, required=True, validate=validate_size),
    'type': Arg(unicode),
    'startUrl': Arg(unicode, required=True, validate=validate_url),
    'finishUrl': Arg(unicode, required=True, validate=validate_url),
    'extra': Arg(),
}


hmac_args = {
    settings.SIGNATURE_HEADER_KEY: Arg(str, required=True, target='headers'),
}


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


class UploadUrlHandler(web.RequestHandler):

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


class DownloadUrlHandler(web.RequestHandler):

    @verify_signature_urls
    def post(self):
        args = parser.parse(download_url_args, self.request, targets=('json',))
        url = get_download_url(**args)
        self.write({'url': url})


@web.stream_request_body
class UploadHandler(web.RequestHandler):

    def setup(self):
        self.payload = None
        self.signature = None
        self.file_path = None
        self.file_pointer = None
        self.content_length = int_or_none(
            self.request.headers.get('Content-Length')
        )
        self.errors = []

    @utils.allow_methods(['put'])
    @gen.coroutine
    def prepare(self):
        """Verify signed URL and notify metadata application of upload start.
        If either check fails, cancel upload.
        """
        self.setup()
        self.payload, self.signature = verify_upload(self.request)
        yield start_upload(self.payload['startUrl'], self.signature, self.payload)
        self.file_path = build_file_path(self.request, self.payload)
        self.file_pointer = open(self.file_path, 'wb')
        content_length_text = int_or_none(
            self.request.headers.get('Content-Length')
        )

    @utils.allow_methods(['put'])
    def data_received(self, chunk):
        """Write data to disk.

        :param str chunk: Chunk of request body
        """
        self.file_pointer.write(chunk)

    def set_default_headers(self):
        self.set_header('Access-Control-Allow-Origin', '*')

    def options(self):
        self.set_header('Access-Control-Allow-Headers', ', '.join(CORS_ACCEPT_HEADERS))
        self.set_header('Access-Control-Allow-Methods', 'PUT'),
        self.set_status(204)

    def put(self):
        """After file is uploaded, push to backend via Celery.
        """
        if not verify_file_size(self.file_pointer, self.content_length):
            self.errors.append(MESSAGES['INVALID_LENGTH'])
            raise web.HTTPError(
                httplib.BAD_REQUEST,
                reason=MESSAGES['INVALID_LENGTH'],
            )
        self.file_pointer.close()
        tasks.push_file(self.payload, self.signature, self.file_path)
        self.write({'status': 'success'})

    def teardown(self):
        """If any errors logged, notify calling application and clear
        temporary file.
        """
        if self.errors:
            logger.error('; '.join(self.errors))
            send_fail_hook(self.payload, self.signature, self.errors)
            delete_file(self.file_pointer)

    @utils.allow_methods(['put'])
    def on_connection_close(self, *args, **kwargs):
        """Log error if connection terminated.
        """
        self.errors.append(MESSAGES['INTERRUPTED'])
        self.teardown()

    @utils.allow_methods(['put'])
    def on_finish(self):
        self.teardown()


def make_app():
    return web.Application(
        [
            web.url(r'/urls/upload/', UploadUrlHandler, name='upload_url'),
            web.url(r'/urls/download/', DownloadUrlHandler, name='download_url'),
            web.url(r'/files/', UploadHandler, name='upload_file'),
        ],
        debug=True,
    )


def main(port, processes):
    app = make_app()
    server = httpserver.HTTPServer(app)
    server.bind(port)
    server.start(processes)
    IOLoop.current().start()


if __name__ == '__main__':
    main(settings.PORT, settings.PROCESSES)
