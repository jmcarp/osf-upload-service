#!/usr/bin/env python
# encoding: utf-8

import os
import time
import uuid
import httplib
import logging

from webargs import Arg
from webargs.tornadoparser import parser

from tornado import gen
from tornado import web
from tornado import httpclient

from raven.contrib.tornado import SentryMixin

from cloudstorm import sign
from cloudstorm import utils
from cloudstorm import errors
from cloudstorm import settings
from cloudstorm.queue import tasks


logger = logging.getLogger(__name__)

# We can't touch the `IOLoop` until after the Tornado process is forked, so
# we wrap the `AsyncHTTPClient` in a cached proxy. We also pass the
# `force_instance` flag so that the client doesn't share state with the client
# defined by the application tests.
http_client = utils.CachedProxy(
    lambda: httpclient.AsyncHTTPClient(force_instance=True),
)

CORS_ACCEPT_HEADERS = [
    'Content-Type',
    'Cache-Control',
    'X-Requested-With',
]

MESSAGES = {
    'INVALID_LENGTH': 'Unexpected content length',
    'INTERRUPTED': 'Connection interrupted',
}

upload_args = {
    'message': Arg(unicode, required=True),
    'signature': Arg(unicode, required=True),
}


def int_or_none(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def get_time():
    """Get time since epoch. Used to simplify mocking.
    """
    return time.time()


def build_file_path(request, payload):
    """Build path to save a cached file.
    """
    return os.path.join(
        settings.FILE_PATH_PENDING,
        str(uuid.uuid4())
    )


def verify_upload(request):
    """Verify signed URL and upload request.

    :param request: Tornado request object
    :raise: `web.HTTPError` if signature or upload is invalid
    """
    args = parser.parse(upload_args, request, targets=('querystring',))
    payload = get_payload(args['message'])
    signature = args['signature']
    try:
        sign.Verifiers.verify(request, payload, signature)
    except errors.SignedUrlError as error:
        raise web.HTTPError(
            httplib.BAD_REQUEST,
            reason=error.message,
        )
    return payload, signature


# Map non-standard HTTP codes
ERROR_MAP = {
    599: httplib.REQUEST_TIMEOUT,
}


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
        raise web.HTTPError(ERROR_MAP.get(error.code, error.code))


def ping_callback(response):
    """Handle error responses from ping hook.

    :param HTTPResponse response: Response from `fetch`
    """
    if response.error:
        logger.error('Ping request rejected.')
        logger.exception(response.error)


def ping(url, signature):
    """Notify calling application that upload request is still alive.

    :param str url: Ping hook URL
    :param str signature: Signature from signed URL
    """
    signature, body = sign.build_hook_body(
        sign.webhook_signer,
        {'uploadSignature': signature},
    )
    http_client.fetch(
        url,
        method='POST',
        body=body,
        headers={
            'Content-Type': 'application/json',
            settings.SIGNATURE_HEADER_KEY: signature,
        },
        callback=ping_callback,
    )


def get_payload(message):
    try:
        return sign.unserialize_payload(message)
    except (TypeError, ValueError) as error:
        raise web.HTTPError(
            httplib.BAD_REQUEST,
            reason=error.message,
        )


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


@web.stream_request_body
class UploadHandler(SentryMixin, web.RequestHandler):

    def setup(self):
        self.payload = None
        self.signature = None
        self.file_path = None
        self.file_pointer = None
        self.content_length = int_or_none(
            self.request.headers.get('Content-Length')
        )
        self.last_ping = get_time()
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

    @utils.allow_methods(['put'])
    def data_received(self, chunk):
        """Write data to disk.

        :param str chunk: Chunk of request body
        """
        self.file_pointer.write(chunk)
        now = get_time()
        if now > (self.last_ping + settings.PING_DEBOUNCE):
            ping(self.payload['pingUrl'], self.signature)
            self.last_ping = now

    def set_default_headers(self):
        self.set_header('Access-Control-Allow-Origin', '*')

    def options(self):
        self.set_header('Access-Control-Allow-Headers', ', '.join(CORS_ACCEPT_HEADERS))
        self.set_header('Access-Control-Allow-Methods', 'PUT'),
        self.set_status(httplib.NO_CONTENT)

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
        tasks.send_hook(
            {
                'status': 'success',
                'uploadSignature': self.signature,
            },
            self.payload['cachedUrl'],
        )
        self.write({'status': 'success'})

    def teardown(self):
        """If any errors logged, notify calling application and clear
        temporary file.
        """
        if self.errors:
            reason = '; '.join(self.errors)
            logger.error(reason)
            tasks.send_hook(
                {
                    'status': 'error',
                    'reason': reason,
                    'uploadSignature': self.signature,
                },
                self.payload['finishUrl'],
            )
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
