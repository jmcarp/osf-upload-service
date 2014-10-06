# -*- coding: utf-8 -*-

import os
import json
import uuid
import httplib
import logging
import urlparse

from webargs import Arg
from webargs.tornadoparser import parser

from tornado.ioloop import IOLoop
from tornado import web, gen, httpclient

from cloudstorm import sign
from cloudstorm import errors
from cloudstorm import settings
from cloudstorm.queue import tasks


logger = logging.getLogger(__name__)

http_client = httpclient.AsyncHTTPClient()


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
def start_upload(url, signature):
    """Notify metadata application that file upload has started. Catch and
    reraise errors.

    :param str url: Webhook start URL
    :param str signature: Signature from signed URL
    :raise: `web.HTTPError` if error received from application
    """
    try:
        response = yield http_client.fetch(
            url,
            method='PUT',
            body=sign.build_hook_body({
                'uploadSignature': signature,
            }),
        )
        raise gen.Return(response)
    except httpclient.HTTPError as error:
        logger.error('Begin-upload request rejected. Aborting upload.')
        logger.exception(error)
        raise web.HTTPError(error.code)


def close_file(file_pointer):
    """Ensure that file is closed, passing silently if `file_pointer` is not a
    file.

    :param file file_pointer: File pointer or `None`
    """
    try:
        file_pointer.close()
    except AttributeError:
        pass


def teardown_file(file_pointer, content_length, payload, signature):
    """
    :raise: `web.HTTPError` if file has incorrect size
    """
    file_pointer.seek(0, os.SEEK_END)
    size = file_pointer.tell()
    close_file(file_pointer)
    if size != content_length:
        logger.error('Unexpected content length. Aborting upload.')
        os.remove(file_pointer.name)
        http_client.fetch(
            payload['finishUrl'],
            method='PUT',
            body=sign.build_hook_body({
                'status': 'error',
                'reason': 'Uploaded file has incorrect size',
                'uploadSignature': signature,
            }),
        )
        raise web.HTTPError(
            httplib.BAD_REQUEST,
            reason='Unexpected content size',
        )


def teardown_incomplete_file(file_pointer, payload, signature):
    """
    """
    logger.error('Client disconnected. Aborting upload.')
    os.remove(file_pointer.name)
    http_client.fetch(
        payload['finishUrl'],
        method='PUT',
        body=sign.build_hook_body({
            'status': 'error',
            'reason': 'Connection terminated',
            'uploadSignature': signature,
        }),
    )


# TODO: Is UUID adequate here?
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
}


class UploadUrlHandler(web.RequestHandler):

    def post(self):
        args = parser.parse(upload_url_args, self.request, targets=('json',))
        base_url = self.reverse_url('upload_url')
        url, _ = sign.build_upload_url(
            base_url,
            args['size'],
            args['type'],
            args['startUrl'],
            args['finishUrl'],
        )
        self.write({
            'status': 'success',
            'url': url,
        })


class DownloadUrlHandler(web.RequestHandler):

    def get(self):
        pass


@web.stream_request_body
class UploadHandler(web.RequestHandler):

    def __init__(self, *args, **kwargs):
        super(UploadHandler, self).__init__(*args, **kwargs)
        self.payload = None
        self.signature = None
        self.file_path = None
        self.file_pointer = None
        self.content_length = int_or_none(self.request.headers['Content-Length'])

    @gen.coroutine
    def prepare(self):
        """Verify signed URL and notify metadata application of upload start.
        If either check fails, cancel upload.
        """
        self.payload, self.signature = verify_upload(self.request)
        yield start_upload(self.payload['startUrl'], self.signature)
        self.file_path = build_file_path(self.request, self.payload)
        self.file_pointer = open(self.file_path, 'wb')
        content_length_text = int_or_none(
            self.request.headers.get('Content-Length')
        )

    def data_received(self, chunk):
        """Write data to disk.

        :param str chunk: Chunk of request body
        """
        self.file_pointer.write(chunk)

    def put(self):
        """After file is uploaded, push to backend via Celery.
        """
        tasks.push_file(self.payload, self.signature, self.file_path)

    def on_connection_close(self, *args, **kwargs):
        """If upload is interrupted, notify metadata application.
        """
        # If no file path, verification has already failed; no need to notify
        if self.file_path is None:
            return
        teardown_incomplete_file(self.file_pointer, self.payload, self.signature)

    def on_finish(self):
        """Ensure that file is closed by the end of the request.
        """
        if self.content_length:
            teardown_file(
                self.file_pointer,
                self.content_length,
                self.payload,
                self.signature,
            )


def make_app():
    return web.Application(
        [
            web.url(r'/urls/upload/', UploadUrlHandler, name='upload_url'),
            web.url(r'/urls/download/', DownloadUrlHandler, name='download_url'),
            web.url(r'/files/', UploadHandler, name='upload_file'),
        ],
        debug=True,
    )


def main():
    app = make_app()
    app.listen(settings.PORT)
    IOLoop.current().start()


if __name__ == '__main__':
    main()

