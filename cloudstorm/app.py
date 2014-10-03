# -*- coding: utf-8 -*-

import os
import json
import uuid
import httplib
import logging

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

    :param str url: Webhook URL
    :param str signature: Signature from signed URL
    :raise: `web.HTTPError` if error received from application
    """
    try:
        response = yield http_client.fetch(
            url,
            method='PUT',
            body=json.dumps({
                'signature': signature,
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
            payload['urls']['finish'],
            method='PUT',
            body=json.dumps({
                'status': 'error',
                'reason': 'Uploaded file has incorrect size',
                'signature': signature,
            })
        )
        raise web.HTTPError(
            httplib.BAD_REQUEST,
            reason='Unexpected content size.',
        )


def teardown_incomplete_file(file_pointer, payload, signature):
    """
    """
    logger.error('Client disconnected. Aborting upload.')
    os.remove(file_pointer.name)
    http_client.fetch(
        payload['urls']['finish'],
        method='PUT',
        body=json.dumps({
            'status': 'error',
            'reason': 'Connection terminated',
            'signature': signature,
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
        yield start_upload(self.payload['urls']['start'], self.signature)
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
        # tasks.push_file(self.payload, self.signature, self.file_path)

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
        # import pdb; pdb.set_trace()
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
            web.url(r'/', UploadHandler),
        ],
        debug=True,
    )


def main():
    app = make_app()
    app.listen(7777)
    IOLoop.current().start()


if __name__ == '__main__':
    main()

