#!/usr/bin/env python
# encoding: utf-8

from tornado import web
from tornado import ioloop
from tornado import httpserver

from raven.contrib.tornado import AsyncSentryClient

from cloudstorm import settings
from cloudstorm.app.handlers import urls
from cloudstorm.app.handlers import upload


def make_app(debug=False):
    app = web.Application(
        [
            web.url(r'/urls/upload/', urls.UploadUrlHandler, name='upload_url'),
            web.url(r'/urls/download/', urls.DownloadUrlHandler, name='download_url'),
            web.url(r'/files/', upload.UploadHandler, name='upload_file'),
        ],
        debug=debug,
    )
    app.sentry_client = AsyncSentryClient(settings.SENTRY_DSN)
    return app


def main(port, processes, debug):
    app = make_app(debug and processes == 1)
    server = httpserver.HTTPServer(app)
    server.bind(port)
    server.start(processes)
    ioloop.IOLoop.current().start()
