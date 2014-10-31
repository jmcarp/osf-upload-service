#!/usr/bin/env python
# encoding: utf-8

from celery import Celery

from raven import Client
from raven.contrib.celery import register_signal

from cloudstorm import settings


app = Celery()
app.config_from_object(settings)


if settings.SENTRY_DSN:
    client = Client(settings.SENTRY_DSN)
    register_signal(client)
