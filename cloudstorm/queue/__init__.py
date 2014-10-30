#!/usr/bin/env python
# encoding: utf-8

from celery import Celery

from cloudstorm import settings


app = Celery()
app.config_from_object(settings)
