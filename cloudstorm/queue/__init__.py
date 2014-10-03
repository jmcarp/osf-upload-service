# -*- coding: utf-8 -*_

from celery import Celery

from cloudstorm import settings


app = Celery()
app.config_from_object(settings)

