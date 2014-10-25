#!/usr/bin/env python
# encoding: utf-8

import os
import sys

from invoke import task, run

from cloudstorm.queue import app
from cloudstorm import settings


@task
def install(upgrade=False):
    cmd = 'pip install -r dev-requirements.txt'
    if upgrade:
        cmd += ' --upgrade'
    run(cmd)


@task
def test():
    cmd = 'py.test tests'
    run(cmd, pty=True)


@task
def rabbitmq():
    cmd = 'rabbitmq-server'
    run(cmd, pty=True)


@task
def celery():
    app.worker_main(['worker'])


@task
def tornado(port=settings.PORT, processes=settings.PROCESSES, debug=settings.DEBUG):
    from cloudstorm import app
    app.main(port, processes, debug)
