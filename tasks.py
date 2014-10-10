# -*- coding: utf-8 -*-

import os
import sys

from invoke import task, run

from cloudstorm import settings


def get_bin_path():
    return os.path.dirname(sys.executable)


def bin_prefix(path):
    return os.path.join(get_bin_path(), path)


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
    cmd = 'celery worker -A cloudstorm.queue.tasks'
    run(bin_prefix(cmd), pty=True)


@task
def tornado(port=None):
    from cloudstorm import app
    port = port or settings.PORT
    app.main(port=port)

