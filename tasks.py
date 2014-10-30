#!/usr/bin/env python
# encoding: utf-8

from invoke import task, run

from cloudstorm import settings


@task
def install(upgrade=False):
    cmd = 'pip install -r dev-requirements.txt'
    if upgrade:
        cmd += ' --upgrade'
    run(cmd)


@task
def test():
    cmd = 'py.test --cov-report term-missing --cov cloudstorm tests'
    run(cmd, pty=True)


@task
def flake():
    run('flake8 .')


@task
def rabbitmq():
    cmd = 'rabbitmq-server'
    run(cmd, pty=True)


@task
def celery():
    from cloudstorm.queue import app
    app.worker_main(['worker'])


@task
def tornado(port=settings.PORT, processes=settings.PROCESSES, debug=settings.DEBUG):
    from cloudstorm.app import main
    main.main(port, processes, debug)
