==================
osf-upload-service
==================

.. image:: https://travis-ci.org/CenterForOpenScience/osf-upload-service.png?branch=master
    :target: https://travis-ci.org/CenterForOpenScience/osf-upload-service

*osf-upload-service is a service that links web applications with cloud storage 
tools like Amazon S3 and Rackspace Cloud Files.*

Features:

- Direct uploads and downloads via signed URL
- Pluggable backends for Amazon S3, Rackspace Cloud Files
- Files named by hash, preventing data duplication


Installation
------------

::

    pip install .


Testing
-------

::

    invoke test


Configuration
-------------


Task Queue
==========

By default, the task queue uses RabbitMQ as the message broker and Redis as the 
result backend; a result backend is needed so that exceptions can be passed to
the error callback task. To avoid memory leaks in the result backend, results
are expired often. It is also recommended to set the `maxmemory` option in Redis
to a reasonable value when deploying.


Sentry
======

Both the Tornado application and the Celery task queue will log uncaught errors
to Sentry if the `SENTRY_DSN` variable is configured in the settings.


Usage
-----

::

    invoke rabbitmq
    invoke redis
    invoke celery
    invoke tornado

