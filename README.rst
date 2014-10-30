==================
osf-upload-service
==================

.. image:: https://travis-ci.org/CenterForOpenScience/osf-upload-service.png?branch=master
    :target: https://travis-ci.org/CenterForOpenScience/osf-upload-service

*osf-upload-service is a service that links web applications with cloud storage tools like Amazon S3 and Rackspace Cloud Files.*

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


Usage
-----

::

    invoke rabbitmq
    invoke celery
    invoke tornado

