#!/usr/bin/env python
# encoding: utf-8

import hashlib
import logging
import functools
import contextlib

import requests

from celery.result import AsyncResult
from celery.utils.log import get_task_logger

from cloudstorm import sign
from cloudstorm import errors
from cloudstorm import storage
from cloudstorm import settings
from cloudstorm.queue import app


logger = get_task_logger(__name__)
logger.setLevel(logging.INFO)

hash_funcs = [settings.UPLOAD_PRIMARY_HASH] + settings.UPLOAD_SECONDARY_HASHES


def iter_chunks(file_pointer, chunk_size):
    """Iterate over chunks of a file. Borrowed from @chrisseto.
    """
    file_pointer.seek(0)
    while True:
        chunk = file_pointer.read(chunk_size)
        if not chunk:
            break
        yield chunk


def get_hashes(file_pointer, chunk_size, hash_funcs):
    """Iteratively compute hash of file contents. Borrowed from @chrisseto.

    :param file file_pointer: File to hash
    :param int chunk_size: Bytes to read per iteration
    :param list hash_funcs: List of hash functions to apply (md5, sha1, etc.)
    """
    file_pointer.seek(0)
    hashes = {func.__name__: func() for func in hash_funcs}
    for chunk in iter_chunks(file_pointer, chunk_size):
        for result in hashes.values():
            result.update(chunk)
    return {name: result.hexdigest() for name, result in hashes.iteritems()}


def clean_hash_names(hashes, hash_funcs):
    return {
        func.__name__.split('_')[-1]: hashes[func.__name__]
        for func in hash_funcs
    }


def serialize_object(file_object, **kwargs):
    """Serialize representation of file object for webhook payload.
    :param file_object: File object from storage backend
    """
    metadata = {
        'size': file_object.size,
        'date_modified': file_object.date_modified.isoformat(),
        'content_type': file_object.content_type,
    }
    metadata.update(kwargs)
    return {
        'location': file_object.location,
        'metadata': metadata,
    }


def _log_task(func):
    """Decorator to add standardized logging to Celery tasks. Decorated tasks
    must also be decorated with `bind=True` so that `self` is available.
    """
    @functools.wraps(func)
    def wrapped(self, *args, **kwargs):
        logger.info('Called {0}(*{1}, **{2}); attempt #{3}'.format(
            getattr(self.request, 'task', None),
            self.request.args,
            self.request.kwargs,
            self.request.retries,
        ))
        return func(self, *args, **kwargs)
    return wrapped


def _create_task(*args, **kwargs):
    """Decorator factory combining `_log_task` and `task(bind=True, *args,
    **kwargs)`. Return a decorator that turns the decorated function into a
    Celery task that logs its calls.
    """
    def wrapper(func):
        wrapped = _log_task(func)
        wrapped = app.task(bind=True, *args, **kwargs)(wrapped)
        return wrapped
    return wrapper


def task(*args, **kwargs):
    """Decorator or decorator factory for logged tasks. If passed a function,
    decorate it; if passed anything else, return a decorator.
    """
    if len(args) == 1 and callable(args[0]):
        return _create_task()(args[0])
    return _create_task(*args, **kwargs)


@contextlib.contextmanager
def RetryTask(task, error_types=(Exception,)):
    try:
        yield
    except error_types as exc_value:
        try_count = task.request.retries + 1
        backoff = settings.UPLOAD_RETRY_BACKOFF * try_count
        countdown = settings.UPLOAD_RETRY_DELAY * backoff
        raise task.retry(
            exc=exc_value,
            countdown=countdown,
            max_retries=settings.UPLOAD_RETRY_ATTEMPTS,
        )


@task
def _push_file_main(self, file_path):
    """Push file to storage backend, retrying on failure.

    :param str file_path: Path to file on disk
    """
    with open(file_path) as file_pointer:
        hashes = get_hashes(
            file_pointer,
            settings.UPLOAD_HASH_CHUNK_SIZE,
            hash_funcs,
        )
        file_pointer.seek(0)
        with RetryTask(self):
            container = storage.container_proxy.get()
            obj = container.get_or_upload_file(
                file_pointer,
                hashes[settings.UPLOAD_PRIMARY_HASH.__name__],
            )
            md5 = hashes.get(hashlib.md5.__name__)
            if md5 != obj.md5:
                raise errors.HashMismatchError
    cleaned_hashes = clean_hash_names(hashes, settings.UPLOAD_SECONDARY_HASHES)
    return serialize_object(obj, **cleaned_hashes)


@task(ignore_result=True)
def _push_file_complete(self, response, payload, signature):
    """Completion callback for `push_file_main`.

    :param response: Object data returned by `push_file_main`
    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    """
    data = {
        'status': 'success',
        'uploadSignature': signature,
        'location': response['location'],
        'metadata': response['metadata'],
    }
    with RetryTask(self):
        return _send_hook(data, payload)


@task(ignore_result=True)
def _push_file_error(self, uuid, payload, signature):
    """Error callback for `push_file_main`.

    :param str uuid: UUID of Celery error result
    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    """
    result = AsyncResult(uuid)
    error = result.result
    data = {
        'status': 'error',
        'reason': 'Upload to backend failed: {0}'.format(error),
        'uploadSignature': signature,
    }
    with RetryTask(self):
        return _send_hook(data, payload)


def _send_hook(data, payload):
    """Send web hook to calling application, retrying on failure.

    :param dict data: JSON-serializable request body
    :param dict payload: Payload from signed URL
    """
    signature, body = sign.build_hook_body(sign.webhook_signer, data)
    return requests.put(
        payload['finishUrl'],
        data=body,
        headers={
            'Content-Type': 'application/json',
            settings.SIGNATURE_HEADER_KEY: signature,
        },
    )


@task(ignore_result=True)
def _send_hook_retry(self, data, payload):
    with RetryTask(self):
        _send_hook(data, payload)


def send_hook(data, payload):
    return _send_hook_retry.apply_async((data, payload))


def push_file(payload, signature, file_path):
    """Push file to storage backend, calling success and error callbacks as
    appropriate.

    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    :param str file_path: Path to file on disk
    """
    return _push_file_main.apply_async(
        (file_path,),
        link=_push_file_complete.s(payload=payload, signature=signature),
        link_error=_push_file_error.s(payload=payload, signature=signature),
    )
