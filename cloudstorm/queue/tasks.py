#!/usr/bin/env python
# encoding: utf-8

import hashlib
import contextlib

import requests
from celery.result import AsyncResult

from cloudstorm import sign
from cloudstorm import storage
from cloudstorm import settings
from cloudstorm.queue import app


def iter_chunks(file_pointer, chunk_size):
    """Iterate over chunks of a file. Borrowed from @chrisseto.
    """
    while True:
        chunk = file_pointer.read(chunk_size)
        if not chunk:
            break
        yield chunk


def get_hash(file_pointer, chunk_size, hash_function):
    """Iteratively compute hash of file contents. Borrowed from @chrisseto.

    :param file file_pointer: File to hash
    :param int chunk_size: Bytes to read per iteration
    :param hash_function: Hash function to apply (md5, sha1, etc.)
    """
    result = hash_function()
    for chunk in iter_chunks(file_pointer, chunk_size):
        result.update(chunk)
    return result.hexdigest()


def serialize_object(file_object):
    """Serialize representation of file object for webhook payload.
    :param file_object: File object from storage backend
    """
    return {
        'location': file_object.location,
        'metadata': {
            'size': file_object.size,
            'date_modified': file_object.date_modified.isoformat(),
            'content_type': file_object.content_type,
        },
    }


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


@app.task(bind=True)
def push_file_main(self, file_path):
    """Push file to storage backend, retrying on failure.

    :param str file_path: Path to file on disk
    """
    with open(file_path) as file_pointer:
        hash_str = get_hash(
            file_pointer,
            settings.UPLOAD_HASH_CHUNK_SIZE,
            settings.UPLOAD_PRIMARY_HASH,
        )
        file_pointer.seek(0)
        with RetryTask(self):
            container = storage.container_proxy.get()
            obj = container.get_or_upload_file(file_pointer, hash_str)

    return serialize_object(obj)


@app.task(bind=True, ignore_result=True)
def push_file_complete(self, response, payload, signature):
    """Completion callback for `push_file_main`.

    :param response: Object data returned by `push_file_main`
    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    """
    signature, body = sign.build_hook_body(
        sign.webhook_signer,
        {
            'status': 'success',
            'uploadSignature': signature,
            'location': response['location'],
            'metadata': response['metadata'],
        },
    )
    with RetryTask(self):
        return requests.put(
            payload['finishUrl'],
            data=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )


@app.task(bind=True, ignore_result=True)
def push_file_error(self, uuid, payload, signature):
    """Error callback for `push_file_main`.

    :param str uuid: UUID of Celery error result
    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    """
    result = AsyncResult(uuid)
    error = result.result
    signature, body = sign.build_hook_body(
        sign.webhook_signer,
        {
            'status': 'error',
            'reason': 'Upload to backend failed: {0}'.format(error),
            'uploadSignature': signature,
        },
    )
    with RetryTask(self):
        return requests.put(
            payload['finishUrl'],
            data=body,
            headers={
                'Content-Type': 'application/json',
                settings.SIGNATURE_HEADER_KEY: signature,
            },
        )


def push_file(payload, signature, file_path):
    """Push file to storage backend, calling success and error callbacks as
    appropriate.

    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    :param str file_path: Path to file on disk
    """
    return push_file_main.apply_async(
        (file_path,),
        link=push_file_complete.s(payload=payload, signature=signature),
        link_error=push_file_error.s(payload=payload, signature=signature),
    )
