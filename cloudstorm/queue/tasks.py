# -*- coding: utf-8 -*-

import hashlib

import requests
from celery.result import AsyncResult

from cloudstorm import sign
from cloudstorm import settings
from cloudstorm.queue import app


class LazyContainer(object):
    """Lazy container; defers computation of its contents until first call to
    `get`. Used to simplify mocking of storage backend objects.
    """
    def __init__(self, getter):
        self._result = None
        self.getter = getter

    def get(self):
        if self._result is None:
            self._result = self.getter()
        return self._result


def _get_storage_client():
    return settings.STORAGE_CLIENT_CLASS(
        **settings.STORAGE_CLIENT_OPTIONS
    )
client_proxy = LazyContainer(_get_storage_client)


def _get_storage_container():
    return client_proxy.get().get_container(
        settings.STORAGE_CONTAINER_NAME
    )
container_proxy = LazyContainer(_get_storage_client)


def iter_chunks(file_pointer, chunk_size):
    """Iterate over chunks of a file.
    """
    while True:
        chunk = file_pointer.read(chunk_size)
        if not chunk:
            break
        yield chunk


def get_hash(file_pointer, chunk_size, hash_function):
    """Iteratively compute hash of file contents.

    :param file file_pointer: File to hash
    :param int chunk_size: Bytes to read per iteration
    :param hash_function: Hash function to apply (md5, sha1, etc.)
    """
    result = hash_function()
    for chunk in iter_chunks(file_pointer, chunk_size):
        result.update(chunk)
    return result.hexdigest()


def get_metadata(file_object):
    """Format metadata from backend file object.
    """
    return {
        'size': file_object.size,
        'date_modified': file_object.date_modified.isoformat(),
        'content_type': file_object.content_type,
    }


@app.task
def push_file_main(file_path):
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
        try:
            return container_proxy.get().upload_file(file_pointer, hash_str)
        except Exception as error:
            try_count = push_file_main.request.retries + 1
            backoff = settings.UPLOAD_RETRY_BACKOFF * try_count
            countdown = settings.UPLOAD_RETRY_DELAY * backoff
            raise push_file_main.retry(
                exc=error,
                countdown=countdown,
                max_retries=settings.UPLOAD_RETRY_ATTEMPTS,
            )


@app.task
def push_file_complete(response, payload, signature):
    """Completion callback for `push_file_main`.

    :param response: Storage object returned by `push_file_main`
    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    """
    return requests.put(
        payload['finishUrl'],
        data=sign.build_hook_body({
            'status': 'success',
            'uploadSignature': signature,
            'location': response.location,
            'metadata': get_metadata(response),
        }),
    )


@app.task
def push_file_error(uuid, payload, signature):
    """Error callback for `push_file_main`.

    :param str uuid: UUID of Celery error result
    :param dict payload: Payload from signed URL
    :param str signature: Signature from signed URL
    """
    result = AsyncResult(uuid)
    error = result.result
    return requests.put(
        payload['finishUrl'],
        data=sign.build_hook_body({
            'status': 'error',
            'reason': 'Upload to backend failed: {0}'.format(error.message),
            'uploadSignature': signature,
        }),
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

