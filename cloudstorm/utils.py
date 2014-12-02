# encoding: utf-8

import os
import glob
import errno
import functools
import subprocess

from werkzeug.local import LocalProxy

from cloudstorm import errors
from cloudstorm import settings


def ensure_path(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


def ensure_paths():
    paths = [
        settings.FILE_PATH_PENDING,
        settings.FILE_PATH_COMPLETE,
    ]
    for path in paths:
        ensure_path(path)


def allow_methods(methods):
    """Decorator factory that skips disallowed methods. Intended for use in
    subclasses of `RequestHandler`.
    """
    methods = [method.lower() for method in methods]

    def wrapper(func):
        @functools.wraps(func)
        def wrapped(self, *args, **kwargs):
            if self.request.method.lower() not in methods:
                return None
            return func(self, *args, **kwargs)
        return wrapped
    return wrapper


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


def CachedProxy(getter):
    """Cached proxy factory. Creates a `LocalProxy` that evaluates to the
    return value of `getter`, only calling `getter` on first access.
    :param function getter: Function that takes no arguments
    """
    container = LazyContainer(getter)
    return LocalProxy(container.get)


def create_parity_files(file_path, redundancy=5):
    """
    :raise: `ParchiveError` if creation of parity files fails
    """
    path, name = os.path.split(file_path)
    with open(os.devnull, 'wb') as DEVNULL:
        ret_code = subprocess.call(
            [
                'par2',
                'c',
                '-r{0}'.format(redundancy),
                os.path.join(path, '{0}.par2'.format(name)),
                file_path,
            ],
            stdout=DEVNULL,
            stderr=DEVNULL,
        )
        if ret_code != 0:
            raise errors.ParchiveError()
        return [
            os.path.abspath(fpath)
            for fpath in
            glob.glob(os.path.join(path, '{0}*.par2'.format(name)))
        ]
