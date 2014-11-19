# encoding: utf-8

import os
import subprocess
import functools
import glob

from werkzeug.local import LocalProxy

from cloudstorm.errors import ParchiveException


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
    path, name = os.path.split(file_path)
    with open(os.devnull, 'wb') as DEVNULL:
        ret_code = subprocess.call(
            [
                'par2',
                'c',
                '-r{}'.format(redundancy),
                os.path.join(path, '{}.par2'.format(name)),
                file_path
            ],
            stdout=DEVNULL,
            stderr=DEVNULL
        )
        if ret_code != 0:
            raise ParchiveException()
        return [
            os.path.abspath(fpath)
            for fpath in
            glob.glob(os.path.join(path, '{}.*.par2'.format(name)))
        ]
