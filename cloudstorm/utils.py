#!/usr/bin/env python
# encoding: utf-8

import functools

from werkzeug.local import LocalProxy


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
