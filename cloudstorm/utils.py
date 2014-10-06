# -*- coding: utf-8 -*-

import functools


def allow_methods(methods):
    methods = [method.lower() for method in methods]
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(self, *args, **kwargs):
            if self.request.method.lower() not in methods:
                return None
            return func(self, *args, **kwargs)
        return wrapped
    return wrapper

