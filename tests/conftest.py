#!/usr/bin/env python
# encoding: utf-8

import pytest

import os
import errno

from cloudstorm import settings


def ensure_path(path):
    """Ensure that specified path exists.

    :param str path: Path to check
    :return: Path was created
    """
    try:
        os.makedirs(path)
        return True
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise
    return False


@pytest.yield_fixture(scope='session', autouse=True)
def ensure_paths():
    pending_path_created = ensure_path(settings.FILE_PATH_PENDING)
    complete_path_created = ensure_path(settings.FILE_PATH_COMPLETE)
    yield
    for path in os.listdir(settings.FILE_PATH_COMPLETE):
        os.remove(os.path.join(settings.FILE_PATH_COMPLETE, path))
    if pending_path_created:
        os.rmdir(settings.FILE_PATH_PENDING)
    if complete_path_created:
        os.rmdir(settings.FILE_PATH_COMPLETE)
