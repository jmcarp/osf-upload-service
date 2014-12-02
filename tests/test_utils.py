# -*- coding: utf-8 -*-

import pytest

import os
import tempfile

from cloudstorm import utils
from cloudstorm import settings


@pytest.yield_fixture
def mock_paths(monkeypatch):
    pending_path = tempfile.mkdtemp()
    complete_path = tempfile.mkdtemp()
    monkeypatch.setattr(settings, 'FILE_PATH_PENDING', pending_path)
    monkeypatch.setattr(settings, 'FILE_PATH_COMPLETE', complete_path)
    yield
    os.rmdir(pending_path)
    os.rmdir(complete_path)


def test_ensure_paths(mock_paths):
    os.rmdir(settings.FILE_PATH_PENDING)
    os.rmdir(settings.FILE_PATH_COMPLETE)
    utils.ensure_paths()
    assert os.path.exists(settings.FILE_PATH_PENDING)
    assert os.path.exists(settings.FILE_PATH_COMPLETE)
