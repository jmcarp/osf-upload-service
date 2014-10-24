#!/usr/bin/env python
# encoding: utf-8

import pytest

import tempfile

from tests import utils


@pytest.fixture
def file_content():
    return utils.build_random_string(1024)


@pytest.fixture
def temp_file(file_content):
    file_pointer = tempfile.NamedTemporaryFile()
    file_pointer.write(file_content)
    file_pointer.seek(0)
    return file_pointer
