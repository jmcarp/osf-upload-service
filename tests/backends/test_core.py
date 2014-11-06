#!/usr/bin/env python
# encoding: utf-8

import mock
import pytest

from cloudstorm.backend import core
from cloudstorm.backend import errors


class SignedUrl(core.SignedUrlBase):
    def _generate_signed_url(self, *args, **kwargs):
        return args, kwargs


class Container(core.BaseContainer):
    @property
    def name(self):
        pass
    def list_objects(self, prefix=None):
        pass
    def get_object(self, obj):
        pass
    def upload_file(self, fobj, name):
        pass
    def _generate_signed_url(self, *args, **kwargs):
        pass


class Object(core.BaseObject):
    @property
    def name(self):
        pass
    @property
    def md5(self):
        pass
    @property
    def size(self):
        pass
    @property
    def date_modified(self):
        pass
    @property
    def content_type(self):
        pass
    @property
    def location(self):
        pass
    def download(self):
        pass
    def delete(self):
        pass
    def _generate_signed_url(self, *args, **kwargs):
        pass


def test_signed_url_base_missing_method():
    with pytest.raises(TypeError):
        core.SignedUrlBase()


def test_signed_url_base_passes_args():
    signed_url = SignedUrl()
    args = (60, 'GET', 'container')
    kwargs = {'filename': 'pizza.py'}
    res = signed_url.generate_signed_url(*args, **kwargs)
    assert res == (args, kwargs)


def test_signed_url_base_validates_seconds():
    signed_url = SignedUrl()
    with pytest.raises(ValueError):
        res = signed_url.generate_signed_url(-5, 'PUT')


def test_signed_url_base_validates_method():
    signed_url = SignedUrl()
    with pytest.raises(ValueError):
        res = signed_url.generate_signed_url(60, 'OPTIONS')


def test_base_client_missing_methods():
    with pytest.raises(TypeError):
        core.BaseClient()


def test_base_client():
    class Client(core.BaseClient):
        def get_container(self, container):
            pass
        def create_container(self, container):
            pass
        def _generate_signed_url(self, *args, **kwargs):
            pass
    client = Client()


def test_base_container_missing_methods():
    with pytest.raises(TypeError):
        core.BaseContainer()


def test_base_container_get_or_upload_exists(monkeypatch):
    container = Container()
    mock_get_object = mock.Mock()
    mock_get_object.return_value = 'object'
    monkeypatch.setattr(Container, 'get_object', mock_get_object)
    res = container.get_or_upload_file(None, 'albums')
    assert res == 'object'
    mock_get_object.assert_called_with('albums')


def test_base_container_get_or_upload_does_not_exist(monkeypatch):
    container = Container()
    mock_get_object = mock.Mock()
    mock_get_object.side_effect = errors.NotFound
    mock_upload_file = mock.Mock()
    mock_upload_file.return_value = 'object'
    monkeypatch.setattr(Container, 'get_object', mock_get_object)
    monkeypatch.setattr(Container, 'upload_file', mock_upload_file)
    res = container.get_or_upload_file(None, 'albums')
    assert res == 'object'
    mock_get_object.assert_called_with('albums')
    mock_upload_file.assert_called_with(None, 'albums')


def test_base_container_repr(monkeypatch):
    container = Container()
    monkeypatch.setattr(Container, 'name', 'albums')
    assert repr(container) == '<Container: albums>'


def test_base_object_missing_methods():
    with pytest.raises(TypeError):
        core.BaseObject()


def test_base_object_repr(monkeypatch):
    obj = Object()
    monkeypatch.setattr(Object, 'name', 'the-works.mp3')
    assert repr(obj) == '<Object: the-works.mp3>'
