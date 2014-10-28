#!/usr/bin/env python
# encoding: utf-8

import mock
import pytest

import types
import datetime

import pyrax

from cloudstorm.backend import errors
from cloudstorm.backend.contrib import cloudfiles


USERNAME = 'freddie'
API_KEY = '39'
REGION = 'UK'


@pytest.fixture
def mock_pyrax(monkeypatch):
    m = mock.Mock()
    monkeypatch.setattr(cloudfiles, 'pyrax', m)
    return m


@pytest.fixture
def mock_connection():
    return mock.Mock()


@pytest.fixture
def client():
    return cloudfiles.CloudFilesClient(USERNAME, API_KEY, REGION)


@pytest.fixture
def mock_client(client, mock_connection):
    client.connection = mock_connection
    return client


@pytest.fixture
def mock_pyrax_container():
    return mock.Mock()


@pytest.fixture
def mock_container(mock_pyrax_container, mock_client):
    return cloudfiles.CloudFilesContainer(mock_pyrax_container, mock_client)


@pytest.fixture
def mock_pyrax_object():
    return mock.Mock()


@pytest.fixture
def mock_object(mock_pyrax_object, mock_container):
    return cloudfiles.CloudFilesObject(mock_pyrax_object, mock_container)


class DummyClient(cloudfiles.CloudFilesClient):
    @cloudfiles.ensure_connection
    def dummy(self):
        pass


def test_add_name_without_filename():
    res = cloudfiles.add_name_to_url('http://queen.com/', 'freddie')
    assert res == 'http://queen.com/?filename=freddie'


def test_add_name_with_filename():
    res = cloudfiles.add_name_to_url('http://queen.com/')
    assert res == 'http://queen.com/'


class TestClient:

    def test_init(self, client):
        assert client.username == USERNAME
        assert client.api_key == API_KEY
        assert client.region == REGION
        assert client.connection is None

    def test_ensure_connection_not_connected(self, client, monkeypatch):
        mock_connect = mock.Mock()
        monkeypatch.setattr(cloudfiles.CloudFilesClient, 'connect', mock_connect)
        dummy_client = DummyClient(USERNAME, API_KEY, REGION)
        dummy_client.dummy()
        assert mock_connect.called

    def test_ensure_connection_connected(self, client, monkeypatch):
        mock_connect = mock.Mock()
        monkeypatch.setattr(cloudfiles.CloudFilesClient, 'connect', mock_connect)
        dummy_client = DummyClient(USERNAME, API_KEY, REGION)
        dummy_client.connection = 7
        dummy_client.dummy()
        assert not mock_connect.called

    def test_connect(self, client, mock_pyrax):
        client.connect()
        mock_pyrax.settings.set.assert_called_with('identity_type', 'rackspace')
        mock_pyrax.set_credentials.assert_called_with(USERNAME, api_key=API_KEY)

    def test_get_container(self, mock_client):
        res = mock_client.get_container('albums')
        mock_client.connection.get_container.assert_called_with('albums')
        assert res._pyrax_container == mock_client.connection.get_container()
        assert res._client == mock_client

    def test_get_container_not_found(self, mock_client):
        mock_client.connection.get_container.side_effect = pyrax.exceptions.NoSuchContainer
        with pytest.raises(errors.NotFound):
            res = mock_client.get_container('albums')
        mock_client.connection.get_container.assert_called_with('albums')

    def test_create_container(self, mock_client):
        res = mock_client.create_container('instruments')
        mock_client.connection.create_container.assert_called_with('instruments')
        assert res._pyrax_container == mock_client.connection.create_container()
        assert res._client == mock_client

    def test_generate_signed_url_without_filename(self, mock_client):
        url = 'http://httpbin.org/'
        mock_client.connection.get_temp_url.return_value = url
        res = mock_client.generate_signed_url(60, 'GET', 'instruments', 'guitar')
        mock_client.connection.get_temp_url.assert_called_with('instruments', 'guitar', 60, 'GET')
        assert res == url

    def test_generate_signed_url_with_filename(self, mock_client):
        url = 'http://httpbin.org/'
        mock_client.connection.get_temp_url.return_value = url
        res = mock_client.generate_signed_url(60, 'GET', 'instruments', 'guitar', filename='guitar.mp3')
        mock_client.connection.get_temp_url.assert_called_with('instruments', 'guitar', 60, 'GET')
        assert res == cloudfiles.add_name_to_url(url, 'guitar.mp3')



class TestContainer:

    def test_init(self, mock_pyrax_container, mock_client, mock_container):
        assert mock_container._pyrax_container == mock_pyrax_container
        assert mock_container._client == mock_client

    def test_name(self, mock_container):
        name = 'freddie'
        mock_container._pyrax_container.name = name
        assert mock_container.name == name

    def test_list_objects_no_prefix(self, mock_container):
        values = ['freddie', 'john', 'roger']
        mock_container._pyrax_container.list_all.return_value = values
        res = mock_container.list_objects()
        mock_container._pyrax_container.list_all.assert_called_with(prefix=None)
        assert isinstance(res, types.GeneratorType)
        expected = [
            cloudfiles.CloudFilesObject(value, mock_container)
            for value in values
        ]
        assert list(res) == expected

    def test_list_objects_with_prefix(self, mock_container):
        values = ['freddie', 'john', 'roger']
        mock_container._pyrax_container.list_all.return_value = values
        res = mock_container.list_objects(prefix='singers')
        mock_container._pyrax_container.list_all.assert_called_with(prefix='singers')
        assert isinstance(res, types.GeneratorType)
        expected = [
            cloudfiles.CloudFilesObject(value, mock_container)
            for value in values
        ]
        assert list(res) == expected

    def test_get_object(self, mock_container):
        res = mock_container.get_object('roger')
        mock_container._pyrax_container.get_object.assert_called_with('roger')
        assert res._pyrax_object == mock_container._pyrax_container.get_object()
        assert res._container == mock_container

    def test_get_object_not_found(self, mock_container):
        mock_container._pyrax_container.get_object.side_effect = pyrax.exceptions.NoSuchObject
        with pytest.raises(errors.NotFound):
            mock_container.get_object('roger')
        mock_container._pyrax_container.get_object.assert_called_with('roger')

    def test_upload_file(self, mock_container):
        mock_container._pyrax_container.upload_file.return_value = 'may'
        res = mock_container.upload_file(None, 'brian')
        mock_container._pyrax_container.upload_file.assert_called_with(None, obj_name='brian')
        assert res._pyrax_object == 'may'
        assert res._container == mock_container

    def test_generate_signed_url_without_filename(self, mock_container):
        url = 'http://queen.com/'
        mock_container._pyrax_container.get_temp_url.return_value = url
        res = mock_container.generate_signed_url(60, 'GET', 'freddie')
        mock_container._pyrax_container.get_temp_url.assert_called_with('freddie', 60, 'GET')
        assert res == url

    def test_generate_signed_url_with_filename(self, mock_container):
        url = 'http://queen.com/'
        mock_container._pyrax_container.get_temp_url.return_value = url
        res = mock_container.generate_signed_url(60, 'GET', 'freddie', filename='freddie.tiff')
        mock_container._pyrax_container.get_temp_url.assert_called_with('freddie', 60, 'GET')
        assert res == cloudfiles.add_name_to_url(url, 'freddie.tiff')


class TestObject:

    def test_init(self, mock_pyrax_object, mock_container, mock_object):
        assert mock_object._pyrax_object == mock_pyrax_object
        assert mock_object._container == mock_container

    def test_eq_same(self):
        obj1 = cloudfiles.CloudFilesObject('foo', 'bar')
        obj2 = cloudfiles.CloudFilesObject('foo', 'bar')
        assert obj1 == obj2

    def test_eq_different(self):
        obj1 = cloudfiles.CloudFilesObject('foo', 'bar')
        obj2 = cloudfiles.CloudFilesObject('bar', 'foo')
        assert obj1 != obj2
        assert obj1 != None
        assert None != obj1

    def test_name(self, mock_object):
        mock_object._pyrax_object.name = 'john'
        assert mock_object.name == 'john'

    def test_size(self, mock_object):
        mock_object._pyrax_object.bytes = 128
        assert mock_object.size == 128

    def test_date(self, mock_object):
        now = datetime.datetime.utcnow()
        mock_object._pyrax_object.last_modified = now.isoformat()
        assert mock_object.date_modified == now

    def test_content_type(self, mock_object):
        content_type = 'application/json'
        mock_object._pyrax_object.content_type = content_type
        assert mock_object.content_type == content_type

    def test_location(self, mock_object):
        mock_object._pyrax_object.name = 'freddie'
        mock_object._container._pyrax_container.name = 'singers'
        expected = {
            'service': 'cloudfiles',
            'container': 'singers',
            'object': 'freddie',
        }
        assert mock_object.location == expected

    def test_download(self, mock_object):
        res = mock_object.download()
        assert mock_object._pyrax_object.fetch.called
        assert res == mock_object._pyrax_object.fetch()

    def test_delete(self, mock_object):
        res = mock_object.delete()
        assert mock_object._pyrax_object.delete.called
        assert res is None

    def test_generate_signed_url_without_filename(self, mock_object):
        url = 'http://queen.com/freddie/'
        mock_object._pyrax_object.get_temp_url.return_value = url
        res = mock_object.generate_signed_url(60, 'GET')
        mock_object._pyrax_object.get_temp_url.assert_called_with(60, 'GET')
        assert res == url

    def test_generate_signed_url_with_filename(self, mock_object):
        url = 'http://queen.com/freddie/'
        mock_object._pyrax_object.get_temp_url.return_value = url
        res = mock_object.generate_signed_url(60, 'GET', filename='freddie.png')
        mock_object._pyrax_object.get_temp_url.assert_called_with(60, 'GET')
        assert res == cloudfiles.add_name_to_url(url, 'freddie.png')
