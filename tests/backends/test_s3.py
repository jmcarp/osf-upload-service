#!/usr/bin/env python
# encoding: utf-8

import mock
import pytest

from cloudstorm.backend.contrib import s3


ACCESS_KEY = 'guitar'
SECRET_KEY = 'red-special'


@pytest.fixture
def mock_s3_connection(monkeypatch):
    m = mock.Mock()
    monkeypatch.setattr(s3, 'S3Connection', m)
    return m()


@pytest.fixture
def mock_client(mock_s3_connection):
    return s3.S3Client(ACCESS_KEY, SECRET_KEY)


class TestClient:

    def test_init(self, mock_s3_connection, mock_client):
        assert mock_client.connection == mock_s3_connection

    def test_get_container(self, mock_client):
        res = mock_client.get_container('instruments')
        mock_client.connection.get_bucket.assert_called_with('instruments')
        assert res._s3_bucket == mock_client.connection.get_bucket()
        assert res._client == mock_client

    def test_create_container(self, mock_client):
        res = mock_client.create_container('instruments')
        mock_client.connection.create_bucket.assert_called_with('instruments')
        assert res._s3_bucket == mock_client.connection.create_bucket()
        assert res._client == mock_client

    def test_generate_signed_url_without_filename(self, mock_client):
        url = 'http://queen.com/'
        mock_client.connection.generate_url.return_value = url
        res = mock_client.generate_signed_url(60, 'GET', 'instruments', 'bass')
        mock_client.connection.generate_url.assert_called_with(
            expires_in=60,
            method='GET',
            bucket='instruments',
            key='bass',
            response_headers=None,
        )

    def test_generate_signed_url_with_filename(self, mock_client):
        url = 'http://queen.com/'
        mock_client.connection.generate_url.return_value = url
        res = mock_client.generate_signed_url(60, 'GET', 'instruments', 'bass', filename='bass.mp3')
        mock_client.connection.generate_url.assert_called_with(
            expires_in=60,
            method='GET',
            bucket='instruments',
            key='bass',
            response_headers={
                'response-content-disposition': 'attachment; filename=bass.mp3',
            },
        )
