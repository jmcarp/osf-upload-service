# -*- coding: utf-8 -*-

from boto.s3.connection import S3Connection

from cloudstorm.backend import core
from cloudstorm.backend import errors


class S3Client(core.BaseClient):

    def __init__(self, access_key_id, secret_access_key):
        self.connection = S3Connection(access_key_id, secret_access_key)

    def get_container(self, container):
        _s3_bucket = self.connection.get_bucket(container)
        return S3Container(_s3_bucket, self)

    def create_container(self, container):
        _s3_bucket = self.connection.create_bucket(container)
        return S3Container(_s3_bucket, self)


class S3Container(core.BaseContainer):

    def __init__(self, s3_bucket, client):
        self._s3_container = s3_bucket
        self._client = client

    def list_objects(self, prefix=None):
        """
        :return: Generator of S3 keys
        """
        _s3_keys = self._s3_container.list(prefix=prefix)
        return (
            S3Object(each, self)
            for each in _s3_keys
        )

    def get_object(self, obj):
        _s3_key = self._s3_container.get_key(obj)
        if _s3_key is None:
            raise errors.NotFound
        return S3Object(_s3_key, self)

    def upload_file(self, fobj, name):
        _s3_key = (
            self._s3_container.get_key(name) or
            self._s3_container.new_key(name)
        )
        _s3_key = self._s3_bucket.send_file(
            fobj,
            obj_name=name,
        )
        return S3Object(_s3_object)


class S3Object(core.BaseObject):

    def __init__(self, s3_key, container):
        self._s3_key = s3_key
        self._container = container

    def download(self):
        return self._s3_key.get_contents_as_string()

    def delete(self):
        self._s3_key.delete()

    def _generate_signed_url(self, seconds, method='GET'):
        return self._s3_key._client.get_temp_url(
            expires_in=seconds,
            method=method,
        )

