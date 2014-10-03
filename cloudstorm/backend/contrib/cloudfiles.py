# -*- coding: utf-8 -*-

import functools

import pyrax

from cloudstorm.backend import core
from cloudstorm.backend import errors


def ensure_connection(func):
    """Decorator ensuring that the connection object has connected to
    Rackspace. For use with `CloudFilesClient` methods.
    """
    @functools.wraps(func)
    def wrapped(self, *args, **kwargs):
        if self.connection is None:
            self.connect()
        return func(self, *args, **kwargs)
    return wrapped


class CloudFilesClient(core.BaseClient):

    def __init__(self, username, api_key, region, lazy=True):
        self.username = username
        self.api_key = api_key
        self.region = region
        self.connection = None
        if not lazy:
            self.connect()

    def connect(self):
        """Connect to Rackspace using provided credentials.
        """
        pyrax.settings.set('identity_type', 'rackspace')
        pyrax.set_credentials(self.username, api_key=self.api_key)
        pyrax.set_setting('region', self.region)
        self.connection = pyrax.cloudfiles

    @ensure_connection
    def get_container(self, container):
        try:
            _pyrax_container = self.connection.get_container(container)
        except pyrax.exceptions.NoSuchContainer:
            raise errors.NotFound
        return CloudFilesContainer(_pyrax_container, self)

    @ensure_connection
    def create_container(self, container):
        _pyrax_container = self.connection.create_container(container)
        return CloudFilesContainer(_pyrax_container, self)


class CloudFilesContainer(core.BaseContainer):

    def __init__(self, pyrax_container, client):
        self._pyrax_container = pyrax_container
        self._client = client

    def list_objects(self, prefix=None):
        """
        :return: Generator of Cloud Files objects
        """
        _pyrax_objects = self._pyrax_container.list_all(prefix=prefix)
        return (
            CloudFilesObject(each, self)
            for each in _pyrax_objects
        )

    def get_object(self, obj):
        try:
            _pyrax_object = self._pyrax_container.get_object(obj)
        except pyrax.exceptions.NoSuchObject:
            raise errors.NotFound
        return CloudFilesObject(_pyrax_object, self)

    def upload_file(self, fobj, name):
        _pyrax_object = self._pyrax_container.upload_file(
            fobj,
            obj_name=name,
        )
        return CloudFilesObject(_pyrax_object, self)


class CloudFilesObject(core.BaseObject):

    def __init__(self, pyrax_object, container):
        self._pyrax_object = pyrax_object
        self._container = container

    def download(self):
        return self._pyrax_object.fetch()

    def delete(self):
        self._pyrax_object.delete()

    def _generate_signed_url(self, seconds, method='GET'):
        return self._pyrax_object.get_temp_url(seconds, method)

