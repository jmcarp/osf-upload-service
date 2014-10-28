#!/usr/bin/env python
# encoding: utf-8

import functools

import furl
from dateutil.parser import parse as parse_date

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


# TODO: Patch Pyrax to include this functionality
def add_name_to_url(url, filename=None):
    """Optionally add a filename to the query string of a URL.
    Note: Cloudfiles allows `filename` as an optional query parameter on signed
    GET requests; if provided, the filename overrides the default filename in
    the `Content-Disposition` header.

    :param str url: Base URL
    :param str filename: Optional filename
    """
    if filename is None:
        return url
    parsed = furl.furl(url)
    parsed.args['filename'] = filename
    return parsed.url


class CloudFilesClient(core.BaseClient):

    def __init__(self, username, api_key, region):
        self.username = username
        self.api_key = api_key
        self.region = region
        self.connection = None

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

    @ensure_connection
    def _generate_signed_url(self, seconds, method, container, obj, filename=None):
        url = self.connection.get_temp_url(container, obj, seconds, method)
        return add_name_to_url(url, filename)


class CloudFilesContainer(core.BaseContainer):

    def __init__(self, pyrax_container, client):
        self._pyrax_container = pyrax_container
        self._client = client

    @property
    def name(self):
        return self._pyrax_container.name

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

    def _generate_signed_url(self, seconds, method, obj, filename=None):
        url = self._pyrax_container.get_temp_url(obj, seconds, method)
        return add_name_to_url(url, filename)


class CloudFilesObject(core.BaseObject):

    def __init__(self, pyrax_object, container):
        self._pyrax_object = pyrax_object
        self._container = container

    def __eq__(self, other):
        if not isinstance(other, CloudFilesObject):
            return NotImplemented
        return (
            self._pyrax_object == other._pyrax_object and
            self._container == other._container
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    @property
    def name(self):
        return self._pyrax_object.name

    @property
    def size(self):
        return self._pyrax_object.bytes

    @property
    def date_modified(self):
        return parse_date(self._pyrax_object.last_modified)

    @property
    def content_type(self):
        return self._pyrax_object.content_type

    @property
    def location(self):
        return {
            'service': 'cloudfiles',
            'container': self._container.name,
            'object': self.name,
        }

    def download(self):
        return self._pyrax_object.fetch()

    def delete(self):
        self._pyrax_object.delete()

    def _generate_signed_url(self, seconds, method, filename=None):
        url = self._pyrax_object.get_temp_url(seconds, method)
        return add_name_to_url(url, filename)
