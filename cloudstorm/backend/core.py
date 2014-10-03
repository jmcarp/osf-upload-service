# -*- coding: utf-8 -*-

import abc
import six


SIGNED_URL_METHODS = ['GET', 'PUT']


@six.add_metaclass(abc.ABCMeta)
class BaseClient(object):

    @abc.abstractmethod
    def get_container(self, container):
        pass

    @abc.abstractmethod
    def create_container(self, container):
        pass


@six.add_metaclass(abc.ABCMeta)
class BaseContainer(object):

    @abc.abstractmethod
    def list_objects(self, prefix=None):
        pass

    @abc.abstractmethod
    def get_object(self, container, obj):
        pass

    @abc.abstractmethod
    def upload_file(self, fobj, name):
        pass


@six.add_metaclass(abc.ABCMeta)
class BaseObject(object):

    @abc.abstractmethod
    def download(self):
        """Download the contents of the object as a string.
        """
        pass

    @abc.abstractmethod
    def delete(self):
        pass

    @abc.abstractmethod
    def _generate_signed_url(self, seconds, method):
        pass

    def generate_signed_url(self, seconds, method='GET'):
        if seconds <= 0:
            raise ValueError('Parameter `seconds` must be positive')
        if method not in SIGNED_URL_METHODS:
            raise ValueError(
                'Parameter `method` must be one of {}'.format(
                    ', '.join(SIGNED_URL_METHODS)
                )
            )
        return self._generate_signed_url(seconds, method)

    @abc.abstractproperty
    def size(self):
        pass

    @abc.abstractproperty
    def date_modified(self):
        pass

    @abc.abstractproperty
    def content_type(self):
        pass

