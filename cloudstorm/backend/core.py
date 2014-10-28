#!/usr/bin/env python
# encoding: utf-8

import abc
import six

from . import errors


SIGNED_URL_METHODS = ['GET', 'PUT']


@six.add_metaclass(abc.ABCMeta)
class SignedUrlBase(object):

    @abc.abstractmethod
    def _generate_signed_url(self, seconds, method, *args, **kwargs):
        raise NotImplementedError

    def generate_signed_url(self, seconds, method, *args, **kwargs):
        if seconds <= 0:
            raise ValueError('Parameter `seconds` must be positive')
        if method not in SIGNED_URL_METHODS:
            raise ValueError(
                'Parameter `method` must be one of {}'.format(
                    ', '.join(SIGNED_URL_METHODS)
                )
            )
        return self._generate_signed_url(seconds, method, *args, **kwargs)


class BaseClient(SignedUrlBase):

    @abc.abstractmethod
    def get_container(self, container):
        raise NotImplementedError

    @abc.abstractmethod
    def create_container(self, container):
        raise NotImplementedError


class BaseContainer(SignedUrlBase):

    @abc.abstractproperty
    def name(self):
        raise NotImplementedError

    @abc.abstractmethod
    def list_objects(self, prefix=None):
        raise NotImplementedError

    @abc.abstractmethod
    def get_object(self, obj):
        raise NotImplementedError

    @abc.abstractmethod
    def upload_file(self, fobj, name):
        raise NotImplementedError

    def get_or_upload_file(self, fobj, name):
        try:
            return self.get_object(name)
        except errors.NotFound:
            return self.upload_file(fobj, name)

    def __repr__(self):
        return '<{klass}: {name}>'.format(
            klass=self.__class__.__name__,
            name=self.name,
        )


class BaseObject(SignedUrlBase):

    @abc.abstractproperty
    def name(self):
        raise NotImplementedError

    @abc.abstractproperty
    def size(self):
        raise NotImplementedError

    @abc.abstractproperty
    def date_modified(self):
        raise NotImplementedError

    @abc.abstractproperty
    def content_type(self):
        raise NotImplementedError

    @abc.abstractproperty
    def location(self):
        raise NotImplementedError

    @abc.abstractmethod
    def download(self):
        """Download the contents of the object as a string.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self):
        raise NotImplementedError

    def __repr__(self):
        return '<{klass}: {name}>'.format(
            klass=self.__class__.__name__,
            name=self.name,
        )
