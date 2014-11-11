# encoding: utf-8

from cloudstorm.utils import LazyContainer
from cloudstorm import settings


def _get_storage_client():
    return settings.STORAGE_CLIENT_CLASS(
        **settings.STORAGE_CLIENT_OPTIONS
    )
client_proxy = LazyContainer(_get_storage_client)


def _get_storage_container():
    return client_proxy.get().create_container(
        settings.STORAGE_CONTAINER_NAME
    )
container_proxy = LazyContainer(_get_storage_container)
