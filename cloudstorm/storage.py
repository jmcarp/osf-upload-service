# encoding: utf-8

from boto.glacier.layer2 import Layer2

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


def _get_layer2():
    return Layer2(
        aws_access_key_id=settings.AWS_ACCESS_KEY,
        aws_secret_access_key=settings.AWS_SECRET_KEY,
    )
layer2_proxy = LazyContainer(_get_layer2)


def _get_glacier_vault():
    return layer2_proxy.get().create_vault(settings.GLACIER_VAULT)
vault_proxy = LazyContainer(_get_glacier_vault)
