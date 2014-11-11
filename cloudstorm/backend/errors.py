# encoding: utf-8

class CloudStoreError(Exception):
    pass

class NotFound(CloudStoreError):
    pass
