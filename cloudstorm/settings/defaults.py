# -*- coding: utf-8 -*-

import hashlib

from cloudstorm.backend import contrib


FILE_CACHE_PATH = '/tmp'

# Backend options
STORAGE_CLIENT_CLASS = contrib.cloudfiles.CloudFilesClient
STORAGE_CLIENT_OPTIONS = {
    'username': None,
    'api_key': None,
    'region': None,
}
STORAGE_CONTAINER_NAME = None

# HMAC options
UPLOAD_HMAC_SECRET = 'changeme'
UPLOAD_HMAC_DIGEST = hashlib.sha1
WEBHOOK_HMAC_SECRET = 'changeme'
WEBHOOK_HMAC_DIGEST = hashlib.sha1

# Hashing options
UPLOAD_PRIMARY_HASH = hashlib.sha256
UPLOAD_HASH_CHUNK_SIZE = 1024 * 1024

# Retry options
UPLOAD_RETRY_ATTEMPTS = 5
UPLOAD_RETRY_DELAY = 30
UPLOAD_RETRY_BACKOFF = 1

# Celery settings
BROKER_URL = 'amqp://'
CELERY_RESULT_BACKEND = 'amqp://'
CELERY_IMPORTS = 'cloudstorm.queue.tasks'

