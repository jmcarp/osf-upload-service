#!/usr/bin/env python
# encoding: utf-8

import hashlib


SCHEME = 'http'
DOMAIN = 'localhost'
PORT = 7777
PROCESSES = 0
DEBUG = True

SENTRY_DSN = None

UPLOAD_EXPIRATION_SECONDS = 60
DOWNLOAD_EXPIRATION_SECONDS = 60
PING_DEBOUNCE = 60

FILE_CACHE_PATH = '/tmp'

# Backend options
STORAGE_CLIENT_CLASS = None
STORAGE_CLIENT_OPTIONS = {
    'username': None,
    'api_key': None,
    'region': None,
}
STORAGE_CONTAINER_NAME = None

# HMAC options
SIGNATURE_HEADER_KEY = 'X-Signature'
URLS_HMAC_SECRET = 'changeme'
URLS_HMAC_DIGEST = hashlib.sha1
UPLOAD_HMAC_SECRET = 'changeme'
UPLOAD_HMAC_DIGEST = hashlib.sha1
WEBHOOK_HMAC_SECRET = 'changeme'
WEBHOOK_HMAC_DIGEST = hashlib.sha1

# Hashing options
UPLOAD_PRIMARY_HASH = hashlib.sha256
UPLOAD_SECONDARY_HASHES = [hashlib.md5, hashlib.sha1]
UPLOAD_HASH_CHUNK_SIZE = 1024 * 1024

# Retry options
UPLOAD_RETRY_ATTEMPTS = 5
UPLOAD_RETRY_DELAY = 30
UPLOAD_RETRY_BACKOFF = 1

# Celery settings
BROKER_URL = 'amqp://'
CELERY_RESULT_BACKEND = 'redis://'
CELERY_IMPORTS = 'cloudstorm.queue.tasks'
CELERY_DISABLE_RATE_LIMITS = True
CELERY_TASK_RESULT_EXPIRES = 60
