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

FILE_PATH_PENDING = '/tmp/pending'
FILE_PATH_COMPLETE = '/tmp/complete'

MAX_REQUEST_SIZE = 1024 * 1024 * 128  # 128mb

USE_SSL = False
SSL_CERT_FILE = 'changeme'
SSL_KEY_FILE = 'changeme'

# Backend options
STORAGE_CLIENT_CLASS = None
STORAGE_CLIENT_OPTIONS = {
    'username': None,
    'api_key': None,
    'region': None,
}
STORAGE_CONTAINER_NAME = None

# Glacier options
AWS_ACCESS_KEY = 'changeme'
AWS_SECRET_KEY = 'changeme'
GLACIER_VAULT = 'changeme'

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

# Parity options
PARITY_CONTAINER_NAME = None
PARITY_REDUNDANCY = 5

# Retry options
UPLOAD_RETRY_ATTEMPTS = None
UPLOAD_RETRY_INIT_DELAY = 30
UPLOAD_RETRY_MAX_DELAY = 60 * 60
UPLOAD_RETRY_BACKOFF = 2
UPLOAD_RETRY_WARN_IDX = 5

HOOK_RETRY_ATTEMPTS = 5
HOOK_RETRY_INIT_DELAY = 30
HOOK_RETRY_MAX_DELAY = 60 * 60
HOOK_RETRY_BACKOFF = 2
HOOK_RETRY_WARN_IDX = None

PARITY_RETRY_ATTEMPTS = 5
PARITY_RETRY_INIT_DELAY = 30
PARITY_RETRY_MAX_DELAY = 60 * 60
PARITY_RETRY_BACKOFF = 2
PARITY_RETRY_WARN_IDX = None

# Celery settings
BROKER_URL = 'amqp://'
CELERY_RESULT_BACKEND = 'redis://'
CELERY_IMPORTS = 'cloudstorm.queue.tasks'
CELERY_DISABLE_RATE_LIMITS = True
CELERY_TASK_RESULT_EXPIRES = 60
