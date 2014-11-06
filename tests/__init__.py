#!/usr/bin/env python
# encoding: utf-8

"""Patch settings for compatibility with tests.
"""

from cloudstorm import settings

# Disable Sentry
settings.SENTRY_DSN = None

# Ensure distinct secret keys
settings.URLS_HMAC_SECRET = 'urls-secret'
settings.UPLOAD_HMAC_SECRET = 'upload-secret'
settings.WEBHOOK_HMAC_SECRET = 'webhook-secret'

# Ensure finite retry attempts
settings.UPLOAD_RETRY_ATTEMPTS = 5
settings.HOOK_RETRY_ATTEMPTS = 5
