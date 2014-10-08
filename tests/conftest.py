# -*- coding: utf-8 -*-

import pytest

from cloudstorm import settings


@pytest.fixture(autouse=True)
def ensure_different_hmac_secrets(monkeypatch):
    """Ensure that HMAC secret keys for uploads and webhooks are different so
    that tests fail if we use the wrong keys.
    """
    monkeypatch.setattr(settings, 'URLS_HMAC_SECRET', 'urls-secret')
    monkeypatch.setattr(settings, 'UPLOAD_HMAC_SECRET', 'upload-secret')
    monkeypatch.setattr(settings, 'WEBHOOK_HMAC_SECRET', 'webhook-secret')

