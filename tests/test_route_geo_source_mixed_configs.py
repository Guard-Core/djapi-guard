import logging

import pytest
from django.core.handlers.base import BaseHandler
from django.http import HttpRequest
from django.http.response import HttpResponseBase
from django.test import RequestFactory, override_settings
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard
from tests import geo_mixed_urls


def test_decorator_false_under_middleware_true_starts_and_answers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    middleware_config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        fail_on_misconfiguration=True,
        trusted_proxies=("127.0.0.1",),
    )
    with override_settings(ROOT_URLCONF="tests.geo_mixed_urls", MIDDLEWARE=[]):
        handler = BaseHandler()
        handler.load_middleware()

        def get_response(request: HttpRequest) -> HttpResponseBase:
            return handler.get_response(request)

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with override_settings(GUARD_SECURITY_CONFIG=middleware_config):
                guard = DjangoAPIGuard(get_response)
            guard.set_decorator_handler(geo_mixed_urls.security)
            reported_before_any_request = caplog.text.count("no GeoIP database")
            statuses = []
            for _ in range(2):
                request = RequestFactory().get("/geo/")
                request.META["REMOTE_ADDR"] = "203.0.113.5"
                statuses.append(guard(request).status_code)

    assert statuses == [200, 200]
    assert reported_before_any_request == 0
    assert caplog.text.count("no GeoIP database") == 1
