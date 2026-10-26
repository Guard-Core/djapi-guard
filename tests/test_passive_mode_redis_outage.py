import logging
from collections.abc import Generator
from unittest.mock import patch

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import middleware as middleware_module
from djangoapi_guard.middleware import DjangoAPIGuard

INIT_OUTAGE_LINE = "Redis unavailable during initialization"


@pytest.fixture(autouse=True)
def _reset_outage_samples() -> Generator[None, None, None]:
    middleware_module._init_outage_samples.clear()
    yield
    middleware_module._init_outage_samples.clear()


def _middleware(passive_mode: bool) -> DjangoAPIGuard:
    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        passive_mode=passive_mode,
    )

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("OK", status=200)

    return DjangoAPIGuard(get_response)


def test_passive_cold_start_with_redis_down_admits_http_and_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    middleware = _middleware(passive_mode=True)
    factory = RequestFactory()

    with patch.object(
        middleware.handler_initializer,
        "initialize_redis_handlers",
        side_effect=GuardRedisError(503, "Redis connection failed"),
    ):
        with caplog.at_level(logging.ERROR):
            responses = [middleware(factory.get("/")) for _ in range(3)]

    assert [r.status_code for r in responses] == [200, 200, 200]
    assert "Retry-After" not in responses[0]
    assert middleware._handlers_initialized is False
    lines = [
        r
        for r in caplog.records
        if INIT_OUTAGE_LINE in r.getMessage() and "passive_mode" in r.getMessage()
    ]
    assert len(lines) == 1


def test_not_passive_cold_start_with_redis_down_keeps_503_with_retry_after() -> None:
    middleware = _middleware(passive_mode=False)

    with patch.object(
        middleware.handler_initializer,
        "initialize_redis_handlers",
        side_effect=GuardRedisError(503, "Redis connection failed"),
    ):
        response = middleware(RequestFactory().get("/"))

    assert response.status_code == 503
    assert response["Retry-After"] == "5"
