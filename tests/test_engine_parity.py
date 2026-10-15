"""Engine parity: the adapter routes through the engine exactly like fastapi-guard.

Real Django URL resolution and views behind the middleware, real engine bypass
handler and response factory. The metrics collector is spied on (it still runs)
to prove which responses reach the engine response pass.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.core.handlers.base import BaseHandler
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse

from djangoapi_guard.middleware import DjangoAPIGuard
from tests import engine_parity_urls


@pytest.fixture(autouse=True)
def _urlconf() -> Iterator[None]:
    with override_settings(ROOT_URLCONF="tests.engine_parity_urls", MIDDLEWARE=[]):
        yield


def _build(**overrides: Any) -> tuple[DjangoAPIGuard, list[str]]:
    base: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "whitelist": None,
        "blacklist": [],
        "exclude_paths": ["/health"],
        "security_headers": {"enabled": True},
    }
    base.update(overrides)
    handler = BaseHandler()
    handler.load_middleware()
    with override_settings(GUARD_SECURITY_CONFIG=SecurityConfig(**base)):
        guard = DjangoAPIGuard(handler.get_response)
    guard.set_decorator_handler(engine_parity_urls.security)
    metrics: list[str] = []
    assert guard.metrics_collector is not None
    real = guard.metrics_collector.collect_request_metrics

    def spy(request: Any, response_time: float, status_code: int) -> None:
        metrics.append(request.url_path)
        real(request, response_time, status_code)

    guard.metrics_collector.collect_request_metrics = spy  # type: ignore[method-assign]
    return guard, metrics


def _get(
    guard: DjangoAPIGuard, path: str, remote_addr: str | None = "127.0.0.1"
) -> HttpResponse:
    request = RequestFactory().get(path)
    if remote_addr is None:
        request.META.pop("REMOTE_ADDR", None)
    else:
        request.META["REMOTE_ADDR"] = remote_addr
    return guard(request)


def test_missing_security_config_is_rejected() -> None:
    with override_settings():
        from django.conf import settings

        if hasattr(settings, "GUARD_SECURITY_CONFIG"):
            del settings.GUARD_SECURITY_CONFIG
        with pytest.raises(ImproperlyConfigured, match="GUARD_SECURITY_CONFIG"):
            DjangoAPIGuard(lambda request: HttpResponse("ok"))


def test_excluded_path_reaches_view_with_scoped_checks_and_response_pass() -> None:
    guard, metrics = _build(blacklist=["10.9.9.9"])

    ok = _get(guard, "/health/")
    assert ok.status_code == 200
    assert ok["X-Content-Type-Options"] == "nosniff"
    assert metrics == ["/health/"]

    blocked = _get(guard, "/health/", "10.9.9.9")
    assert blocked.status_code == 403
    assert metrics == ["/health/"]


def test_no_client_address_gets_fail_secure_403_by_default() -> None:
    guard, metrics = _build()

    resp = _get(guard, "/open/", None)

    assert resp.status_code == 403
    assert b"Client address could not be determined" in resp.content
    assert metrics == []


def test_no_client_address_fail_secure_false_runs_the_pipeline() -> None:
    guard, metrics = _build(fail_secure=False)

    resp = _get(guard, "/open/", None)

    assert resp.status_code == 200
    assert metrics == ["/open/"]


def test_route_bypass_reaches_real_view_and_skips_response_pass() -> None:
    def modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Modified"] = "1"
        return response

    guard, metrics = _build(custom_response_modifier=modifier)

    resp = _get(guard, "/bypassed/")

    assert resp.status_code == 200
    assert b"real view" in resp.content
    assert resp["X-Modified"] == "1"
    assert metrics == []
    assert "X-Content-Type-Options" not in resp


def test_blocked_request_emits_no_request_metrics() -> None:
    guard, metrics = _build(blacklist=["10.9.9.9"])

    assert _get(guard, "/open/", "10.9.9.9").status_code == 403
    assert metrics == []
    assert _get(guard, "/open/").status_code == 200
    assert metrics == ["/open/"]


def test_global_behavior_return_rule_fires() -> None:
    guard, _metrics = _build(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            {
                "rule_type": "return_pattern",
                "threshold": 2,
                "window": 60,
                "pattern": "json:message==Echo response",
                "action": "ban",
                "ban_duration": 30,
            }
        ],
    )

    codes = [_get(guard, "/open/", "203.0.113.9").status_code for _ in range(5)]

    assert codes[0] == 200
    assert 403 in codes
