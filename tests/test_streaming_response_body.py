"""A streamed Django response behind the middleware (LEDGER 6.114).

Probe at djapi-guard e2a1593 with guard-core efa0ffde: a custom_response_modifier
that read `.body` on a StreamingHttpResponse hit an AttributeError from
`.content`, the engine logged it and dropped every header edit made after the read.
"""

import logging
from collections.abc import Iterator
from typing import Any

import pytest
from django.http import HttpRequest, HttpResponse, StreamingHttpResponse
from django.http.response import HttpResponseBase
from django.test import RequestFactory, override_settings
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse

from djangoapi_guard.adapters import DjangoGuardResponse
from djangoapi_guard.middleware import DjangoAPIGuard
from tests import engine_parity_urls

BODY = b'{"message": "Echo response"}'


@pytest.fixture(autouse=True)
def _urlconf() -> Iterator[None]:
    with override_settings(ROOT_URLCONF="tests.engine_parity_urls", MIDDLEWARE=[]):
        yield


def _guard(kind: str, **overrides: Any) -> DjangoAPIGuard:
    def view(request: HttpRequest) -> HttpResponseBase:
        if kind == "streamed":
            return StreamingHttpResponse(iter([BODY]))
        return HttpResponse(b"" if kind == "empty" else BODY)

    base: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "whitelist": None,
        "blacklist": [],
    }
    base.update(overrides)
    with override_settings(GUARD_SECURITY_CONFIG=SecurityConfig(**base)):
        guard = DjangoAPIGuard(view)
    guard.set_decorator_handler(engine_parity_urls.security)
    return guard


def _get(guard: DjangoAPIGuard, client_ip: str = "203.0.113.9") -> HttpResponseBase:
    request = RequestFactory().get("/open/")
    request.META["REMOTE_ADDR"] = client_ip
    return guard(request)


def test_body_of_a_streamed_response_is_none_not_an_exception() -> None:
    streamed = DjangoGuardResponse(StreamingHttpResponse(iter([BODY])))

    assert streamed.body is None
    assert streamed.read_body_prefix(10) == b""


def test_body_of_a_plain_response_is_its_bytes() -> None:
    assert DjangoGuardResponse(HttpResponse(BODY)).body == BODY


def test_modifier_reading_the_body_of_a_streamed_response_raises_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    seen: list[bytes | None] = []

    def modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Before"] = "1"
        seen.append(response.body)
        response.headers["X-After"] = "1"
        return response

    guard = _guard("streamed", custom_response_modifier=modifier)
    with caplog.at_level(logging.WARNING):
        response = _get(guard)

    assert response.streaming
    assert response.status_code == 200
    assert seen == [None]
    assert response.headers["X-Before"] == "1"
    assert response.headers["X-After"] == "1"
    assert not [r for r in caplog.records if "custom_response_modifier" in r.message]


def test_modifier_reading_the_body_of_a_plain_response_sees_its_bytes() -> None:
    seen: list[bytes | None] = []

    def modifier(response: GuardResponse) -> GuardResponse:
        seen.append(response.body)
        return response

    _get(_guard("plain", custom_response_modifier=modifier))

    assert seen == [BODY]


def test_return_rule_verdict_of_a_streamed_response_is_the_empty_body_verdict(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rule = {
        "rule_type": "return_pattern",
        "threshold": 2,
        "window": 60,
        "pattern": "json:message==Echo response",
        "action": "ban",
        "ban_duration": 30,
    }

    def codes(kind: str, client_ip: str) -> list[int]:
        guard = _guard(
            kind, behavior_scan_response_body=True, global_behavior_rules=[rule]
        )
        return [_get(guard, client_ip).status_code for _ in range(5)]

    with caplog.at_level(logging.WARNING):
        assert codes("plain", "203.0.113.20") == [200, 200, 200, 403, 403]
        streamed = codes("streamed", "203.0.113.21")
        assert streamed == codes("empty", "203.0.113.22") == [200] * 5
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
