import itertools
from collections.abc import Iterator
from typing import Any
from unittest.mock import Mock

import pytest
from django.core.handlers.base import BaseHandler
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory, override_settings
from django.urls import path
from guard_core.models import BehaviorRuleConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule

from djangoapi_guard import SecurityConfig, SecurityDecorator
from djangoapi_guard.middleware import DjangoAPIGuard

_IPS = itertools.count(1)

security = SecurityDecorator(
    SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
)


@security.usage_monitor(max_calls=2, window=60, action="throttle")
def limited(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


def ping(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


urlpatterns = [path("limited/", limited), path("ping/", ping)]


@pytest.fixture(autouse=True)
def _urlconf() -> Iterator[None]:
    with override_settings(ROOT_URLCONF=__name__, MIDDLEWARE=[]):
        yield


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": True,
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _guard(config: SecurityConfig) -> DjangoAPIGuard:
    handler = BaseHandler()
    handler.load_middleware()

    def get_response(request: HttpRequest) -> HttpResponse:
        response = handler.get_response(request)
        assert isinstance(response, HttpResponse)
        return response

    with override_settings(GUARD_SECURITY_CONFIG=config):
        guard = DjangoAPIGuard(get_response)
    guard.set_decorator_handler(security)
    return guard


def _responses(config: SecurityConfig, paths: list[str]) -> list[HttpResponse]:
    guard = _guard(config)
    ip = f"198.51.100.{next(_IPS)}"
    responses = []
    for target in paths:
        request = RequestFactory().get(target)
        request.META["REMOTE_ADDR"] = ip
        responses.append(guard(request))
    return responses


def test_route_throttle_answers_429_with_retry_after() -> None:
    responses = _responses(_config(), ["/limited/"] * 4)
    assert [r.status_code for r in responses] == [200, 200, 429, 429]
    assert ["Retry-After" in r for r in responses] == [False, False, True, True]
    assert all(1 <= int(r["Retry-After"]) <= 60 for r in responses[2:])


def test_global_throttle_covers_unrouted_paths() -> None:
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="usage", threshold=2, window=60, action="throttle"
            ),
        )
    )
    responses = _responses(config, ["/nope-1/", "/nope-2/", "/nope-3/"])
    assert [r.status_code for r in responses] == [404, 404, 429]


def test_throttled_requests_still_count_toward_a_global_ban_rule() -> None:
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(rule_type="usage", threshold=3, window=60, action="ban"),
        )
    )
    responses = _responses(config, ["/limited/"] * 5)
    assert [r.status_code for r in responses] == [200, 200, 429, 429, 403]


def test_global_return_rule_halves_its_threshold_after_a_detection_hit() -> None:
    config = _config(
        enable_penetration_detection=True,
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=4,
                window=60,
                pattern="status:404",
                action="ban",
                correlate_with_detection=True,
            ),
        ),
    )
    paths = ["/ping/?q=<script>alert(1)</script>"] + ["/missing/"] * 4 + ["/ping/"]
    statuses = [r.status_code for r in _responses(config, paths)]
    assert statuses[1:] == [404, 404, 404, 403, 403]


def test_decorator_usage_rules_wrapper_returns_the_throttle_response() -> None:
    guard = _guard(_config())
    route_config = Mock()
    route_config.behavior_rules = [
        BehaviorRule("usage", threshold=1, window=60, action="throttle")
    ]
    statuses = []
    for _ in range(2):
        request = RequestFactory().get("/limited/")
        response = guard._process_decorator_usage_rules(
            request, "127.0.0.1", route_config
        )
        statuses.append(None if response is None else response.status_code)
    assert statuses == [None, 429]


@pytest.mark.parametrize("client_ip", ["", "127.0.0.1"])
def test_requests_without_rules_skip_the_usage_call(
    client_ip: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _guard(_config())
    usage = Mock()
    monkeypatch.setattr(guard.behavioral_processor, "process_usage_rules", usage)
    assert guard._process_behavioral_usage(Mock(), client_ip, None) is None
    usage.assert_not_called()
