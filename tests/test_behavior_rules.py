import itertools
from collections.abc import Iterator
from typing import Any

import pytest
from django.core.handlers.base import BaseHandler
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory, override_settings
from django.urls import path
from guard_core.models import BehaviorRuleConfig

from djangoapi_guard import SecurityConfig, SecurityDecorator
from djangoapi_guard.middleware import DjangoAPIGuard

_IPS = itertools.count(1)

security = SecurityDecorator(
    SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
)


def ping(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


urlpatterns = [path("ping/", ping)]


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
