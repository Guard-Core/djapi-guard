import uuid
from typing import Any, cast
from unittest.mock import Mock

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.exceptions import MisconfigurationError
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipban_handler import ip_ban_manager, ip_ban_manager_for
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityDecorator
from djangoapi_guard.middleware import DjangoAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

PEER = "203.0.113.9"


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "rate_limit": 1000,
    }
    fields.update(overrides)
    return SecurityConfig[SyncGuardRequest](**fields)


def _middleware(
    config: SecurityConfig[SyncGuardRequest],
    monkeypatch: pytest.MonkeyPatch,
) -> DjangoAPIGuard:
    monkeypatch.setattr("djangoapi_guard.middleware.resolve_decorator", lambda: None)
    django.conf.settings.GUARD_SECURITY_CONFIG = config
    return DjangoAPIGuard(lambda request: HttpResponse("OK"))


def _view(decorator: SecurityDecorator, name: str, *wraps: Any) -> str:
    view = Mock()
    view.__name__ = view.__qualname__ = name
    view.__module__ = "late_decorator_tests"
    for wrap in wraps:
        view = wrap(view)
    return cast(str, cast(Any, view)._guard_route_id)


def _get(middleware: DjangoAPIGuard, route_id: str | None = None) -> int:
    request: HttpRequest = RequestFactory().get("/", REMOTE_ADDR=PEER)
    if route_id is not None:
        cast(Any, request).guard_route_id = route_id
    return int(middleware(request).status_code)


def test_a_ban_rule_of_a_late_decorator_bans_on_the_apps_ban_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _middleware(_config(), monkeypatch)
    assert _get(first) == 200
    config = _config()
    middleware = _middleware(config, monkeypatch)
    assert _get(middleware) == 200
    apps_manager = ip_ban_manager_for(config)
    assert apps_manager is not ip_ban_manager
    decorator = SecurityDecorator(SecurityConfig())
    route_id = _view(
        decorator, "counted", decorator.usage_monitor(max_calls=1, action="ban")
    )

    middleware.set_decorator_handler(decorator)
    statuses = [_get(middleware, route_id) for _ in range(3)]

    assert statuses[0] == 200
    assert apps_manager.is_ip_banned(PEER)
    assert decorator.behavior_tracker.bound_ban_manager is apps_manager


def test_a_late_decorators_rule_counts_on_the_decorators_tracker_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    middleware = _middleware(_config(), monkeypatch)
    assert _get(middleware) == 200
    decorator = SecurityDecorator(SecurityConfig())
    route_id = _view(
        decorator, "counted", decorator.usage_monitor(max_calls=5, action="log")
    )

    middleware.set_decorator_handler(decorator)
    assert _get(middleware, route_id) == 200

    initializer = middleware.handler_initializer
    assert initializer is not None
    assert middleware.behavioral_processor is not None
    held = middleware.behavioral_processor.context.behavior_tracker
    assert held in (None, decorator.behavior_tracker)
    assert initializer.behavior_tracker in (None, decorator.behavior_tracker)
    assert any(decorator.behavior_tracker.usage_counts.values())


def test_a_late_decorators_tracker_gets_redis_once_adoption_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"{REDIS_PREFIX}wp779{uuid.uuid4().hex[:8]}:",
    )
    middleware = _middleware(config, monkeypatch)
    assert _get(middleware) == 200
    decorator = SecurityDecorator(SecurityConfig())

    middleware.set_decorator_handler(decorator)
    assert _get(middleware) == 200

    initializer = middleware.handler_initializer
    assert initializer is not None
    assert decorator.behavior_tracker.redis_handler is initializer.redis_handler
    assert decorator.behavior_tracker.redis_handler is not None


def test_a_route_country_rule_of_a_late_decorator_builds_the_geo_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    middleware = _middleware(_config(ipinfo_token="test_token"), monkeypatch)
    assert _get(middleware) == 200
    before = middleware.geo_ip_handler
    decorator = SecurityDecorator(SecurityConfig(fail_on_misconfiguration=False))
    _view(decorator, "by_country", decorator.block_countries(["XX"]))

    middleware.set_decorator_handler(decorator)

    initializer = middleware.handler_initializer
    assert initializer is not None
    assert before is None
    assert middleware.geo_ip_handler is initializer.geo_ip_handler
    assert middleware.geo_ip_handler is not None


def test_a_raise_in_the_adoption_leaves_the_previous_decorator_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    middleware = _middleware(_config(), monkeypatch)
    assert _get(middleware) == 200
    previous = SecurityDecorator(SecurityConfig())
    middleware.set_decorator_handler(previous)
    candidate = SecurityDecorator(SecurityConfig(fail_on_misconfiguration=False))
    _view(candidate, "by_country", candidate.block_countries(["XX"]))
    candidate.config.fail_on_misconfiguration = True

    with pytest.raises(MisconfigurationError):
        middleware.set_decorator_handler(candidate)

    initializer = middleware.handler_initializer
    assert initializer is not None
    assert middleware.guard_decorator is previous
    assert initializer.guard_decorator is previous
    assert middleware.route_resolver.context.guard_decorator is previous
    assert middleware.response_factory is not None
    assert middleware.response_factory.context.guard_decorator is previous
    assert middleware.behavioral_processor is not None
    assert middleware.behavioral_processor.context.guard_decorator is previous
