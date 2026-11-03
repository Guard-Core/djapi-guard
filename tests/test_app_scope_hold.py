from collections.abc import Callable, Iterator
from typing import Any

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync._utils.app_scope import _current_app_scope, app_scope_of
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

PROXY = "10.0.0.1"


def _middleware(
    prefix: str,
    proxies: tuple[str, ...],
    view: Callable[[HttpRequest], HttpResponse],
) -> DjangoAPIGuard:
    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig[SyncGuardRequest](
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX + prefix,
        trusted_proxies=proxies,
        enable_agent=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )
    return DjangoAPIGuard(view)


@pytest.fixture
def cleanup() -> Iterator[list[DjangoAPIGuard]]:
    apps: list[DjangoAPIGuard] = []
    yield apps
    for app in apps:
        ip_ban_manager_for(app.config).unban_ip(PROXY, config=app.config)


def _banning_view(
    seen: dict[str, Any], holder: list[DjangoAPIGuard]
) -> Callable[[HttpRequest], HttpResponse]:
    def view(request: HttpRequest) -> HttpResponse:
        app = holder[0]
        seen["scope"] = _current_app_scope.get()
        seen["banned"] = ip_ban_manager_for(app.config).ban_ip(PROXY, 60)
        return HttpResponse("ok")

    return view


def test_a_ban_in_a_view_goes_through_the_views_own_app(
    cleanup: list[DjangoAPIGuard],
) -> None:
    seen_a: dict[str, Any] = {}
    seen_b: dict[str, Any] = {}
    holder_a: list[DjangoAPIGuard] = []
    holder_b: list[DjangoAPIGuard] = []
    app_a = _middleware("wp136-hold:", (PROXY,), _banning_view(seen_a, holder_a))
    holder_a.append(app_a)
    app_b = _middleware("wp136-hold:", (), _banning_view(seen_b, holder_b))
    holder_b.append(app_b)
    cleanup.extend([app_a, app_b])
    factory = RequestFactory()

    app_a(factory.get("/x"))
    app_b(factory.get("/x"))
    app_a(factory.get("/x"))

    assert seen_a["scope"] is app_scope_of(app_a.config)
    assert seen_b["scope"] is app_scope_of(app_b.config)
    assert seen_a["banned"] is False
    assert seen_b["banned"] is True
    assert _current_app_scope.get() is None


def test_a_raising_view_leaves_no_scope_for_the_next_request() -> None:
    def view(request: HttpRequest) -> HttpResponse:
        raise RuntimeError("view failed")

    app = _middleware("wp136-boom:", (), view)

    with pytest.raises(RuntimeError, match="view failed"):
        app(RequestFactory().get("/x"))

    assert _current_app_scope.get() is None


def test_a_nested_app_hands_back_the_outer_apps_scope(
    cleanup: list[DjangoAPIGuard],
) -> None:
    inner = _middleware("wp136-nest:", (), lambda request: HttpResponse("inner"))
    seen: dict[str, Any] = {}

    def outer_view(request: HttpRequest) -> HttpResponse:
        inner(request)
        seen["after"] = _current_app_scope.get()
        return HttpResponse("outer")

    outer = _middleware("wp136-nest:", (PROXY,), outer_view)
    cleanup.extend([inner, outer])

    outer(RequestFactory().get("/x"))

    assert seen["after"] is app_scope_of(outer.config)
    assert _current_app_scope.get() is None
