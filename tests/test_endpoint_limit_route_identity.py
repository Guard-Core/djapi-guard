from collections.abc import Iterator
from typing import Any, cast

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, override_settings
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler

from djangoapi_guard.adapters import DjangoGuardRequest
from djangoapi_guard.middleware import DjangoAPIGuard

URLCONF = override_settings(
    ROOT_URLCONF="tests.urls_route_identity",
    USE_I18N=True,
    LANGUAGE_CODE="en",
    LANGUAGES=[("en", "English"), ("fr", "French")],
)


@pytest.fixture(autouse=True)
def _urlconf_and_clean_limits() -> Iterator[None]:
    with URLCONF:
        yield
    rate_limit_handler(SecurityConfig(enable_redis=False, enable_agent=False)).reset()


def _middleware(
    limits: dict[str, tuple[int, int]], **config_options: Any
) -> DjangoAPIGuard:
    import django.conf

    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1000,
        endpoint_rate_limits=limits,
        passive_mode=False,
        **config_options,
    )
    return DjangoAPIGuard(lambda request: HttpResponse("OK"))


def _statuses(middleware: DjangoAPIGuard, paths: list[str]) -> list[int]:
    factory = RequestFactory()
    return [middleware(factory.get(path)).status_code for path in paths]


def test_optional_slash_re_path_shares_one_limit() -> None:
    middleware = _middleware({"/login": (2, 60)})

    assert _statuses(middleware, ["/login", "/login/", "/login", "/login/"]) == [
        200,
        200,
        429,
        429,
    ]


def test_i18n_languages_of_one_view_share_a_key_resolved_at_init() -> None:
    middleware = _middleware({"/en/account/": (2, 60)})

    assert _statuses(middleware, ["/en/account/", "/fr/account/", "/en/account/"]) == [
        200,
        200,
        429,
    ]


def test_concrete_id_key_stays_per_resource() -> None:
    middleware = _middleware({"/users/42/": (1, 60)})

    assert _statuses(middleware, ["/users/42/", "/users/7/", "/users/42/"]) == [
        200,
        200,
        429,
    ]


def test_login_and_login_slash_keys_are_both_enforced() -> None:
    middleware = _middleware({"/login": (3, 60), "/login/": (1, 60)})

    assert _statuses(middleware, ["/login", "/login", "/login"]) == [200, 429, 429]


def test_key_the_router_cannot_resolve_still_limits_through_the_fallback() -> None:
    middleware = _middleware({"/login/.": (1, 60)}, fail_on_misconfiguration=False)

    assert _statuses(middleware, ["/login", "/login"]) == [200, 429]


def test_key_the_router_cannot_resolve_refuses_to_start_by_default() -> None:
    with pytest.raises(ValueError, match="has a dot segment"):
        _middleware({"/login/.": (1, 60)})


def test_resolve_route_reports_the_view_and_its_path_parameters() -> None:
    from tests.urls_route_identity import user

    middleware = _middleware({})

    assert middleware.resolve_route("/users/042/") == ((user, (("user_id", "42"),)),)
    assert middleware.resolve_route("/nope/") == ()


def _request_identity(
    middleware: DjangoAPIGuard, path: str
) -> tuple[Any, tuple[tuple[str, str], ...]]:
    request = RequestFactory().get(path)
    middleware._populate_guard_state(DjangoGuardRequest(request), request)
    identity: tuple[Any, tuple[tuple[str, str], ...]]
    identity = cast(Any, request).guard_route_identity
    return identity


@pytest.mark.parametrize(
    "path", ["/login", "/users/5/", "/panel/", "/wrapped/", "/fr/account/"]
)
def test_request_identity_equals_the_identity_resolve_route_returns(path: str) -> None:
    middleware = _middleware({path: (5, 60)})

    assert _request_identity(middleware, path) in middleware.resolve_route(path)


def test_request_identity_is_not_built_without_endpoint_limits() -> None:
    middleware = _middleware({})
    request: HttpRequest = RequestFactory().get("/login")

    middleware._populate_guard_state(DjangoGuardRequest(request), request)

    assert not hasattr(request, "guard_route_identity")


def test_i18n_prefixed_view_resolves_without_locale_middleware() -> None:
    middleware = _middleware({})
    request = RequestFactory().get("/fr/account/")

    middleware._populate_guard_state(DjangoGuardRequest(request), request)

    assert not hasattr(request, "guard_route_unresolved")
    assert cast(Any, request).guard_endpoint_id == "tests.urls_route_identity.account"
