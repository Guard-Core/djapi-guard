import logging
import sys
from collections.abc import Iterator

import pytest
from django.test import Client, override_settings
from django.urls import clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import djangoapi_guard._decorator_adoption as adoption
import djangoapi_guard.middleware as middleware_module

_URLS = "tests.cbv_decorator_urls"


def _config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        ban_on_hostile_signals=False,
        rate_limit=1000,
    )


@pytest.fixture
def served() -> Iterator[Client]:
    adoption._created.clear()
    middleware_module._several_warned.clear()
    sys.modules.pop(_URLS, None)
    clear_url_caches()
    try:
        with override_settings(
            ROOT_URLCONF=_URLS,
            GUARD_SECURITY_CONFIG=_config(),
            GUARD_DECORATOR=f"{_URLS}.guard_deco",
        ):
            yield Client()
    finally:
        sys.modules.pop(_URLS, None)
        clear_url_caches()
        adoption._created.clear()
        rate_limit_handler(_config()).reset()


@pytest.mark.parametrize(
    "path", ["/function/", "/as-view/", "/method/", "/dispatch/", "/class/", "/both/"]
)
def test_a_route_decorator_is_enforced_however_it_is_applied(
    served: Client, path: str
) -> None:
    refused = served.get(path)
    allowed = served.get(path, HTTP_X_NEED="1")

    assert (refused.status_code, allowed.status_code) == (400, 200)


def test_a_method_decorator_guards_its_own_http_method_only(served: Client) -> None:
    assert served.post("/method/").status_code == 200


def test_decorators_applied_in_two_places_warn_once_and_name_them(
    served: Client, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        served.get("/both/", HTTP_X_NEED="1")
        served.get("/both/", HTTP_X_NEED="1")

    lines = [r for r in caplog.records if "applied to" in r.getMessage()]
    assert len(lines) == 1
    assert "the view function" in lines[0].getMessage()
    assert "its get method" in lines[0].getMessage()
