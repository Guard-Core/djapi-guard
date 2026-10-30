import sys
from collections.abc import Iterator

import pytest
from django.test import Client, override_settings
from django.urls import clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import djangoapi_guard._decorator_adoption as adoption

_MODULES = ("tests.request_urlconf_admin_urls", "tests.request_urlconf_main_urls")


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
    for name in _MODULES:
        sys.modules.pop(name, None)
    clear_url_caches()
    try:
        with override_settings(
            ROOT_URLCONF="tests.request_urlconf_main_urls",
            GUARD_SECURITY_CONFIG=_config(),
            GUARD_DECORATOR="tests.request_urlconf_admin_urls.guard_deco",
            MIDDLEWARE=[
                "tests.request_urlconf_middleware.UrlconfByHost",
                "djangoapi_guard.middleware.DjangoAPIGuard",
            ],
        ):
            yield Client()
    finally:
        for name in _MODULES:
            sys.modules.pop(name, None)
        clear_url_caches()
        adoption._created.clear()
        rate_limit_handler(_config()).reset()


def test_a_decorator_in_the_requests_own_urlconf_is_enforced(served: Client) -> None:
    refused = served.get("/admin/", HTTP_HOST="admin.example.com")
    allowed = served.get("/admin/", HTTP_HOST="admin.example.com", HTTP_X_NEED="1")

    assert (refused.status_code, allowed.status_code) == (400, 200)


def test_the_root_urlconf_still_serves_the_other_host(served: Client) -> None:
    assert served.get("/hello/", HTTP_HOST="www.example.com").status_code == 200
