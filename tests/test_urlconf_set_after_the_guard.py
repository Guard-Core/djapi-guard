import logging
import sys
from typing import Any

import pytest
from django.test import Client, override_settings
from django.urls import clear_url_caches

import djangoapi_guard._decorator_adoption as adoption
from tests.wsgi_sweep_support import config

_MODULES = ("tests.request_urlconf_admin_urls", "tests.request_urlconf_main_urls")
_AFTER_THE_GUARD = (
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "tests.request_urlconf_middleware.UrlconfByHost",
)
_BEFORE_THE_GUARD = tuple(reversed(_AFTER_THE_GUARD))


def _fresh_modules() -> None:
    adoption._created.clear()
    for name in _MODULES:
        sys.modules.pop(name, None)


def _admin(client: Client, need: str | None = None) -> int:
    headers = {"X-Need": need} if need else None
    response = client.get("/admin/", headers=headers, HTTP_HOST="admin.example.com")
    return response.status_code


def _serve(order: tuple[str, ...], **config_fields: bool) -> Any:
    _fresh_modules()
    clear_url_caches()
    return override_settings(
        ROOT_URLCONF="tests.request_urlconf_main_urls",
        GUARD_SECURITY_CONFIG=config(**config_fields),
        GUARD_DECORATOR="tests.request_urlconf_admin_urls.guard_deco",
        MIDDLEWARE=list(order),
    )


def test_a_urlconf_set_after_the_guard_is_refused_before_the_view_runs() -> None:
    with _serve(_AFTER_THE_GUARD, fail_on_misconfiguration=True):
        assert _admin(Client()) == 500


def test_a_urlconf_set_after_the_guard_is_logged_once_when_the_flag_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _serve(_AFTER_THE_GUARD, fail_on_misconfiguration=False):
        client = Client()
        with caplog.at_level(logging.ERROR):
            statuses = [_admin(client), _admin(client)]

    assert statuses == [200, 200]
    assert sum("listed after DjangoAPIGuard" in m for m in caplog.messages) == 1


def test_a_urlconf_set_before_the_guard_is_enforced_and_not_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _serve(_BEFORE_THE_GUARD, fail_on_misconfiguration=True):
        client = Client()
        with caplog.at_level(logging.ERROR):
            refused = _admin(client)
            allowed = _admin(client, "1")

    assert (refused, allowed) == (400, 200)
    assert not [m for m in caplog.messages if "listed after" in m]


def test_a_request_the_guard_never_saw_is_left_to_the_view() -> None:
    from django.http import HttpResponse
    from django.test import RequestFactory

    from djangoapi_guard.middleware import DjangoAPIGuard

    with override_settings(GUARD_SECURITY_CONFIG=config()):
        middleware = DjangoAPIGuard(lambda request: HttpResponse("ok"))

    request = RequestFactory().get("/")

    assert middleware.process_view(request, lambda r: HttpResponse(), (), {}) is None
