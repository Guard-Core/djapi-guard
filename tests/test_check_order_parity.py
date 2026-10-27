import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from collections.abc import Callable, Iterator
from typing import cast

import pytest
from django.core.handlers.base import BaseHandler
from django.http import HttpRequest
from django.http.response import HttpResponseBase
from django.test import RequestFactory, override_settings
from guard_core.sync.core.checks import DEFAULT_CHECK_CLASSES
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler

from djangoapi_guard.middleware import DjangoAPIGuard
from tests import check_order_urls

OTHER_IP = "10.0.0.7"


@pytest.fixture
def guard() -> Iterator[DjangoAPIGuard]:
    with override_settings(ROOT_URLCONF="tests.check_order_urls", MIDDLEWARE=[]):
        handler = BaseHandler()
        handler.load_middleware()
        with override_settings(GUARD_SECURITY_CONFIG=check_order_urls.config):
            instance = DjangoAPIGuard(
                cast(Callable[[HttpRequest], HttpResponseBase], handler.get_response)
            )
        instance.set_decorator_handler(check_order_urls.security)
        rate_limit_handler(check_order_urls.config).reset()
        yield instance
        rate_limit_handler(check_order_urls.config).reset()


def _get(path: str, client_ip: str) -> HttpRequest:
    return RequestFactory().get(path, HTTP_X_FORWARDED_FOR=client_ip)


def test_a_banned_ip_without_a_required_header_gets_the_ban_answer(
    guard: DjangoAPIGuard,
) -> None:
    banned = guard(_get("/needs-header/", check_order_urls.BANNED_IP))
    missing_header = guard(_get("/needs-header/", OTHER_IP))

    assert banned.status_code == 403
    assert missing_header.status_code == 400


def test_a_request_over_the_rate_limit_that_fails_authentication_gets_429(
    guard: DjangoAPIGuard,
) -> None:
    first = guard(_get("/limited-and-authed/", OTHER_IP))
    second = guard(_get("/limited-and-authed/", OTHER_IP))

    assert first.status_code == 401
    assert second.status_code == 429


def test_the_pipeline_keeps_the_engine_default_order_with_the_cors_preflight_check(
    guard: DjangoAPIGuard,
) -> None:
    engine_order = [cls(guard).check_name for cls in DEFAULT_CHECK_CLASSES]

    assert guard.security_pipeline is not None
    names = guard.security_pipeline.get_check_names()
    assert "cors_preflight" in names
    assert names == [name for name in engine_order if name in names]
