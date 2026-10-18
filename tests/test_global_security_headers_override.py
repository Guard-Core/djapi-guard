import os
from collections.abc import Generator
from typing import Any

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.security_headers_handler import security_headers_manager

from djangoapi_guard.middleware import DjangoAPIGuard

APP_CSP = {"default-src": ["'self'", "https://app.example"]}
GLOBAL_CSP = {"default-src": ["'self'", "https://global.example"]}
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


@pytest.fixture(autouse=True)
def _clean_global_manager() -> Generator[None, None, None]:
    security_headers_manager.reset()
    yield
    security_headers_manager.reset()


def _middleware(**overrides: Any) -> DjangoAPIGuard:
    values: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": False,
        "security_headers": {
            "enabled": True,
            "csp": APP_CSP,
            "frame_options": "DENY",
        },
    }
    values.update(overrides)
    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig(**values)

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("ok")

    return DjangoAPIGuard(get_response)


def test_the_global_configure_reaches_a_guarded_app() -> None:
    middleware = _middleware()
    factory = RequestFactory()
    assert middleware(factory.get("/x"))["Content-Security-Policy"].endswith(
        "app.example"
    )

    security_headers_manager.configure(csp=GLOBAL_CSP, override_apps=True)

    for path in ("/x", "/y"):
        response = middleware(factory.get(path))
        assert response["Content-Security-Policy"] == (
            "default-src 'self' https://global.example"
        )
        assert response["X-Frame-Options"] == "DENY"


def test_without_a_global_call_the_app_keeps_its_own_config() -> None:
    response = _middleware()(RequestFactory().get("/x"))

    assert response["Content-Security-Policy"].endswith("app.example")


def test_the_response_manager_reaches_the_redis_of_its_app() -> None:
    middleware = _middleware(enable_redis=True, redis_url=REDIS_URL)

    assert middleware.redis_handler is not None
    assert middleware.response_factory is not None
    assert middleware.response_factory.security_headers_manager.redis_handler is (
        middleware.redis_handler
    )


def test_building_a_second_app_does_not_override_the_first() -> None:
    factory = RequestFactory()
    first = _middleware()
    second = _middleware(security_headers={"enabled": True, "csp": GLOBAL_CSP})
    first(factory.get("/x"))
    second(factory.get("/x"))

    assert first(factory.get("/x"))["Content-Security-Policy"].endswith("app.example")
    assert second(factory.get("/x"))["Content-Security-Policy"].endswith(
        "global.example"
    )


def test_a_call_without_override_apps_does_not_reach_a_guarded_app() -> None:
    middleware = _middleware()
    factory = RequestFactory()
    middleware(factory.get("/x"))

    security_headers_manager.configure(csp=GLOBAL_CSP)

    assert middleware(factory.get("/x"))["Content-Security-Policy"].endswith(
        "app.example"
    )
