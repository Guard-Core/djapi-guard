import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from collections.abc import Callable, Iterator
from typing import Any, cast
from unittest.mock import Mock

import pytest
from django.core.handlers.base import BaseHandler
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, override_settings

from djangoapi_guard import SecurityConfig, SecurityDecorator
from djangoapi_guard.middleware import DjangoAPIGuard
from tests import api_key_urls


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        trusted_proxies=("127.0.0.1",),
        trust_x_forwarded_proto=True,
        enforce_https=False,
        enable_penetration_detection=False,
    )


@pytest.fixture
def decorator(security_config: SecurityConfig) -> SecurityDecorator:
    return SecurityDecorator(security_config)


@pytest.mark.parametrize(
    "decorator_method,decorator_kwargs,expected_attr,expected_value,description",
    [
        ("require_https", {}, "require_https", True, "require_https decorator"),
        (
            "require_auth",
            {},
            "auth_required",
            "bearer",
            "require_auth default decorator",
        ),
        (
            "require_auth",
            {"type": "basic"},
            "auth_required",
            "basic",
            "require_auth custom type decorator",
        ),
        (
            "api_key_auth",
            {},
            "api_key_required",
            True,
            "api_key_auth default decorator",
        ),
        (
            "api_key_auth",
            {"header_name": "Authorization"},
            "api_key_required",
            True,
            "api_key_auth custom header decorator",
        ),
    ],
)
def test_authentication_decorators_applied(
    decorator: SecurityDecorator,
    decorator_method: str,
    decorator_kwargs: dict[str, str],
    expected_attr: str,
    expected_value: object,
    description: str,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = f"test_{decorator_method}"
    mock_func.__module__ = "test_module"

    dec = getattr(decorator, decorator_method)(**decorator_kwargs)
    decorated = dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, f"{description} should have route config"
    assert getattr(route_config, expected_attr) == expected_value, (
        f"{description} should have correct {expected_attr}"
    )


@pytest.mark.parametrize(
    "decorator_method,decorator_kwargs,expected_headers,description",
    [
        (
            "require_headers",
            {"headers": {"X-API-Version": "v1"}},
            {"X-API-Version": "v1"},
            "require_headers single header",
        ),
        (
            "require_headers",
            {"headers": {"X-API-Version": "v2", "X-Client-ID": "required"}},
            {"X-API-Version": "v2", "X-Client-ID": "required"},
            "require_headers multiple headers",
        ),
    ],
)
def test_header_requirements_applied(
    decorator: SecurityDecorator,
    decorator_method: str,
    decorator_kwargs: dict[str, object],
    expected_headers: dict[str, str],
    description: str,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = f"test_{decorator_method}"
    mock_func.__module__ = "test_module"

    dec = getattr(decorator, decorator_method)(**decorator_kwargs)
    decorated = dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, f"{description} should have route config"
    for header, value in expected_headers.items():
        assert route_config.required_headers[header] == value, (
            f"{description} should require {header}={value}"
        )


def test_authentication_decorators_unit(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    https_decorator = decorator.require_https()
    decorated_func = https_decorator(mock_func)
    route_config = decorator.get_route_config(cast(Any, decorated_func)._guard_route_id)
    assert route_config is not None
    assert route_config.require_https is True

    auth_decorator = decorator.require_auth()
    decorated_func2 = auth_decorator(mock_func)
    route_config2 = decorator.get_route_config(
        cast(Any, decorated_func2)._guard_route_id
    )
    assert route_config2 is not None
    assert route_config2.auth_required == "bearer"

    auth_custom = decorator.require_auth(type="digest")
    decorated_func3 = auth_custom(mock_func)
    route_config3 = decorator.get_route_config(
        cast(Any, decorated_func3)._guard_route_id
    )
    assert route_config3 is not None
    assert route_config3.auth_required == "digest"

    api_key = decorator.api_key_auth()
    decorated_func4 = api_key(mock_func)
    route_config4 = decorator.get_route_config(
        cast(Any, decorated_func4)._guard_route_id
    )
    assert route_config4 is not None
    assert route_config4.api_key_required is True
    assert route_config4.api_key_header == "X-API-Key"

    api_key_custom = decorator.api_key_auth(header_name="X-Custom-Key")
    decorated_func5 = api_key_custom(mock_func)
    route_config5 = decorator.get_route_config(
        cast(Any, decorated_func5)._guard_route_id
    )
    assert route_config5 is not None
    assert route_config5.api_key_required is True
    assert route_config5.api_key_header == "X-Custom-Key"

    headers = decorator.require_headers({"X-Test": "value", "X-Other": "required"})
    decorated_func6 = headers(mock_func)
    route_config6 = decorator.get_route_config(
        cast(Any, decorated_func6)._guard_route_id
    )
    assert route_config6 is not None
    assert route_config6.required_headers["X-Test"] == "value"
    assert route_config6.required_headers["X-Other"] == "required"


def test_authentication_failures_unit(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "auth_test"
    mock_func.__module__ = "test_module"

    auth_dec = decorator.require_auth()
    decorated = auth_dec(mock_func)
    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    assert route_config.auth_required == "bearer"

    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "auth_basic_test"
    mock_func2.__module__ = "test_module"

    auth_dec2 = decorator.require_auth(type="basic")
    decorated2 = auth_dec2(mock_func2)
    route_config2 = decorator.get_route_config(cast(Any, decorated2)._guard_route_id)
    assert route_config2 is not None
    assert route_config2.auth_required == "basic"


def test_multiple_auth_decorators(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "multi_auth"
    mock_func.__module__ = "test_module"

    https_dec = decorator.require_https()
    auth_dec = decorator.require_auth(type="bearer")
    headers_dec = decorator.require_headers({"X-API-Version": "v1"})

    decorated = https_dec(mock_func)
    decorated = auth_dec(decorated)
    decorated = headers_dec(decorated)

    assert hasattr(decorated, "_guard_route_id")


def test_auth_passive_mode_config() -> None:
    security_config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
        trusted_proxies=("127.0.0.1",),
    )
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "passive_auth"
    mock_func.__module__ = "test_module"

    auth_dec = decorator.require_auth("bearer")
    decorated = auth_dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    assert route_config.auth_required == "bearer"
    assert security_config.passive_mode is True


def test_require_auth_with_various_types(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)

    for auth_type in ["bearer", "basic", "digest", "token"]:
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = f"auth_{auth_type}"
        mock_func.__module__ = "test_module"

        auth_dec = decorator.require_auth(type=auth_type)
        decorated = auth_dec(mock_func)

        route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
        assert route_config is not None
        assert route_config.auth_required == auth_type


@pytest.fixture
def api_key_guard() -> Iterator[DjangoAPIGuard]:
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        whitelist=None,
        blacklist=(),
        trusted_proxies=("127.0.0.1",),
        auth_verifier=lambda request, credential: (
            {"user": "ok"} if credential else None
        ),
    )
    with override_settings(ROOT_URLCONF="tests.api_key_urls", MIDDLEWARE=[]):
        handler = BaseHandler()
        handler.load_middleware()
        with override_settings(GUARD_SECURITY_CONFIG=config):
            guard = DjangoAPIGuard(
                cast(Callable[[HttpRequest], HttpResponse], handler.get_response)
            )
        guard.set_decorator_handler(api_key_urls.security)
        yield guard


@pytest.mark.parametrize(
    "path,header,handler_message",
    [
        (
            "/api-key-default/",
            "X-API-Key",
            "API key required (default header)",
        ),
        (
            "/api-key-custom/",
            "Authorization",
            "API key required (custom header)",
        ),
    ],
)
def test_api_key_route_refuses_a_missing_key_and_answers_a_present_one(
    api_key_guard: DjangoAPIGuard,
    path: str,
    header: str,
    handler_message: str,
) -> None:
    missing_request = RequestFactory().get(path)
    missing_request.META["REMOTE_ADDR"] = "203.0.113.5"
    missing = api_key_guard(missing_request)
    assert missing.status_code in (400, 401)
    assert handler_message not in missing.content.decode()

    present_request = RequestFactory().get(path, headers={header: "test-key"})
    present_request.META["REMOTE_ADDR"] = "203.0.113.5"
    present = api_key_guard(present_request)
    assert present.status_code == 200
    assert handler_message in present.content.decode()
