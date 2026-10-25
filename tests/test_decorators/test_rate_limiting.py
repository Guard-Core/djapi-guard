import os

from guard_core.sync.protocols.request_protocol import SyncGuardRequest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from typing import Any, cast
from unittest.mock import Mock

import pytest

from djangoapi_guard import SecurityConfig, SecurityDecorator


@pytest.fixture
def security_config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        trusted_proxies=("127.0.0.1",),
        enable_penetration_detection=False,
        ipinfo_token="test-token",
    )


@pytest.fixture
def decorator(security_config: SecurityConfig[SyncGuardRequest]) -> SecurityDecorator:
    return SecurityDecorator(security_config)


@pytest.mark.parametrize(
    "requests_limit,window,description",
    [
        (10, 60, "rate_limit decorator"),
    ],
)
def test_rate_limiting_decorators_applied(
    decorator: SecurityDecorator,
    requests_limit: int,
    window: int,
    description: str,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "rate_limited"
    mock_func.__module__ = "test_module"

    rate_dec = decorator.rate_limit(requests=requests_limit, window=window)
    decorated = rate_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, f"{description} should have route config"
    assert route_config.rate_limit == requests_limit, (
        f"{description} should have correct rate limit"
    )
    assert route_config.rate_limit_window == window, (
        f"{description} should have correct rate limit window"
    )


def test_geo_rate_limit_decorator_applied(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "geo_limited"
    mock_func.__module__ = "test_module"

    limits: dict[str, tuple[int, int]] = {
        "US": (100, 3600),
        "CN": (10, 3600),
        "*": (50, 3600),
    }
    geo_dec = decorator.geo_rate_limit(limits)
    decorated = geo_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, "geo_rate_limit should have route config"
    assert route_config.geo_rate_limits == limits, (
        "geo_rate_limit should store limits in geo_rate_limits"
    )


def test_rate_limiting_decorators_unit(
    security_config: SecurityConfig[SyncGuardRequest],
) -> None:
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    rate_limit_decorator = decorator.rate_limit(requests=5, window=120)
    decorated_func = rate_limit_decorator(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated_func)._guard_route_id)
    assert route_config is not None
    assert route_config.rate_limit == 5
    assert route_config.rate_limit_window == 120

    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    limits: dict[str, tuple[int, int]] = {"US": (100, 3600), "EU": (50, 3600)}
    geo_rate_limit_decorator = decorator.geo_rate_limit(limits)
    decorated_func2 = geo_rate_limit_decorator(mock_func2)

    route_config2 = decorator.get_route_config(
        cast(Any, decorated_func2)._guard_route_id
    )
    assert route_config2 is not None
    assert route_config2.geo_rate_limits == limits


def test_rate_limit_endpoint_response_config(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "rate_view"
    mock_func.__module__ = "test_module"

    rate_dec = decorator.rate_limit(requests=10, window=60)
    decorated = rate_dec(mock_func)
    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    assert route_config.rate_limit == 10
    assert route_config.rate_limit_window == 60

    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "geo_view"
    mock_func2.__module__ = "test_module"

    geo_dec = decorator.geo_rate_limit(
        {"US": (100, 3600), "CN": (10, 3600), "*": (50, 3600)}
    )
    decorated2 = geo_dec(mock_func2)
    route_config2 = decorator.get_route_config(cast(Any, decorated2)._guard_route_id)
    assert route_config2 is not None
    assert route_config2.geo_rate_limits is not None
