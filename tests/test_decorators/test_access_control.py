import os

from guard_core.sync.protocols.request_protocol import SyncGuardRequest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from typing import Any, cast
from unittest.mock import Mock

import pytest
from django.test import RequestFactory

from djangoapi_guard import SecurityConfig, SecurityDecorator


@pytest.fixture
def security_config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        trusted_proxies=("127.0.0.1",),
        enable_penetration_detection=False,
    )


@pytest.fixture
def decorator(security_config: SecurityConfig[SyncGuardRequest]) -> SecurityDecorator:
    return SecurityDecorator(security_config)


@pytest.fixture
def rf() -> RequestFactory:
    return RequestFactory()


@pytest.mark.parametrize(
    "whitelist,blacklist,ip,expected_blocked,description",
    [
        (
            ["127.0.0.1", "192.168.1.0/24"],
            None,
            "127.0.0.1",
            False,
            "Whitelisted IP should pass",
        ),
        (
            ["127.0.0.1", "192.168.1.0/24"],
            None,
            "192.168.1.50",
            False,
            "IP in whitelisted CIDR should pass",
        ),
        (
            ["127.0.0.1", "192.168.1.0/24"],
            None,
            "10.0.0.1",
            True,
            "Non-whitelisted IP should be blocked",
        ),
        (
            None,
            ["10.0.0.1", "172.16.0.0/16"],
            "127.0.0.1",
            False,
            "Non-blacklisted IP should pass",
        ),
        (
            None,
            ["10.0.0.1", "172.16.0.0/16"],
            "10.0.0.1",
            True,
            "Blacklisted IP should be blocked",
        ),
        (
            None,
            ["10.0.0.1", "172.16.0.0/16"],
            "172.16.5.10",
            True,
            "IP in blacklisted CIDR should be blocked",
        ),
    ],
)
def test_ip_access_control(
    decorator: SecurityDecorator,
    whitelist: list[str] | None,
    blacklist: list[str] | None,
    ip: str,
    expected_blocked: bool,
    description: str,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    ip_decorator = decorator.require_ip(whitelist=whitelist, blacklist=blacklist)
    decorated = ip_decorator(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None

    if whitelist:
        assert route_config.ip_whitelist == whitelist
    if blacklist:
        assert route_config.ip_blacklist == blacklist


def test_country_blocking_configuration(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    block_dec = decorator.block_countries(["CN", "RU"])
    decorated = block_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.blocked_countries == ["CN", "RU"]


def test_country_allow_configuration(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    allow_dec = decorator.allow_countries(["US", "GB", "DE"])
    decorated = allow_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.whitelist_countries == ["US", "GB", "DE"]


def test_cloud_provider_blocking(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    cloud_dec = decorator.block_clouds(["AWS", "GCP"])
    decorated = cloud_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.block_cloud_providers == {"AWS", "GCP"}


def test_block_all_clouds_default(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    cloud_dec = decorator.block_clouds()
    decorated = cloud_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.block_cloud_providers == {
        "AWS",
        "GCP",
        "Azure",
        "DigitalOcean",
        "Vultr",
        "Linode",
    }


def test_security_bypass(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    bypass_dec = decorator.bypass(["ip", "rate_limit"])
    decorated = bypass_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert "ip" in route_config.bypassed_checks
    assert "rate_limit" in route_config.bypassed_checks
