import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from typing import Any, cast
from unittest.mock import Mock

import pytest
from django.http import HttpResponse
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityConfig, SecurityDecorator
from djangoapi_guard.adapters import DjangoGuardResponse


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


@pytest.mark.parametrize(
    "decorator_method,decorator_kwargs,expected_attr,expected_value,description",
    [
        (
            "block_user_agents",
            {"patterns": ["bot", "crawler"]},
            "blocked_user_agents",
            ["bot", "crawler"],
            "block_user_agents decorator",
        ),
        (
            "content_type_filter",
            {"allowed_types": ["application/json", "text/plain"]},
            "allowed_content_types",
            ["application/json", "text/plain"],
            "content_type_filter decorator",
        ),
        (
            "max_request_size",
            {"size_bytes": 1024},
            "max_request_size",
            1024,
            "max_request_size decorator",
        ),
        (
            "require_referrer",
            {"allowed_domains": ["example.com", "app.example.com"]},
            "require_referrer",
            ["example.com", "app.example.com"],
            "require_referrer decorator",
        ),
    ],
)
def test_content_filtering_decorators_applied(
    decorator: SecurityDecorator,
    decorator_method: str,
    decorator_kwargs: dict[str, object],
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


def test_custom_validation_decorator_applied(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "custom_view"
    mock_func.__module__ = "test_module"

    def custom_validator(request: SyncGuardRequest) -> GuardResponse | None:
        if "forbidden" in request.url_path:
            return DjangoGuardResponse(
                HttpResponse("Custom validation failed", status=400)
            )
        return None

    custom_dec = decorator.custom_validation(custom_validator)
    decorated = custom_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, "custom_validation should have route config"
    assert len(route_config.custom_validators) == 1, (
        "custom_validation should have one validator"
    )


def test_content_filtering_decorators_unit(
    security_config: SecurityConfig[SyncGuardRequest],
) -> None:
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    user_agent_decorator = decorator.block_user_agents(["bot", "spider"])
    decorated_func = user_agent_decorator(mock_func)
    route_config = decorator.get_route_config(cast(Any, decorated_func)._guard_route_id)
    assert route_config is not None
    assert route_config.blocked_user_agents == ["bot", "spider"]

    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    content_type_decorator = decorator.content_type_filter(["application/json"])
    decorated_func2 = content_type_decorator(mock_func2)
    route_config2 = decorator.get_route_config(
        cast(Any, decorated_func2)._guard_route_id
    )
    assert route_config2 is not None
    assert route_config2.allowed_content_types == ["application/json"]

    mock_func3 = Mock()
    mock_func3.__name__ = mock_func3.__qualname__ = "test_func3"
    mock_func3.__module__ = "test_module"

    size_decorator = decorator.max_request_size(2048)
    decorated_func3 = size_decorator(mock_func3)
    route_config3 = decorator.get_route_config(
        cast(Any, decorated_func3)._guard_route_id
    )
    assert route_config3 is not None
    assert route_config3.max_request_size == 2048

    mock_func4 = Mock()
    mock_func4.__name__ = mock_func4.__qualname__ = "test_func4"
    mock_func4.__module__ = "test_module"

    referrer_decorator = decorator.require_referrer(["example.com"])
    decorated_func4 = referrer_decorator(mock_func4)
    route_config4 = decorator.get_route_config(
        cast(Any, decorated_func4)._guard_route_id
    )
    assert route_config4 is not None
    assert route_config4.require_referrer == ["example.com"]

    mock_func5 = Mock()
    mock_func5.__name__ = mock_func5.__qualname__ = "test_func5"
    mock_func5.__module__ = "test_module"

    def test_validator(request: SyncGuardRequest) -> GuardResponse | None:
        return None

    custom_decorator = decorator.custom_validation(test_validator)
    decorated_func5 = custom_decorator(mock_func5)
    route_config5 = decorator.get_route_config(
        cast(Any, decorated_func5)._guard_route_id
    )
    assert route_config5 is not None
    assert len(route_config5.custom_validators) == 1
    assert route_config5.custom_validators[0] == test_validator

    result = test_validator(cast(SyncGuardRequest, Mock()))
    assert result is None


def test_referrer_passive_mode_config() -> None:
    security_config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
        trusted_proxies=("127.0.0.1",),
    )
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "referrer_test"
    mock_func.__module__ = "test_module"

    ref_dec = decorator.require_referrer(["example.com"])
    decorated = ref_dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    assert route_config.require_referrer == ["example.com"]
    assert security_config.passive_mode is True


def test_custom_validator_returns_response(
    security_config: SecurityConfig[SyncGuardRequest],
) -> None:
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "validated_view"
    mock_func.__module__ = "test_module"

    def blocking_validator(request: SyncGuardRequest) -> GuardResponse | None:
        return DjangoGuardResponse(HttpResponse("Blocked", status=400))

    custom_dec = decorator.custom_validation(blocking_validator)
    decorated = custom_dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    result = validator(cast(SyncGuardRequest, Mock()))
    assert result is not None
    assert result.status_code == 400
