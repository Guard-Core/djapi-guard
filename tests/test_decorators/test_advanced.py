import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import json
from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest

from djangoapi_guard import SecurityConfig, SecurityDecorator


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        trusted_proxies=["127.0.0.1"],
        enable_penetration_detection=False,
    )


@pytest.fixture
def decorator(security_config: SecurityConfig) -> SecurityDecorator:
    return SecurityDecorator(security_config)


def test_time_window_configuration(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    time_dec = decorator.time_window("09:00", "17:00", "UTC")
    decorated = time_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.time_restrictions == {
        "start": "09:00",
        "end": "17:00",
        "timezone": "UTC",
    }


def test_night_hours_configuration(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    time_dec = decorator.time_window("22:00", "06:00", "UTC")
    decorated = time_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.time_restrictions == {
        "start": "22:00",
        "end": "06:00",
        "timezone": "UTC",
    }


def test_suspicious_detection_enabled(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    sus_dec = decorator.suspicious_detection(enabled=True)
    decorated = sus_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.enable_suspicious_detection is True


def test_suspicious_detection_disabled(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    sus_dec = decorator.suspicious_detection(enabled=False)
    decorated = sus_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.enable_suspicious_detection is False


@pytest.mark.parametrize(
    "trap_fields,description",
    [
        (
            ["bot_trap", "hidden_field"],
            "Form honeypot should have trap fields configured",
        ),
        (
            ["spam_check", "robot_field"],
            "JSON honeypot should have trap fields configured",
        ),
    ],
)
def test_honeypot_detection_configuration(
    decorator: SecurityDecorator,
    trap_fields: list[str],
    description: str,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    honeypot_dec = decorator.honeypot_detection(trap_fields)
    decorated = honeypot_dec(mock_func)

    route_id = cast(Any, decorated)._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None
    assert len(route_config.custom_validators) == 1

    validator = route_config.custom_validators[0]
    assert callable(validator)


def test_honeypot_form_detection(security_config: SecurityConfig) -> None:
    dec = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = dec.honeypot_detection(["bot_trap"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = cast(Any, decorated_func)._guard_route_id
    route_config = dec.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": (
        "application/x-www-form-urlencoded" if key == "content-type" else default
    )
    mock_request.body.return_value = b"bot_trap=filled"
    mock_request.read_body_prefix = lambda _max_bytes: b"bot_trap=filled"

    result = validator(mock_request)
    assert result is not None
    assert result.status_code == 403


def test_honeypot_json_exception(security_config: SecurityConfig) -> None:
    dec = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = dec.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = cast(Any, decorated_func)._guard_route_id
    route_config = dec.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": (
        "application/json" if key == "content-type" else default
    )
    mock_request.body.return_value = b"invalid json {"

    result = validator(mock_request)
    assert result is None


def test_honeypot_json_detection(security_config: SecurityConfig) -> None:
    dec = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = dec.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = cast(Any, decorated_func)._guard_route_id
    route_config = dec.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": (
        "application/json" if key == "content-type" else default
    )
    body_bytes = json.dumps({"spam_check": "filled"}).encode()
    mock_request.body.return_value = body_bytes
    mock_request.read_body_prefix = lambda _max_bytes: body_bytes

    result = validator(mock_request)
    assert result is not None
    assert result.status_code == 403
