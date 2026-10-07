import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from collections.abc import Awaitable, Callable
from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.http import HttpRequest, HttpResponse
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule

from djangoapi_guard import SecurityConfig, SecurityDecorator
from djangoapi_guard.adapters import DjangoGuardRequest
from djangoapi_guard.middleware import DjangoAPIGuard


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )


def _make_middleware(config: SecurityConfig) -> DjangoAPIGuard:
    from django.conf import settings

    settings.GUARD_SECURITY_CONFIG = config
    try:
        middleware = DjangoAPIGuard(lambda request: HttpResponse("OK"))
    finally:
        if hasattr(settings, "GUARD_SECURITY_CONFIG"):
            delattr(settings, "GUARD_SECURITY_CONFIG")
    return middleware


def test_set_decorator_handler(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    decorator = SecurityDecorator(security_config)
    middleware.set_decorator_handler(decorator)
    assert middleware.guard_decorator is decorator

    middleware.set_decorator_handler(None)
    assert middleware.guard_decorator is None


def test_get_endpoint_id_with_route(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    mock_request = Mock()
    mock_request.path = "/test"
    mock_request.path_info = "/test"
    mock_request.method = "GET"
    mock_request.guard_route_id = "orders:list"
    mock_request.guard_endpoint_id = "test_module.test_function"

    # The stamped route id wins over the runtime endpoint-id extra
    # (guard-core #142's get_endpoint_id resolution order).
    endpoint_id = middleware._get_endpoint_id(mock_request)
    assert endpoint_id == "orders:list"

    # No stamped route id: the runtime endpoint-id extra is honored.
    mock_request.guard_route_id = None
    endpoint_id = middleware._get_endpoint_id(mock_request)
    assert endpoint_id == "test_module.test_function"

    # Neither is present: the redacted method:path fallback.
    mock_request.guard_endpoint_id = None
    endpoint_id = middleware._get_endpoint_id(mock_request)
    assert endpoint_id == "GET:/test"


def test_should_bypass_check(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    assert middleware.route_resolver is not None
    assert not middleware.route_resolver.should_bypass_check("ip", None)

    mock_route_config = Mock()
    mock_route_config.bypassed_checks = {"ip"}
    assert middleware.route_resolver.should_bypass_check("ip", mock_route_config)
    assert not middleware.route_resolver.should_bypass_check(
        "rate_limit", mock_route_config
    )

    mock_route_config.bypassed_checks = {"all"}
    assert middleware.route_resolver.should_bypass_check("ip", mock_route_config)
    assert middleware.route_resolver.should_bypass_check(
        "rate_limit", mock_route_config
    )


def test_check_route_ip_access_invalid_ip(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = middleware._check_route_ip_access("invalid_ip", mock_route_config)
    assert result is False


def test_check_route_ip_access_blacklist(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = middleware._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is False

    result = middleware._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is False

    result = middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is None


def test_check_route_ip_access_whitelist(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = middleware._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is True

    result = middleware._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is True

    result = middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


def test_check_route_ip_access_countries(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    mock_geo_handler = Mock()
    middleware.geo_ip_handler = mock_geo_handler

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None

    mock_route_config.blocked_countries = ["XX"]
    mock_route_config.whitelist_countries = None
    mock_geo_handler.get_country.return_value = "XX"

    result = middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = ["US"]
    mock_geo_handler.get_country.return_value = "US"

    result = middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is True

    mock_geo_handler.get_country.return_value = "XX"
    result = middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    mock_geo_handler.get_country.return_value = None
    result = middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


def test_check_user_agent_allowed(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    mock_route_config = Mock()
    mock_route_config.blocked_user_agents = [r"badbot"]

    with patch("guard_core.sync.utils.is_user_agent_allowed", return_value=True):
        result = middleware._check_user_agent_allowed("badbot", mock_route_config)
        assert result is False

        result = middleware._check_user_agent_allowed("goodbot", mock_route_config)
        assert result is True

    with patch(
        "guard_core.sync.utils.is_user_agent_allowed", return_value=False
    ) as mock_global:
        result = middleware._check_user_agent_allowed("somebot", None)
        assert result is False
        mock_global.assert_called_once()


def test_time_window_error_handling(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    invalid_time_restrictions: dict[str, str] = {"invalid": "data"}

    assert middleware.validator is not None
    with patch.object(middleware.validator.context.logger, "error") as mock_error:
        result = middleware._check_time_window(invalid_time_restrictions)
        assert result is True
        mock_error.assert_called_once()


def test_time_window_overnight(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    time_restrictions = {"start": "22:00", "end": "06:00"}

    with patch("guard_core.sync.core.validation.validator.datetime") as mock_datetime:
        mock_now = Mock()
        mock_now.strftime.return_value = "23:00"
        mock_datetime.now.return_value = mock_now
        result = middleware._check_time_window(time_restrictions)
        assert result is True

    with patch("guard_core.sync.core.validation.validator.datetime") as mock_datetime:
        mock_now = Mock()
        mock_now.strftime.return_value = "05:00"
        mock_datetime.now.return_value = mock_now
        result = middleware._check_time_window(time_restrictions)
        assert result is True

    with patch("guard_core.sync.core.validation.validator.datetime") as mock_datetime:
        mock_now = Mock()
        mock_now.strftime.return_value = "12:00"
        mock_datetime.now.return_value = mock_now
        result = middleware._check_time_window(time_restrictions)
        assert result is False


def test_time_window_normal(security_config: SecurityConfig) -> None:
    middleware = _make_middleware(security_config)

    time_restrictions = {"start": "09:00", "end": "17:00"}

    with patch("guard_core.sync.core.validation.validator.datetime") as mock_datetime:
        mock_now = Mock()
        mock_now.strftime.return_value = "12:00"
        mock_datetime.now.return_value = mock_now
        result = middleware._check_time_window(time_restrictions)
        assert result is True

    with patch("guard_core.sync.core.validation.validator.datetime") as mock_datetime:
        mock_now = Mock()
        mock_now.strftime.return_value = "20:00"
        mock_datetime.now.return_value = mock_now
        result = middleware._check_time_window(time_restrictions)
        assert result is False


def test_behavioral_rules_without_guard_decorator(
    security_config: SecurityConfig,
) -> None:
    middleware = _make_middleware(security_config)

    middleware.set_decorator_handler(None)

    mock_request = Mock()
    mock_route_config = Mock()
    mock_route_config.behavior_rules = [BehaviorRule("usage", threshold=5, window=3600)]

    middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )
    middleware._process_decorator_return_rules(
        mock_request, Mock(), "127.0.0.1", mock_route_config
    )


def test_behavioral_usage_rules_with_decorator(
    security_config: SecurityConfig,
) -> None:
    middleware = _make_middleware(security_config)

    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    middleware.set_decorator_handler(mock_guard_decorator)

    mock_request = Mock()
    mock_request.path = "/test"
    mock_request.path_info = "/test"
    mock_request.method = "GET"

    mock_route_config = Mock()
    usage_rule = BehaviorRule("usage", threshold=5, window=3600)
    mock_route_config.behavior_rules = [usage_rule]

    def mock_track_usage(*args: Any, **kwargs: Any) -> bool:
        return False

    mock_behavior_tracker.track_endpoint_usage = mock_track_usage

    middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )
    mock_behavior_tracker.apply_action.assert_not_called()

    def mock_track_usage_exceeded(*args: Any, **kwargs: Any) -> bool:
        return True

    def mock_apply_action(*args: Any, **kwargs: Any) -> None:
        return None

    mock_behavior_tracker.track_endpoint_usage = mock_track_usage_exceeded
    mock_behavior_tracker.apply_action = mock_apply_action

    middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )


def test_behavioral_return_rules_with_decorator(
    security_config: SecurityConfig,
) -> None:
    middleware = _make_middleware(security_config)

    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    middleware.set_decorator_handler(mock_guard_decorator)

    mock_request = Mock()
    mock_request.path = "/test"
    mock_request.path_info = "/test"
    mock_request.method = "GET"

    mock_response = Mock()
    mock_route_config = Mock()
    return_rule = BehaviorRule(
        "return_pattern", threshold=3, window=3600, pattern="win"
    )
    mock_route_config.behavior_rules = [return_rule]

    def mock_track_pattern(*args: Any, **kwargs: Any) -> bool:
        return False

    mock_behavior_tracker.track_return_pattern = mock_track_pattern

    middleware._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )
    mock_behavior_tracker.apply_action.assert_not_called()

    def mock_track_pattern_detected(*args: Any, **kwargs: Any) -> bool:
        return True

    def mock_apply_action(*args: Any, **kwargs: Any) -> None:
        return None

    mock_behavior_tracker.track_return_pattern = mock_track_pattern_detected
    mock_behavior_tracker.apply_action = mock_apply_action

    middleware._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )


def test_get_route_decorator_config_no_guard_decorator(
    security_config: SecurityConfig,
) -> None:
    middleware = _make_middleware(security_config)

    middleware.set_decorator_handler(None)

    django_request = HttpRequest()
    django_request.path = "/test"
    django_request.path_info = "/test"
    django_request.method = "GET"
    django_request.META["SERVER_NAME"] = "localhost"
    django_request.META["SERVER_PORT"] = "80"

    assert middleware.route_resolver is not None
    guard_req = DjangoGuardRequest(django_request)
    result = middleware.route_resolver.get_route_config(guard_req)
    assert result is None


def test_get_route_decorator_config_no_guard_route_id(
    security_config: SecurityConfig,
) -> None:
    middleware = _make_middleware(security_config)

    decorator = SecurityDecorator(security_config)
    middleware.set_decorator_handler(decorator)

    django_request = HttpRequest()
    django_request.path = "/nonexistent"
    django_request.path_info = "/nonexistent"
    django_request.method = "GET"
    django_request.META["SERVER_NAME"] = "localhost"
    django_request.META["SERVER_PORT"] = "80"

    assert middleware.route_resolver is not None
    result = middleware.route_resolver.get_route_config(
        DjangoGuardRequest(django_request)
    )
    assert result is None


def test_get_route_decorator_config_no_matching_route(
    security_config: SecurityConfig,
) -> None:
    middleware = _make_middleware(security_config)

    decorator = SecurityDecorator(security_config)
    middleware.set_decorator_handler(decorator)

    django_request = HttpRequest()
    django_request.path = "/nonexistent"
    django_request.path_info = "/nonexistent"
    django_request.method = "GET"
    django_request.META["SERVER_NAME"] = "localhost"
    django_request.META["SERVER_PORT"] = "80"
    cast(Any, django_request).guard_route_id = "nonexistent_route_id"

    assert middleware.route_resolver is not None
    result = middleware.route_resolver.get_route_config(
        DjangoGuardRequest(django_request)
    )
    assert result is None


def test_bypass_all_security_checks(security_config: SecurityConfig) -> None:
    mock_route_config = RouteConfig()
    mock_route_config.bypassed_checks = {"all"}

    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "bypass_all"
    mock_func.__module__ = "test_module"

    bypass_dec = decorator.bypass(["all"])
    decorated = bypass_dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    assert "all" in route_config.bypassed_checks


def test_bypass_all_security_checks_with_custom_modifier() -> None:
    def custom_modifier(response: GuardResponse) -> GuardResponse:
        return response

    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        custom_response_modifier=cast(
            Callable[[GuardResponse], Awaitable[GuardResponse]], custom_modifier
        ),
    )

    decorator = SecurityDecorator(config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "bypass_modified"
    mock_func.__module__ = "test_module"

    bypass_dec = decorator.bypass(["all"])
    decorated = bypass_dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    assert "all" in route_config.bypassed_checks
    assert config.custom_response_modifier is not None


@pytest.mark.parametrize(
    "test_case,description",
    [
        (
            {"max_request_size": 100},
            "Test route-specific request size limits",
        ),
        (
            {"allowed_content_types": ["application/json"]},
            "Test route-specific content type filtering",
        ),
        (
            {
                "custom_validators": [
                    MagicMock(return_value=HttpResponse("Failed", status=400))
                ]
            },
            "Test custom validator returning a Response object",
        ),
        (
            {"custom_validators": [MagicMock(return_value=None)]},
            "Test custom validator returning None (allows request)",
        ),
    ],
)
def test_route_specific_extension_validations(
    security_config: SecurityConfig,
    test_case: dict[str, Any],
    description: str,
) -> None:
    decorator = SecurityDecorator(security_config)

    route_config = RouteConfig()
    for attr, value in test_case.items():
        setattr(route_config, attr, value)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_view"
    mock_func.__module__ = "test_module"

    route_id = f"{mock_func.__module__}.{mock_func.__qualname__}"
    decorator._route_configs[route_id] = route_config

    retrieved = decorator.get_route_config(route_id)
    assert retrieved is not None
    for attr, value in test_case.items():
        assert getattr(retrieved, attr) == value, (
            f"{description}: {attr} should be {value}"
        )


def test_route_specific_rate_limit_config(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)

    route_config = RouteConfig()
    route_config.rate_limit = 5
    route_config.rate_limit_window = 60

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "rate_limited_view"
    mock_func.__module__ = "test_module"

    rate_dec = decorator.rate_limit(requests=5, window=60)
    decorated = rate_dec(mock_func)

    retrieved = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert retrieved is not None
    assert retrieved.rate_limit == 5
    assert retrieved.rate_limit_window == 60
