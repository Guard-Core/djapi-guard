import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from typing import Any, cast
from unittest.mock import Mock

import pytest
from guard_core.sync.handlers.behavior_handler import BehaviorRule
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityConfig, SecurityDecorator


@pytest.fixture
def security_config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        trusted_proxies=("127.0.0.1",),
        enable_penetration_detection=False,
        behavior_scan_response_body=True,
    )


@pytest.fixture
def decorator(security_config: SecurityConfig[SyncGuardRequest]) -> SecurityDecorator:
    return SecurityDecorator(security_config)


@pytest.mark.parametrize(
    "decorator_method,decorator_kwargs,expected_rules_count,expected_action,description",
    [
        (
            "usage_monitor",
            {"max_calls": 5, "window": 3600, "action": "ban"},
            1,
            "ban",
            "usage_monitor with ban action",
        ),
        (
            "usage_monitor",
            {"max_calls": 10, "window": 300, "action": "log"},
            1,
            "log",
            "usage_monitor with log action",
        ),
        (
            "return_monitor",
            {"pattern": "win", "max_occurrences": 3, "window": 86400, "action": "ban"},
            1,
            "ban",
            "return_monitor with ban action",
        ),
        (
            "return_monitor",
            {
                "pattern": "json:result.status==success",
                "max_occurrences": 5,
                "window": 3600,
                "action": "throttle",
            },
            1,
            "throttle",
            "return_monitor with throttle action",
        ),
        (
            "suspicious_frequency",
            {"max_frequency": 0.1, "window": 300, "action": "ban"},
            1,
            "ban",
            "suspicious_frequency with ban action",
        ),
        (
            "suspicious_frequency",
            {"max_frequency": 2.0, "window": 60, "action": "alert"},
            1,
            "alert",
            "suspicious_frequency with alert action",
        ),
    ],
)
def test_behavioral_decorators_applied(
    decorator: SecurityDecorator,
    decorator_method: str,
    decorator_kwargs: dict[str, object],
    expected_rules_count: int,
    expected_action: str,
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
    assert len(route_config.behavior_rules) == expected_rules_count, (
        f"{description} should have {expected_rules_count} behavior rules"
    )
    assert route_config.behavior_rules[0].action == expected_action, (
        f"{description} should have {expected_action} action"
    )


def test_behavior_analysis_multiple_rules(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "multi_behavior"
    mock_func.__module__ = "test_module"

    rules = [
        BehaviorRule("usage", threshold=10, window=3600),
        BehaviorRule("return_pattern", threshold=3, pattern="rare", window=86400),
    ]

    behavior_dec = decorator.behavior_analysis(rules)
    decorated = behavior_dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    assert len(route_config.behavior_rules) == 2

    usage_rule = route_config.behavior_rules[0]
    assert usage_rule.rule_type == "usage"
    assert usage_rule.threshold == 10
    assert usage_rule.window == 3600

    pattern_rule = route_config.behavior_rules[1]
    assert pattern_rule.rule_type == "return_pattern"
    assert pattern_rule.threshold == 3
    assert pattern_rule.pattern == "rare"
    assert pattern_rule.window == 86400


@pytest.mark.parametrize(
    "decorator_method,decorator_kwargs,expected_rule_type,expected_threshold,expected_window,description",
    [
        (
            "usage_monitor",
            {"max_calls": 5, "window": 3600, "action": "ban"},
            "usage",
            5,
            3600,
            "usage_monitor ban configuration",
        ),
        (
            "usage_monitor",
            {"max_calls": 10, "window": 300, "action": "log"},
            "usage",
            10,
            300,
            "usage_monitor log configuration",
        ),
        (
            "return_monitor",
            {"pattern": "win", "max_occurrences": 3, "window": 86400, "action": "ban"},
            "return_pattern",
            3,
            86400,
            "return_monitor win configuration",
        ),
        (
            "return_monitor",
            {
                "pattern": "json:result.status==success",
                "max_occurrences": 5,
                "window": 3600,
                "action": "throttle",
            },
            "return_pattern",
            5,
            3600,
            "return_monitor json configuration",
        ),
        (
            "suspicious_frequency",
            {"max_frequency": 0.1, "window": 300, "action": "ban"},
            "frequency",
            30,
            300,
            "suspicious_frequency ban configuration",
        ),
        (
            "suspicious_frequency",
            {"max_frequency": 2.0, "window": 60, "action": "alert"},
            "frequency",
            120,
            60,
            "suspicious_frequency alert configuration",
        ),
    ],
)
def test_behavioral_rule_configuration(
    decorator: SecurityDecorator,
    decorator_method: str,
    decorator_kwargs: dict[str, object],
    expected_rule_type: str,
    expected_threshold: int,
    expected_window: int,
    description: str,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = f"rule_{decorator_method}"
    mock_func.__module__ = "test_module"

    dec = getattr(decorator, decorator_method)(**decorator_kwargs)
    decorated = dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None, f"{description} should have route config"
    rule = route_config.behavior_rules[0]

    assert rule.rule_type == expected_rule_type
    assert rule.threshold == expected_threshold
    assert rule.window == expected_window


@pytest.mark.parametrize(
    "pattern,expected_pattern,description",
    [
        ("win", "win", "return_monitor win pattern"),
        (
            "json:result.status==success",
            "json:result.status==success",
            "return_monitor json pattern",
        ),
    ],
)
def test_return_monitor_patterns(
    decorator: SecurityDecorator,
    pattern: str,
    expected_pattern: str,
    description: str,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = f"pattern_{pattern}"
    mock_func.__module__ = "test_module"

    ret_dec = decorator.return_monitor(
        pattern=pattern, max_occurrences=3, window=86400, action="ban"
    )
    decorated = ret_dec(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated)._guard_route_id)
    assert route_config is not None
    rule = route_config.behavior_rules[0]
    assert rule.pattern == expected_pattern


def test_behavioral_decorators_unit(
    security_config: SecurityConfig[SyncGuardRequest],
) -> None:
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    usage_decorator = decorator.usage_monitor(max_calls=5, window=3600, action="ban")
    decorated_func = usage_decorator(mock_func)

    route_config = decorator.get_route_config(cast(Any, decorated_func)._guard_route_id)
    assert route_config is not None
    assert len(route_config.behavior_rules) == 1
    assert route_config.behavior_rules[0].rule_type == "usage"
    assert route_config.behavior_rules[0].threshold == 5
    assert route_config.behavior_rules[0].window == 3600
    assert route_config.behavior_rules[0].action == "ban"

    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    return_decorator = decorator.return_monitor(
        pattern="test_pattern", max_occurrences=3, window=86400, action="log"
    )
    decorated_func2 = return_decorator(mock_func2)

    route_config2 = decorator.get_route_config(
        cast(Any, decorated_func2)._guard_route_id
    )
    assert route_config2 is not None
    assert len(route_config2.behavior_rules) == 1
    assert route_config2.behavior_rules[0].rule_type == "return_pattern"
    assert route_config2.behavior_rules[0].threshold == 3
    assert route_config2.behavior_rules[0].pattern == "test_pattern"
    assert route_config2.behavior_rules[0].window == 86400
    assert route_config2.behavior_rules[0].action == "log"

    mock_func3 = Mock()
    mock_func3.__name__ = mock_func3.__qualname__ = "test_func3"
    mock_func3.__module__ = "test_module"

    rules = [
        BehaviorRule("usage", threshold=10, window=3600),
        BehaviorRule("return_pattern", threshold=5, pattern="win", window=86400),
    ]
    behavior_decorator = decorator.behavior_analysis(rules)
    decorated_func3 = behavior_decorator(mock_func3)

    route_config3 = decorator.get_route_config(
        cast(Any, decorated_func3)._guard_route_id
    )
    assert route_config3 is not None
    assert len(route_config3.behavior_rules) == 2
    assert route_config3.behavior_rules[0].rule_type == "usage"
    assert route_config3.behavior_rules[1].rule_type == "return_pattern"

    mock_func4 = Mock()
    mock_func4.__name__ = mock_func4.__qualname__ = "test_func4"
    mock_func4.__module__ = "test_module"

    frequency_decorator = decorator.suspicious_frequency(
        max_frequency=0.5, window=300, action="throttle"
    )
    decorated_func4 = frequency_decorator(mock_func4)

    route_config4 = decorator.get_route_config(
        cast(Any, decorated_func4)._guard_route_id
    )
    assert route_config4 is not None
    assert len(route_config4.behavior_rules) == 1
    assert route_config4.behavior_rules[0].rule_type == "frequency"
    assert route_config4.behavior_rules[0].threshold == 150
    assert route_config4.behavior_rules[0].window == 300
    assert route_config4.behavior_rules[0].action == "throttle"
