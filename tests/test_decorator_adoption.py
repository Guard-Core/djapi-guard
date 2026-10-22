import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import Client, override_settings
from django.urls import clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler

import djangoapi_guard._decorator_adoption as adoption
import djangoapi_guard.middleware as middleware_module
from djangoapi_guard import SecurityDecorator


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        rate_limit=1000,
        ban_on_hostile_signals=False,
    )


@pytest.fixture(autouse=True)
def _isolated() -> Iterator[None]:
    adoption._created.clear()
    middleware_module._decorator_missing_warned = False
    yield
    adoption._created.clear()
    rate_limit_handler(_config()).reset()


@contextmanager
def _served(urlconf: str, **extra: Any) -> Iterator[Client]:
    sys.modules.pop(urlconf, None)
    clear_url_caches()
    try:
        with override_settings(
            ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=_config(), **extra
        ):
            yield Client()
    finally:
        sys.modules.pop(urlconf, None)
        clear_url_caches()


def _statuses(client: Client, count: int = 3) -> list[int]:
    return [client.get("/limited").status_code for _ in range(count)]


def test_readme_usage_enforces_the_view_decorator() -> None:
    with _served("tests.readme_adoption_urls") as client:
        assert _statuses(client) == [200, 429, 429]


def test_setting_dotted_path_picks_among_two_decorators() -> None:
    with _served(
        "tests.two_decorators_urls",
        GUARD_DECORATOR="tests.two_decorators_urls.guard_deco",
    ) as client:
        assert _statuses(client) == [200, 429, 429]


def test_two_decorators_without_setting_raise_improperly_configured() -> None:
    with _served("tests.two_decorators_urls") as client:
        with pytest.raises(ImproperlyConfigured) as raised:
            client.get("/limited")
    message = str(raised.value)
    assert "GUARD_DECORATOR" in message
    assert message.count("_decorator_adoption.SecurityDecorator at") == 2


def test_decorator_outside_the_registry_warns_once_naming_the_fix(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        with _served("tests.unregistered_decorator_urls") as client:
            assert _statuses(client) == [200, 200, 200]
    named = [r for r in caplog.records if "GUARD_DECORATOR" in r.getMessage()]
    assert len(named) == 1


def test_setting_accepts_the_decorator_instance() -> None:
    chosen = SecurityDecorator(_config())
    SecurityDecorator(_config())
    with override_settings(GUARD_DECORATOR=chosen):
        assert adoption.resolve_decorator() is chosen


def test_setting_rejects_a_value_that_is_not_a_decorator() -> None:
    with override_settings(GUARD_DECORATOR=object()):
        with pytest.raises(ImproperlyConfigured):
            adoption.resolve_decorator()


def test_a_dead_decorator_is_forgotten() -> None:
    SecurityDecorator(_config())
    import gc

    gc.collect()
    assert adoption.resolve_decorator() is None
    assert adoption._created == []
