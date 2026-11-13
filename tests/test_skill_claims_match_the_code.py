import re
from pathlib import Path
from unittest.mock import Mock

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import override_settings
from guard_core.sync.core.checks.factory import DEFAULT_CHECK_CLASSES

import djangoapi_guard
from djangoapi_guard import SecurityDecorator
from djangoapi_guard.middleware import DjangoAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL
from tests.wsgi_sweep_support import config

SKILL = (
    Path(djangoapi_guard.__file__).parent
    / ".agents"
    / "skills"
    / "djapi-guard"
    / "SKILL.md"
).read_text(encoding="utf-8")


def _build() -> DjangoAPIGuard:
    return DjangoAPIGuard(lambda request: HttpResponse("ok"))


def test_a_missing_setting_raises_as_the_skill_says() -> None:
    assert "raises `ImproperlyConfigured` when Django builds it" in SKILL
    assert "falls back to `SecurityConfig()`" not in SKILL
    with (
        override_settings(GUARD_SECURITY_CONFIG=None),
        pytest.raises(ImproperlyConfigured),
    ):
        _build()


def test_the_check_count_the_skill_gives_is_the_engines_default_pipeline() -> None:
    quoted = re.search(r"guard-core's (\d+) default check classes", SKILL)
    assert quoted is not None
    assert int(quoted.group(1)) == len(DEFAULT_CHECK_CLASSES)


def test_the_only_decorator_is_adopted_when_the_middleware_is_built() -> None:
    assert "when Django builds it (server load, before the first request)" in SKILL
    guard_config = config()
    decorator = SecurityDecorator(guard_config)
    with override_settings(GUARD_SECURITY_CONFIG=guard_config):
        middleware = _build()

    assert middleware.guard_decorator is decorator


def test_two_decorators_raise_when_the_middleware_is_built() -> None:
    guard_config = config()
    alive = [SecurityDecorator(guard_config), SecurityDecorator(guard_config)]
    with (
        override_settings(GUARD_SECURITY_CONFIG=guard_config),
        pytest.raises(ImproperlyConfigured, match="GUARD_DECORATOR"),
    ):
        _build()
    assert len(alive) == 2


def test_redis_and_agent_are_built_with_the_middleware_and_connected_later(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = Mock()
    monkeypatch.setattr("guard_agent.SyncGuardAgentHandler", lambda cfg: handler)
    monkeypatch.setattr("atexit.register", lambda *args: None)
    guard_config = config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        enable_agent=True,
        agent_api_key="k" * 32,
        agent_project_id="p",
    )
    with override_settings(GUARD_SECURITY_CONFIG=guard_config):
        middleware = _build()

    assert middleware.redis_handler is not None
    assert middleware.agent_handler is handler
    assert middleware._handlers_initialized is False
