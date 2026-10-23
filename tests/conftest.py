import os
from collections.abc import Generator, Iterator
from typing import Any

import pytest
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import djangoapi_guard._decorator_adoption as decorator_adoption
from tests.redis_isolation import (
    REDIS_PREFIX,
    REDIS_URL,
    delete_every_key_under_the_suite_prefix,
    point_security_config_defaults_at_the_test_redis,
    refuse_connections_to_the_default_redis_port,
    refused_connections,
)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

point_security_config_defaults_at_the_test_redis()


@pytest.fixture(scope="session", autouse=True)
def _refuse_the_default_redis_port() -> Generator[None, None, None]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        refuse_connections_to_the_default_redis_port(monkeypatch)
        yield


@pytest.fixture(autouse=True)
def refused_redis_connections() -> Generator[list[tuple[Any, ...]], None, None]:
    refused_connections.clear()
    yield refused_connections
    attempts = list(refused_connections)
    refused_connections.clear()
    assert not attempts, f"the test connected to port 6379: {attempts}"


@pytest.fixture(autouse=True)
def redis_cleanup() -> None:
    delete_every_key_under_the_suite_prefix()


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    terminalreporter.write_line(
        f"redis isolation: REDIS_URL={REDIS_URL} REDIS_PREFIX={REDIS_PREFIX}"
    )


@pytest.fixture
def request_factory() -> RequestFactory:
    return RequestFactory()


@pytest.fixture
def security_config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )


@pytest.fixture
def make_request(request_factory: RequestFactory) -> Any:
    def _make_request(
        method: str = "GET",
        path: str = "/",
        data: Any = None,
        content_type: str = "application/json",
        **headers: str,
    ) -> Any:
        method_func = getattr(request_factory, method.lower())
        kwargs: dict[str, Any] = {}
        if data is not None:
            kwargs["data"] = data
            kwargs["content_type"] = content_type

        meta: dict[str, str] = {}
        for key, value in headers.items():
            meta_key = f"HTTP_{key.upper().replace('-', '_')}"
            meta[meta_key] = value

        request = method_func(path, **kwargs)
        for key, value in meta.items():
            request.META[key] = value

        return request

    return _make_request


@pytest.fixture(autouse=True)
def forget_registered_decorators() -> None:
    decorator_adoption._created.clear()


@pytest.fixture(autouse=True)
def cleanup_ipban_singleton() -> Iterator[None]:
    yield
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.redis_handler = None
    ip_ban_manager.agent_handler = None


@pytest.fixture(autouse=True)
def cleanup_suspatterns_singleton() -> Iterator[None]:
    yield
    sus_patterns_handler.redis_handler = None
    sus_patterns_handler.agent_handler = None


@pytest.fixture(autouse=True)
def reset_headers_manager() -> Iterator[None]:
    yield
    security_headers_manager.enabled = False
    security_headers_manager.headers_cache.clear()


@pytest.fixture(autouse=True)
def reset_ratelimit_singleton() -> Iterator[None]:
    yield
    manager = getattr(RateLimitManager, "_instance", None)
    if manager is not None:
        manager.request_timestamps.clear()
        manager.redis_handler = None
        manager.agent_handler = None
