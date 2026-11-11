import os
import sys
import weakref
from collections.abc import Callable, Generator, Iterator
from typing import Any, Concatenate, ParamSpec

import django
import pytest
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync import release_app
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.cloud_handler import cloud_handler_for
from guard_core.sync.handlers.ipban_handler import reset_global_state
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import djangoapi_guard._decorator_adoption as decorator_adoption
from tests import network_guard, thread_guard
from tests.agent_loop import close_the_agent_event_loop
from tests.redis_isolation import (
    REDIS_PREFIX,
    REDIS_URL,
    delete_every_key_under_the_suite_prefix,
    point_security_config_defaults_at_the_test_redis,
    refuse_connections_to_the_default_redis_port,
    refused_connections,
)

network_guard.install()
thread_guard.install()

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
django.setup()

point_security_config_defaults_at_the_test_redis()


@pytest.fixture(scope="session", autouse=True)
def _refuse_the_default_redis_port() -> Generator[None, None, None]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        refuse_connections_to_the_default_redis_port(monkeypatch)
        yield


@pytest.fixture(autouse=True)
def _close_the_agent_event_loop() -> Generator[None, None, None]:
    yield
    close_the_agent_event_loop()


@pytest.fixture(autouse=True)
def refused_redis_connections() -> Generator[list[tuple[Any, ...]], None, None]:
    refused_connections.clear()
    yield refused_connections
    attempts = list(refused_connections)
    refused_connections.clear()
    assert not attempts, f"the test connected to port 6379: {attempts}"


def _refuse_the_ipinfo_download(self: object) -> None:
    raise ConnectionError("the test suite has no network")


@pytest.fixture(autouse=True)
def no_ipinfo_database_download(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guard_core.sync.handlers.ipinfo_handler.IPInfoManager._fetch_and_store_database",
        _refuse_the_ipinfo_download,
    )


@pytest.fixture(autouse=True)
def no_cloud_range_downloads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler._fetch_provider_ranges",
        lambda provider: (set(), {}),
    )


@pytest.fixture(autouse=True)
def redis_cleanup() -> None:
    delete_every_key_under_the_suite_prefix()


@pytest.fixture(scope="session", autouse=True)
def _delete_the_last_tests_keys() -> Generator[None, None, None]:
    yield
    delete_every_key_under_the_suite_prefix()


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    terminalreporter.write_line(
        f"redis isolation: REDIS_URL={REDIS_URL} REDIS_PREFIX={REDIS_PREFIX}"
    )


@pytest.fixture(scope="session", autouse=True)
def _engine_default_redis_url_follows_redis_url() -> None:
    # A SecurityConfig built without redis_url falls back to localhost:6379, which
    # is not where Redis lives inside the compose network.
    SecurityConfig.model_fields["redis_url"].default = (
        os.getenv("REDIS_URL") or "redis://localhost:6379"
    )
    SecurityConfig.model_rebuild(force=True)


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


_P = ParamSpec("_P")


def _recording_the_config_it_binds(
    original: Callable[Concatenate[HandlerInitializer, _P], None],
    bound: list[weakref.ref[SecurityConfig[SyncGuardRequest]]],
) -> Callable[Concatenate[HandlerInitializer, _P], None]:
    def initializer(
        self: HandlerInitializer, *args: _P.args, **kwargs: _P.kwargs
    ) -> None:
        original(self, *args, **kwargs)
        bound.append(weakref.ref(self.config))

    return initializer


def _let_the_scheduled_cloud_refresh_end(
    config: SecurityConfig[SyncGuardRequest],
) -> None:
    # A request schedules a background download; it must end while the fixture
    # that refuses the download is still in place.
    refresh = cloud_handler_for(config)._refresh_task
    if refresh is not None:
        refresh.join(timeout=30)


@pytest.fixture(autouse=True)
def _release_every_app_between_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """HandlerInitializer binds an app's config to the engine's managers; an app
    that nothing releases keeps that binding until the collector frees it, so
    which managers the next test gets would depend on collector timing (D-317)."""
    bound: list[weakref.ref[SecurityConfig[SyncGuardRequest]]] = []
    monkeypatch.setattr(
        HandlerInitializer,
        "__init__",
        _recording_the_config_it_binds(HandlerInitializer.__init__, bound),
    )
    yield
    for reference in bound:
        config = reference()
        if config is not None:
            _let_the_scheduled_cloud_refresh_end(config)
            release_app(config)


@pytest.fixture(autouse=True)
def forget_registered_decorators() -> None:
    decorator_adoption._created.clear()


@pytest.fixture(autouse=True)
def cleanup_ipban_singleton() -> Iterator[None]:
    yield
    reset_global_state()


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


@pytest.fixture(autouse=True)
def _no_outbound_network() -> Iterator[None]:
    network_guard.reset()
    yield
    violations = network_guard.drain()
    assert not violations, "test reached the network:\n" + "\n".join(violations)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    thread_guard.stop_the_shared_regex_pools()
    leaked = thread_guard.leaked_threads()
    if leaked:
        sys.stderr.write(f"\nthreads the tests left running: {leaked}\n")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
