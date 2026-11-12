"""LEDGER 6.793 / D-317 amendment 2: a request on an app that was released rebinds
and initializes it before it decides, once, whatever the number of first requests."""

import threading
import time
import uuid
from typing import Any

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers._ipban_bans import _VERSION_PAIR
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import release_app
from djangoapi_guard.middleware import DjangoAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

CLIENT_IP = "203.0.113.9"


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    settings: dict[str, Any] = {"enable_redis": False, "enable_agent": False}
    settings.update(overrides)
    return SecurityConfig[SyncGuardRequest](**settings)


def _view(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


def _middleware(
    monkeypatch: pytest.MonkeyPatch, config: SecurityConfig[SyncGuardRequest]
) -> DjangoAPIGuard:
    monkeypatch.setattr(
        django.conf.settings, "GUARD_SECURITY_CONFIG", config, raising=False
    )
    return DjangoAPIGuard(_view)


def _get(middleware: DjangoAPIGuard, factory: RequestFactory) -> int:
    return middleware(factory.get("/", REMOTE_ADDR=CLIENT_IP)).status_code


def _limiter_managers(middleware: DjangoAPIGuard) -> list[Any]:
    assert middleware.security_pipeline is not None
    return [
        check.ip_ban_manager
        for check in middleware.security_pipeline.checks
        if isinstance(check, RateLimitCheck)
    ]


def test_a_late_request_rebinds_and_its_ban_lands_on_its_own_manager(
    monkeypatch: pytest.MonkeyPatch, request_factory: RequestFactory
) -> None:
    config = _config()
    middleware = _middleware(monkeypatch, config)
    other_config = _config()
    assert _get(middleware, request_factory) == 200
    release_app(config)
    assert ip_ban_manager_for(other_config, bind=True) is ipban_module.ip_ban_manager
    try:
        assert _get(middleware, request_factory) == 200
        own = ip_ban_manager_for(config)
        assert own is not ipban_module.ip_ban_manager
        managers = _limiter_managers(middleware)
        assert managers
        assert all(manager is own for manager in managers)
        managers[0].ban_ip("198.51.100.7", 60, "pin")
        assert own.is_ip_banned("198.51.100.7")
        assert not ipban_module.ip_ban_manager.is_ip_banned("198.51.100.7")
    finally:
        release_app(other_config)


def test_two_concurrent_first_requests_after_a_release_initialize_once(
    monkeypatch: pytest.MonkeyPatch, request_factory: RequestFactory
) -> None:
    config = _config()
    middleware = _middleware(monkeypatch, config)
    assert _get(middleware, request_factory) == 200
    assert middleware.handler_initializer is not None
    calls: list[float] = []

    def counted_initialize() -> None:
        calls.append(time.monotonic())
        time.sleep(0.1)

    monkeypatch.setattr(
        middleware.handler_initializer, "initialize_redis_handlers", counted_initialize
    )
    release_app(config)
    barrier = threading.Barrier(2)
    statuses: list[int] = []

    def first_request() -> None:
        barrier.wait()
        statuses.append(_get(middleware, request_factory))

    threads = [threading.Thread(target=first_request) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses == [200, 200]
    assert len(calls) == 1


def test_a_ban_another_worker_wrote_in_redis_is_refused_after_a_release(
    monkeypatch: pytest.MonkeyPatch, request_factory: RequestFactory
) -> None:
    prefix = f"{REDIS_PREFIX}wp620r3:{uuid.uuid4().hex[:8]}:"
    config = _config(enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix)
    middleware = _middleware(monkeypatch, config)
    assert _get(middleware, request_factory) == 200
    release_app(config)
    worker = RedisManager(
        SecurityConfig[SyncGuardRequest](
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=prefix,
            enable_agent=False,
        )
    )
    worker.initialize()
    try:
        worker.write_ban_extending_only(
            "banned_ips", CLIENT_IP, str(time.time() + 300), 300, version=_VERSION_PAIR
        )
        assert _get(middleware, request_factory) == 403
        assert ip_ban_manager_for(config).redis_handler is not None
    finally:
        worker.close()
