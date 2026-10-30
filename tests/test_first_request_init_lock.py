import threading
import time
from typing import Any

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization import HandlerInitializer
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard

CLIENT = "1.2.3.4"


def _ok(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


def test_concurrent_first_requests_initialize_the_handlers_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    original = HandlerInitializer.initialize_redis_handlers

    def slow(self: HandlerInitializer, *args: Any, **kwargs: Any) -> None:
        calls.append(threading.get_ident())
        time.sleep(0.2)
        original(self, *args, **kwargs)

    monkeypatch.setattr(HandlerInitializer, "initialize_redis_handlers", slow)
    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig[SyncGuardRequest](
        enable_redis=False, rate_limit=100000, enable_agent=False
    )
    guard = DjangoAPIGuard(_ok)
    statuses: list[int] = []

    def hit() -> None:
        statuses.append(
            guard(RequestFactory().get("/", REMOTE_ADDR=CLIENT)).status_code
        )

    threads = [threading.Thread(target=hit) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert statuses == [200] * 8
    assert len(calls) == 1
