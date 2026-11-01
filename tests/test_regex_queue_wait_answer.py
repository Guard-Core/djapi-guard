import concurrent.futures
import threading
from collections.abc import Iterator

import pytest
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.detection_engine import compiler as compiler_module
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard

BUSY_ROW = "[xyz]7"


@pytest.fixture
def saturated_regex_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    workers = compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    monkeypatch.setattr(compiler_module, "_shared_executor", pool)
    release = threading.Event()
    all_running = threading.Barrier(workers + 1)

    def hold() -> None:
        all_running.wait(10)
        release.wait(30)

    for _ in range(workers):
        pool.submit(hold)
    all_running.wait(10)
    yield
    release.set()
    pool.shutdown(wait=True)


@pytest.fixture
def guarded() -> Iterator[DjangoAPIGuard]:
    import django.conf

    config = SecurityConfig[SyncGuardRequest](
        enable_rate_limiting=False,
        enable_redis=False,
        enable_agent=False,
        fail_secure=True,
        detection_compiler_timeout=0.3,
        custom_error_responses={503: "Busy, retry shortly"},
    )
    django.conf.settings.GUARD_SECURITY_CONFIG = config

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("OK", status=200)

    middleware = DjangoAPIGuard(get_response)
    sus_patterns_manager_for(config).add_pattern(BUSY_ROW, custom=True)
    yield middleware
    sus_patterns_manager_for(config).remove_pattern(BUSY_ROW, custom=True)


def _get(middleware: DjangoAPIGuard) -> HttpResponseBase:
    request = RequestFactory().get("/ping?q=hello")
    request.META["REMOTE_ADDR"] = "203.0.113.9"
    return middleware(request)


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_answers_503_with_retry_after_and_the_custom_message(
    guarded: DjangoAPIGuard,
) -> None:
    response = _get(guarded)

    assert response.status_code == 503
    assert response["Retry-After"] == "1"
    assert isinstance(response, HttpResponse)
    assert response.content.decode() == "Busy, retry shortly"


def test_the_same_request_on_a_free_pool_passes(guarded: DjangoAPIGuard) -> None:
    assert _get(guarded).status_code == 200
