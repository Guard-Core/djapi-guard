"""D-188 end to end: a runtime Redis outage reaches the Django client as 503
with Retry-After.

Real Django request through the middleware and the real engine. Only the Redis
client the engine holds is replaced, by one whose commands raise redis' own
ConnectionError.
"""

from typing import Any

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseBase
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from redis.exceptions import ConnectionError as RedisConnectionError

from djangoapi_guard.middleware import DjangoAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL


class _DeadRedis:
    def __getattr__(self, name: str) -> Any:
        def command(*args: Any, **kwargs: Any) -> Any:
            raise RedisConnectionError("Redis went away")

        return command


def _get_after_redis_died(path: str, **overrides: Any) -> HttpResponseBase:
    settings: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": f"{REDIS_PREFIX}wp192:",
        "enable_agent": False,
        "fail_secure": True,
        "redis_fail_open": False,
        "enable_penetration_detection": False,
        "exclude_paths": ["/health"],
    }
    settings.update(overrides)
    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig[SyncGuardRequest](
        **settings
    )

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("OK", status=200)

    middleware = DjangoAPIGuard(get_response)
    factory = RequestFactory()
    assert middleware(factory.get("/open")).status_code == 200
    assert middleware.redis_handler is not None
    middleware.redis_handler._redis = _DeadRedis()
    return middleware(factory.get(path))


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_runtime_outage_answers_503_with_retry_after(path: str) -> None:
    response = _get_after_redis_died(path)
    assert response.status_code == 503
    assert response.headers.get("Retry-After") == "5"


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_passive_mode_admits_during_a_runtime_outage(path: str) -> None:
    assert _get_after_redis_died(path, passive_mode=True).status_code == 200


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_redis_fail_open_admits_during_a_runtime_outage(path: str) -> None:
    assert _get_after_redis_died(path, redis_fail_open=True).status_code == 200
