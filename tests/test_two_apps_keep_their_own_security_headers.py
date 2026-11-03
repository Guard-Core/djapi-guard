from typing import Any

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

ORIGIN_A = "https://a.example"
ORIGIN_B = "https://b.example"


def _middleware(name: str, origin: str, max_age: int, redis: bool) -> DjangoAPIGuard:
    values: dict[str, Any] = {
        "enable_redis": redis,
        "redis_url": REDIS_URL if redis else None,
        "redis_prefix": f"{REDIS_PREFIX}wp102:",
        "enable_agent": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": False,
        "enable_cors": True,
        "cors_allow_origins": [origin],
        "security_headers": {
            "enabled": True,
            "csp": {"default-src": ["'self'", f"https://{name}.csp.example"]},
            "hsts": {"max_age": max_age, "include_subdomains": True},
            "frame_options": "DENY" if name == "a" else "SAMEORIGIN",
            "custom": {"X-App-Name": name},
        },
    }
    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig[SyncGuardRequest](
        **values
    )

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("ok")

    return DjangoAPIGuard(get_response)


@pytest.mark.parametrize("redis", [False, True])
def test_two_apps_in_one_process_each_answer_with_their_own_headers(
    redis: bool,
) -> None:
    app_a = _middleware("a", ORIGIN_A, 31536000, redis)
    app_b = _middleware("b", ORIGIN_B, 63072000, redis)
    factory = RequestFactory()
    assert (app_a.redis_handler is not None) is redis
    for _ in range(2):
        a = app_a(factory.get("/x", HTTP_ORIGIN=ORIGIN_A))
        b = app_b(factory.get("/x", HTTP_ORIGIN=ORIGIN_B))
        assert a["Content-Security-Policy"].endswith("https://a.csp.example")
        assert b["Content-Security-Policy"].endswith("https://b.csp.example")
        assert a["Strict-Transport-Security"].startswith("max-age=31536000")
        assert b["Strict-Transport-Security"].startswith("max-age=63072000")
        assert a["X-App-Name"] == "a"
        assert b["X-App-Name"] == "b"
        assert a["X-Frame-Options"] == "DENY"
        assert b["X-Frame-Options"] == "SAMEORIGIN"
        assert a["Access-Control-Allow-Origin"] == ORIGIN_A
        assert b["Access-Control-Allow-Origin"] == ORIGIN_B
        cross = app_a(factory.get("/x", HTTP_ORIGIN=ORIGIN_B))
        assert "Access-Control-Allow-Origin" not in cross
