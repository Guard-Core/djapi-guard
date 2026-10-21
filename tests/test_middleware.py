import logging
import os
import sys
import time
from collections.abc import Awaitable, Callable, Iterator
from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    rate_limit_handler,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityDecorator
from djangoapi_guard.adapters import DjangoGuardRequest, DjangoGuardResponse
from djangoapi_guard.middleware import DjangoAPIGuard

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> Iterator[None]:
    yield
    config = SecurityConfig(enable_redis=False, enable_agent=False)
    handler = rate_limit_handler(config)
    handler.reset()


class TestDjangoAPIGuard:
    def _make_middleware(self, config: SecurityConfig | None = None) -> DjangoAPIGuard:
        if config is None:
            config = SecurityConfig(
                enable_redis=False,
                enable_agent=False,
                enable_penetration_detection=False,
            )

        import django.conf

        django.conf.settings.GUARD_SECURITY_CONFIG = config

        def get_response(request: HttpRequest) -> HttpResponse:
            return HttpResponse("OK", status=200)

        return DjangoAPIGuard(get_response)

    def test_middleware_creation(self) -> None:
        middleware = self._make_middleware()
        assert middleware is not None
        assert middleware.config is not None

    def test_passthrough_request(self) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        response = middleware(request)
        assert response.status_code == 200

    def test_passthrough_request_no_client_host(self) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        request.META.pop("REMOTE_ADDR", None)
        response = middleware(request)
        assert response.status_code == 403

    def test_excluded_path(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            exclude_paths=["/health"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/health")
        response = middleware(request)
        assert response.status_code == 200

    def test_ip_blacklist(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            blacklist=["192.168.1.100"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/api/test/")
        request.META["REMOTE_ADDR"] = "192.168.1.100"
        response = middleware(request)
        assert response.status_code == 403

    def test_ip_whitelist_allows(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            whitelist=["10.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_ip_whitelist_blacklist_combined(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["127.0.0.1"],
            blacklist=["192.168.1.1"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.1"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 403

    def test_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            rate_limit=2,
            rate_limit_window=60,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for _ in range(3):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "10.0.0.50"
            response = middleware(request)

        assert response.status_code == 429

    def test_rate_limiting_with_reset(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 429

        middleware.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_rate_limiting_multiple_ips(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=60,
            enable_rate_limiting=True,
            whitelist=[],
            blacklist=[],
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for i in range(1, 4):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.1"
            response = middleware(request)
            assert response.status_code == (200 if i <= 2 else 429)

        for i in range(1, 4):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.5"
            response = middleware(request)
            assert response.status_code == (200 if i <= 2 else 429)

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"
        response = middleware(request)
        assert response.status_code == 429

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.5"
        response = middleware(request)
        assert response.status_code == 429

    def test_rate_limiting_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            enable_rate_limiting=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for _ in range(20):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "10.0.0.1"
            response = middleware(request)
            assert response.status_code == 200

    def test_sliding_window_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            rate_limit=3,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        handler = rate_limit_handler(config)
        handler.reset()

        for _ in range(3):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "127.0.0.1"
            response = middleware(request)
            assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 429

        time.sleep(1.5)

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_cleanup_expired_request_times(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            rate_limit=2,
            rate_limit_window=1,
        )
        middleware = self._make_middleware(config)
        handler = middleware.rate_limit_handler
        handler.reset()

        assert len(handler.request_timestamps) == 0

        current_time = time.time()
        handler.request_timestamps["ip1"].append(current_time)
        handler.request_timestamps["ip1"].append(current_time)
        handler.request_timestamps["ip2"].append(current_time)

        assert len(handler.request_timestamps["ip1"]) == 2
        assert len(handler.request_timestamps["ip2"]) == 1
        assert len(handler.request_timestamps) == 2

        handler.reset()
        assert len(handler.request_timestamps) == 0

    def test_rate_limiter_deque_cleanup(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            rate_limit=10,
            rate_limit_window=60,
        )
        handler = rate_limit_handler(config)
        handler.reset()

        current_time = time.time()
        window_start = current_time - config.rate_limit_window
        client_ip = "192.168.1.1"

        old_queue = handler.request_timestamps[client_ip]
        old_queue.append(window_start - 0.5)
        old_queue.append(window_start - 0.7)
        old_queue.append(window_start - 0.2)

        assert len(old_queue) == 3
        assert all(ts < window_start for ts in old_queue)

        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = client_ip

        def create_error_response(
            status_code: int, message: str
        ) -> DjangoGuardResponse:
            return DjangoGuardResponse(HttpResponse(message, status=status_code))

        result = handler.check_rate_limit(
            DjangoGuardRequest(request), client_ip, create_error_response
        )
        assert result is None
        assert len(handler.request_timestamps[client_ip]) == 1

    def test_passive_mode(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            passive_mode=True,
            blacklist=["192.168.1.100"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.100"
        response = middleware(request)
        assert response.status_code == 200

    def test_passive_mode_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            passive_mode=True,
            rate_limit=1,
            rate_limit_window=60,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_passive_mode_penetration_detection(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            passive_mode=True,
            whitelist=[],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        with (
            patch(
                "guard_core.sync.core.checks.implementations.suspicious_activity.log_activity"
            ),
            patch(
                "guard_core.sync.utils.detect_penetration_attempt",
                return_value=DetectionResult(
                    is_threat=True, trigger_info="SQL injection attempt"
                ),
            ),
        ):
            request = factory.get("/login")
            request.META["REMOTE_ADDR"] = "10.0.0.1"
            response = middleware(request)
            assert response.status_code == 200

    def test_user_agent_blocking(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            blocked_user_agents=["BadBot"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["HTTP_USER_AGENT"] = "BadBot/1.0"
        response = middleware(request)
        assert response.status_code == 403

    def test_user_agent_filtering_allowed(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            blocked_user_agents=[r"badbot"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["HTTP_USER_AGENT"] = "badbot"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["HTTP_USER_AGENT"] = "goodbot"
        response = middleware(request)
        assert response.status_code == 200

    def test_custom_request_check(self) -> None:
        from djangoapi_guard.adapters import DjangoGuardResponse

        def custom_check(request: SyncGuardRequest) -> GuardResponse | None:
            if request.headers.get("X-Custom-Header") == "block":
                return DjangoGuardResponse(HttpResponse("Custom block", status=403))
            return None

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            custom_request_check=cast(
                Callable[[GuardRequest], Awaitable[GuardResponse | None]], custom_check
            ),
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["HTTP_X_CUSTOM_HEADER"] = "block"
        response = middleware(request)
        assert response.status_code == 403
        assert response.content == b"Custom block"

        request = factory.get("/")
        request.META["HTTP_X_CUSTOM_HEADER"] = "allow"
        response = middleware(request)
        assert response.status_code == 200

    def test_custom_response_modifier(self) -> None:
        def custom_modifier(response: GuardResponse) -> GuardResponse:
            response.headers["X-Modified"] = "True"
            return response

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            custom_response_modifier=cast(
                Callable[[GuardResponse], Awaitable[GuardResponse]], custom_modifier
            ),
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response["X-Modified"] == "True"
        assert response.status_code == 200

    def test_custom_response_modifier_with_blacklist(self) -> None:
        def custom_modifier(response: GuardResponse) -> GuardResponse:
            response.headers["X-Modified"] = "True"
            return response

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            blacklist=["192.168.1.5"],
            custom_response_modifier=cast(
                Callable[[GuardResponse], Awaitable[GuardResponse]], custom_modifier
            ),
            trusted_proxies=["127.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response["X-Modified"] == "True"
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.5"
        response = middleware(request)
        assert response.status_code == 403

    def test_custom_response_modifier_with_custom_check(self) -> None:
        from djangoapi_guard.adapters import DjangoGuardResponse

        def custom_modifier(response: GuardResponse) -> GuardResponse:
            response.headers["X-Modified"] = "True"
            return response

        def custom_check(request: SyncGuardRequest) -> GuardResponse | None:
            if request.headers.get("X-Custom-Check"):
                return DjangoGuardResponse(HttpResponse("I'm a teapot", status=418))
            return None

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            custom_response_modifier=cast(
                Callable[[GuardResponse], Awaitable[GuardResponse]], custom_modifier
            ),
            custom_request_check=cast(
                Callable[[GuardRequest], Awaitable[GuardResponse | None]], custom_check
            ),
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["HTTP_X_CUSTOM_CHECK"] = "true"
        response = middleware(request)
        assert response.status_code == 418

        request = factory.get("/")
        response = middleware(request)
        assert response["X-Modified"] == "True"
        assert response.status_code == 200

    def test_custom_error_responses(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            custom_error_responses={403: "Custom Forbidden"},
        )
        middleware = self._make_middleware(config)
        response = middleware.create_error_response(403, "Default")
        assert response.body is not None
        assert b"Custom Forbidden" in response.body

    def test_custom_error_responses_with_rate_limit(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blacklist=["192.168.1.3"],
            custom_error_responses={
                403: "Custom Forbidden",
                429: "Custom Too Many Requests",
            },
            rate_limit=5,
            rate_limit_window=60,
            auto_ban_threshold=10,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.3"
        response = middleware(request)
        assert response.status_code == 403
        assert b"Custom Forbidden" in response.content

        for _ in range(5):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.4"
            response = middleware(request)
            assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.4"
        response = middleware(request)
        assert response.status_code == 429
        assert b"Custom Too Many Requests" in response.content

    def test_cors_preflight(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            enable_cors=True,
            cors_allow_origins=["http://example.com"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.options("/")
        request.META["HTTP_ORIGIN"] = "http://example.com"
        request.META["HTTP_ACCESS_CONTROL_REQUEST_METHOD"] = "GET"
        response = middleware(request)
        assert response.status_code == 200
        assert response["Access-Control-Allow-Origin"] == "http://example.com"

    def test_cors_preflight_with_methods_and_headers(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            enable_cors=True,
            cors_allow_origins=["https://example.com"],
            cors_allow_methods=["GET", "POST"],
            cors_allow_headers=["Content-Type"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.options("/")
        request.META["HTTP_ORIGIN"] = "https://example.com"
        request.META["HTTP_ACCESS_CONTROL_REQUEST_METHOD"] = "POST"
        request.META["HTTP_ACCESS_CONTROL_REQUEST_HEADERS"] = "Content-Type"
        response = middleware(request)
        assert response.status_code == 200
        assert response["Access-Control-Allow-Origin"] == "https://example.com"

    def test_cors_disabled(self) -> None:
        from guard_core.sync.handlers.security_headers_handler import (
            security_headers_manager,
        )

        security_headers_manager.reset()
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            enable_cors=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["HTTP_ORIGIN"] = "https://example.com"
        response = middleware(request)
        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" not in response

    def test_cloud_ip_blocking(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            block_cloud_providers={"AWS", "GCP", "Azure"},
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        with patch.object(cloud_handler, "is_cloud_ip", return_value=True):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "13.59.255.255"
            response = middleware(request)
            assert response.status_code == 403

        with patch.object(cloud_handler, "is_cloud_ip", return_value=False):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "8.8.8.8"
            response = middleware(request)
            assert response.status_code == 200

    def test_cloud_ip_refresh_no_providers(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            block_cloud_providers=None,
        )
        middleware = self._make_middleware(config)

        initial_refresh_time = middleware.last_cloud_ip_refresh
        middleware.refresh_cloud_ip_ranges()
        assert middleware.last_cloud_ip_refresh == initial_refresh_time

    def test_penetration_detection_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/wp-admin")
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_emergency_mode_passive(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            emergency_mode=True,
            passive_mode=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/test")
        request.META["REMOTE_ADDR"] = "8.8.8.8"
        response = middleware(request)
        assert response.status_code == 200

    def test_create_error_response(self) -> None:
        middleware = self._make_middleware()
        response = middleware.create_error_response(403, "Forbidden")
        assert response.status_code == 403

    def test_reset(self) -> None:
        middleware = self._make_middleware()
        middleware.reset()

    def test_reset_clears_rate_limits(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            rate_limit=2,
            rate_limit_window=60,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for _ in range(2):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "127.0.0.1"
            middleware(request)

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 429

        middleware.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_redis_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        assert middleware.redis_handler is None
        assert middleware.rate_limit_handler is not None
        middleware.rate_limit_handler.reset()

    def test_redis_initialization(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url=REDIS_URL,
            block_cloud_providers={"AWS"},
        )
        with (
            patch(
                "guard_core.sync.handlers.redis_handler.RedisManager.initialize"
            ) as redis_init,
            patch(
                "guard_core.sync.handlers.cloud_handler.cloud_handler.initialize_redis"
            ) as cloud_init,
            patch(
                "guard_core.sync.handlers.ipban_handler.ip_ban_manager.initialize_redis"
            ) as ipban_init,
            patch(
                "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
            ) as sus_init,
            patch(
                "guard_core.sync.handlers.ratelimit_handler.RateLimitManager.initialize_redis"
            ) as rate_init,
        ):
            middleware = self._make_middleware(config)
            middleware._initialize_handlers()

            redis_init.assert_called_once()
            cloud_init.assert_called_once()
            ipban_init.assert_called_once()
            sus_init.assert_called_once()
            rate_init.assert_called_once()

    def test_redis_initialization_without_cloud(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url=REDIS_URL,
        )
        with (
            patch(
                "guard_core.sync.handlers.redis_handler.RedisManager.initialize"
            ) as redis_init,
            patch(
                "guard_core.sync.handlers.cloud_handler.cloud_handler.initialize_redis"
            ) as cloud_init,
            patch(
                "guard_core.sync.handlers.ipban_handler.ip_ban_manager.initialize_redis"
            ) as ipban_init,
            patch(
                "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
            ) as sus_init,
            patch(
                "guard_core.sync.handlers.ratelimit_handler.RateLimitManager.initialize_redis"
            ) as rate_init,
        ):
            middleware = self._make_middleware(config)
            middleware._initialize_handlers()

            redis_init.assert_called_once()
            cloud_init.assert_not_called()
            ipban_init.assert_called_once()
            sus_init.assert_called_once()
            rate_init.assert_called_once()

    def test_agent_initialization_import_error(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
        )
        with patch.object(
            SecurityConfig,
            "to_agent_config",
            return_value=MagicMock(),
        ):
            middleware = self._make_middleware(config)
            assert middleware.agent_handler is None

    def test_agent_initialization_success(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
        )
        mock_agent_instance = MagicMock()
        mock_guard_agent_fn = MagicMock(return_value=mock_agent_instance)
        mock_agent_module: Any = MagicMock()
        mock_agent_module.guard_agent = mock_guard_agent_fn

        mock_agent_config = MagicMock()

        with patch.object(
            SecurityConfig,
            "to_agent_config",
            return_value=mock_agent_config,
        ):
            with patch.dict(sys.modules, {"guard_agent": mock_agent_module}):
                middleware = self._make_middleware(config)
                middleware._initialize_handlers()
                assert middleware.handler_initializer is not None
                composite = middleware.handler_initializer.composite_handler
                assert composite is not None
                assert middleware.agent_handler is composite
                assert mock_agent_instance in composite._handlers
                mock_guard_agent_fn.assert_called_once_with(mock_agent_config)

    def test_agent_initialization_invalid_config(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
        )
        with patch(
            "guard_core.models.SecurityConfig.to_agent_config",
            return_value=None,
        ):
            middleware = self._make_middleware(config)
            assert middleware.agent_handler is None

    def test_request_with_unknown_client_ip(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        with patch(
            "djangoapi_guard.middleware.extract_client_ip",
            return_value="unknown",
        ):
            request = factory.get("/")
            response = middleware(request)
            assert response.status_code == 200

    def test_set_decorator_handler(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)

        mock_decorator = MagicMock(spec=BaseSecurityDecorator)
        middleware.set_decorator_handler(mock_decorator)

        assert middleware.guard_decorator is mock_decorator
        assert middleware.route_resolver is not None
        assert middleware.route_resolver.context.guard_decorator is mock_decorator
        assert middleware.behavioral_processor is not None
        assert middleware.behavioral_processor.context.guard_decorator is mock_decorator
        assert middleware.response_factory is not None
        assert middleware.response_factory.context.guard_decorator is mock_decorator
        assert middleware.handler_initializer is not None
        assert middleware.handler_initializer.guard_decorator is mock_decorator

    def test_security_headers_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            security_headers={"enabled": False},
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200
        assert "X-Content-Type-Options" not in response

    def test_security_headers_none(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            security_headers=None,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_ipv6_blacklist(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["::1", "2001:db8::1"],
            blacklist=["2001:db8::dead:beef"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1", "::1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::dead:beef"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::2"
        response = middleware(request)
        assert response.status_code == 403

    def test_ipv6_cidr_whitelist_blacklist(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["2001:db8::/32"],
            blacklist=["2001:db8:dead::/48"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1", "::1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8:1::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8:dead::beef"
        response = middleware(request)
        # In both a whitelist CIDR and the blacklist: whitelist overrides
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db9::1"
        response = middleware(request)
        assert response.status_code == 403

    def test_mixed_ipv4_ipv6_handling(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["127.0.0.1", "::1", "192.168.1.0/24", "2001:db8::/32"],
            blacklist=["192.168.1.100", "2001:db8:dead::beef"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1", "::1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.50"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.100"
        response = middleware(request)
        # In both a whitelist CIDR and the blacklist: whitelist overrides
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8:dead::beef"
        response = middleware(request)
        # In both a whitelist CIDR and the blacklist: whitelist overrides
        assert response.status_code == 200

    def test_ipv6_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=60,
            enable_rate_limiting=True,
            whitelist=[],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        handler = rate_limit_handler(config)
        handler.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 429

        handler = rate_limit_handler(config)
        handler.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

    def _make_redis_middleware(self, config: SecurityConfig) -> DjangoAPIGuard:
        with patch(
            "guard_core.sync.core.initialization.handler_initializer.HandlerInitializer.initialize_redis_handlers"
        ):
            return self._make_middleware(config)

    def test_lua_script_execution(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url=REDIS_URL,
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_redis_middleware(config)
        handler = middleware.rate_limit_handler

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        handler.redis_handler = mock_redis_handler

        mock_conn = MagicMock()
        mock_conn.evalsha = MagicMock(return_value=1)

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)
        mock_redis_handler.get_connection.return_value = mock_context

        handler.rate_limit_script_sha = "test_script_sha"

        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"

        def create_error_response(
            status_code: int, message: str
        ) -> DjangoGuardResponse:
            return DjangoGuardResponse(HttpResponse(message, status=status_code))

        guard_request = DjangoGuardRequest(request)
        result = handler.check_rate_limit(
            guard_request, "192.168.1.1", create_error_response
        )
        assert result is None

        mock_conn.evalsha.assert_called_once()

        mock_conn.evalsha.reset_mock()
        mock_conn.evalsha.return_value = 3

        result = handler.check_rate_limit(
            guard_request, "192.168.1.1", create_error_response
        )
        assert result is not None
        assert result.status_code == 429

    def test_fallback_to_pipeline(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url=REDIS_URL,
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_redis_middleware(config)
        handler = middleware.rate_limit_handler

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        handler.redis_handler = mock_redis_handler

        mock_conn = MagicMock()
        mock_pipeline = Mock()
        mock_pipeline.zadd = Mock()
        mock_pipeline.zremrangebyscore = Mock()
        mock_pipeline.zcard = Mock()
        mock_pipeline.expire = Mock()
        mock_pipeline.execute = Mock(
            side_effect=[
                [0, 0, 1, True],
                [0, 0, 3, True],
            ]
        )
        mock_conn.pipeline = Mock(return_value=mock_pipeline)

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)
        mock_redis_handler.get_connection.return_value = mock_context

        handler.rate_limit_script_sha = None

        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"

        def create_error_response(
            status_code: int, message: str
        ) -> DjangoGuardResponse:
            return DjangoGuardResponse(HttpResponse(message, status=status_code))

        guard_request = DjangoGuardRequest(request)
        result = handler.check_rate_limit(
            guard_request, "192.168.1.1", create_error_response
        )
        assert result is None

        mock_conn.pipeline.assert_called_once()
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()
        mock_pipeline.execute.assert_called_once()

        mock_conn.pipeline.reset_mock()
        mock_pipeline.zadd.reset_mock()
        mock_pipeline.zremrangebyscore.reset_mock()
        mock_pipeline.zcard.reset_mock()
        mock_pipeline.expire.reset_mock()
        mock_pipeline.execute.reset_mock()

        result = handler.check_rate_limit(
            guard_request, "192.168.1.1", create_error_response
        )
        assert result is not None
        assert result.status_code == 429
        assert result.body == b"Too many requests"

        mock_conn.pipeline.assert_called_once()
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()
        mock_pipeline.execute.assert_called_once()

    def test_rate_limiter_redis_errors(self) -> None:
        from redis.exceptions import RedisError

        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url=REDIS_URL,
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        handler = rate_limit_handler(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        handler.redis_handler = mock_redis_handler

        def create_error_response(
            status_code: int, message: str
        ) -> DjangoGuardResponse:
            return DjangoGuardResponse(HttpResponse(message, status=status_code))

        with (
            patch.object(mock_redis_handler, "get_connection") as mock_get_connection,
            patch.object(logging.Logger, "error") as mock_error,
        ):
            mock_conn = MagicMock()
            mock_conn.__enter__ = MagicMock(
                side_effect=RedisError("Redis connection error")
            )
            mock_get_connection.return_value = mock_conn

            handler.rate_limit_script_sha = "test_script_sha"

            factory = RequestFactory()
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.1"

            with pytest.raises(GuardRedisError):
                handler.check_rate_limit(
                    DjangoGuardRequest(request), "192.168.1.1", create_error_response
                )

            mock_error.assert_called_once()
            assert "Redis rate limiting error" in mock_error.call_args[0][0]

            mock_error.reset_mock()
            config.redis_fail_open = True

            result = handler.check_rate_limit(
                DjangoGuardRequest(request), "192.168.1.1", create_error_response
            )
            assert result is None
            mock_error.assert_not_called()

            config.redis_fail_open = False

        with (
            patch.object(mock_redis_handler, "get_connection") as mock_get_connection,
            patch.object(logging.Logger, "error") as mock_error,
        ):
            mock_conn = MagicMock()
            mock_conn.__enter__ = MagicMock(side_effect=Exception("Unexpected error"))
            mock_get_connection.return_value = mock_conn

            factory = RequestFactory()
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.1"

            with pytest.raises(GuardRedisError):
                handler.check_rate_limit(
                    DjangoGuardRequest(request), "192.168.1.1", create_error_response
                )

            mock_error.assert_called_once()
            assert "Unexpected error in rate limiting" in mock_error.call_args[0][0]

            mock_error.reset_mock()
            config.redis_fail_open = True

            result = handler.check_rate_limit(
                DjangoGuardRequest(request), "192.168.1.1", create_error_response
            )
            assert result is None
            mock_error.assert_not_called()

    def test_rate_limiter_init_redis_exception(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url=REDIS_URL,
        )
        handler = rate_limit_handler(config)

        mock_redis: Any = Mock()
        mock_cm = MagicMock()
        mock_conn = MagicMock()
        mock_conn.script_load = MagicMock(side_effect=Exception("Script load failed"))
        mock_cm.__enter__.return_value = mock_conn
        mock_cm.__exit__ = MagicMock(return_value=False)
        mock_redis.get_connection.return_value = mock_cm
        mock_redis.config = config

        mock_logger = Mock()
        handler.logger = mock_logger

        handler.initialize_redis(mock_redis)

        mock_logger.error.assert_called_once()
        error_msg = mock_logger.error.call_args[0][0]
        assert (
            "Failed to load rate limiting Lua script: Script load failed" == error_msg
        )

    def test_rate_limit_reset_with_redis_errors(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url=REDIS_URL,
            rate_limit=2,
            enable_rate_limiting=True,
        )

        RateLimitManager._instance = None
        handler = rate_limit_handler(config)

        mock_redis: Any = Mock()
        mock_redis.config = config

        def mock_keys(*args: Any) -> None:
            raise Exception("Redis keys error")

        mock_redis.keys = mock_keys

        handler.redis_handler = mock_redis

        with patch.object(logging.Logger, "error") as mock_logger:
            handler.reset()

            mock_logger.assert_called_once()
            args = mock_logger.call_args[0]
            assert "Failed to reset Redis rate limits" in args[0]

    def test_https_enforcement(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            enforce_https=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 301

    def test_excluded_paths_multiple(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            exclude_paths=["/health", "/status", "/metrics"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for path in ["/health", "/status", "/metrics"]:
            request = factory.get(path)
            response = middleware(request)
            assert response.status_code == 200


class TestDjangoAPIGuardCoverage:
    def _make_middleware(self, config: SecurityConfig | None = None) -> DjangoAPIGuard:
        if config is None:
            config = SecurityConfig(
                enable_redis=False, enable_penetration_detection=False
            )

        import django.conf

        django.conf.settings.GUARD_SECURITY_CONFIG = config

        def get_response(request: HttpRequest) -> HttpResponse:
            return HttpResponse("OK")

        return DjangoAPIGuard(get_response)

    def test_missing_config_is_rejected(self) -> None:
        import django.conf
        from django.core.exceptions import ImproperlyConfigured

        django.conf.settings.GUARD_SECURITY_CONFIG = None
        with pytest.raises(ImproperlyConfigured, match="GUARD_SECURITY_CONFIG"):
            DjangoAPIGuard(lambda _: HttpResponse("OK"))

    def test_guard_response_factory_property(self) -> None:
        from djangoapi_guard.adapters import DjangoResponseFactory

        middleware = self._make_middleware()
        assert isinstance(middleware.guard_response_factory, DjangoResponseFactory)

    def test_geo_ip_handler_init(self) -> None:
        from pathlib import Path

        from guard_core.protocols.geo_ip_protocol import GeoIPHandler
        from guard_core.sync.handlers.ipinfo_handler import IPInfoManager

        handler = IPInfoManager("fake", Path("/tmp/test.mmdb"))
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            blocked_countries=["CN"],
            geo_ip_handler=cast(GeoIPHandler, handler),
        )
        middleware = self._make_middleware(config)
        assert middleware.geo_ip_handler is not None

    def test_security_headers_not_configured(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            security_headers=None,
        )
        self._make_middleware(config)

    def test_security_headers_disabled(self) -> None:
        from guard_core.sync.handlers.security_headers_handler import (
            security_headers_manager,
        )

        security_headers_manager.reset()
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            security_headers={"enabled": False},
        )
        self._make_middleware(config)

    def test_assert_initialized_bypass_handler_none(self) -> None:
        middleware = self._make_middleware()
        middleware.bypass_handler = None
        with pytest.raises(RuntimeError, match="bypass_handler"):
            middleware._assert_initialized()

    def test_assert_initialized_route_resolver_none(self) -> None:
        middleware = self._make_middleware()
        middleware.route_resolver = None
        with pytest.raises(RuntimeError, match="route_resolver"):
            middleware._assert_initialized()

    def test_assert_initialized_behavioral_none(self) -> None:
        middleware = self._make_middleware()
        middleware.behavioral_processor = None
        with pytest.raises(RuntimeError, match="behavioral_processor"):
            middleware._assert_initialized()

    def test_assert_initialized_response_factory_none(self) -> None:
        middleware = self._make_middleware()
        middleware.response_factory = None
        with pytest.raises(RuntimeError, match="response_factory"):
            middleware._assert_initialized()

    def test_populate_guard_state_with_view_class(self) -> None:
        middleware = self._make_middleware()
        request = HttpRequest()
        request.path = "/test"
        request.META["SERVER_NAME"] = "localhost"
        request.META["SERVER_PORT"] = "80"

        mock_view = Mock()
        mock_view.view_class = Mock()
        mock_view.view_class._guard_route_id = "test_id"
        mock_view.view_class.__module__ = "test_module"
        mock_view.view_class.__qualname__ = "TestView"

        mock_match = Mock()
        mock_match.func = mock_view

        guard_request = DjangoGuardRequest(request)
        with patch("django.urls.resolve", return_value=mock_match):
            middleware._populate_guard_state(guard_request, request)
        assert cast(Any, request).guard_route_id == "test_id"
        assert cast(Any, request).guard_endpoint_id == "test_module.TestView"

    def test_populate_guard_state_marks_unresolvable_path(self) -> None:
        middleware = self._make_middleware()
        request = HttpRequest()
        request.path = "/no-such-path"
        request.META["SERVER_NAME"] = "localhost"
        request.META["SERVER_PORT"] = "80"

        guard_request = DjangoGuardRequest(request)
        middleware._populate_guard_state(guard_request, request)

        assert cast(Any, request).guard_route_unresolved is True

    def test_populate_guard_state_leaves_undecorated_view_resolved(self) -> None:
        middleware = self._make_middleware()
        request = HttpRequest()
        request.path = "/"
        request.META["SERVER_NAME"] = "localhost"
        request.META["SERVER_PORT"] = "80"

        guard_request = DjangoGuardRequest(request)
        middleware._populate_guard_state(guard_request, request)

        assert not hasattr(request, "guard_route_unresolved")
        assert not hasattr(request, "guard_route_id")

    def test_call_passthrough_response(self) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()
        request = factory.get("/")

        mock_resp = DjangoGuardResponse(HttpResponse("pass", status=200))
        with patch.object(
            middleware.bypass_handler,
            "handle_passthrough",
            return_value=mock_resp,
        ):
            response = middleware(request)
            assert response.content == b"pass"

    def test_call_bypass_response(self) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()
        request = factory.get("/")

        mock_resp = DjangoGuardResponse(HttpResponse("bypass", status=403))
        with (
            patch.object(
                middleware.bypass_handler,
                "handle_passthrough",
                return_value=None,
            ),
            patch.object(
                middleware.bypass_handler,
                "handle_security_bypass",
                return_value=mock_resp,
            ),
        ):
            response = middleware(request)
            assert response.status_code == 403

    def test_call_bypass_all_invokes_call_next(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)

        decorator = SecurityDecorator(config)
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "bypass_all_view"
        mock_func.__module__ = "test_module"
        decorated = decorator.bypass(["all"])(mock_func)
        route_id = cast(Any, decorated)._guard_route_id

        middleware.set_decorator_handler(decorator)

        factory = RequestFactory()
        request = factory.get("/")
        cast(Any, request).guard_route_id = route_id

        response = middleware(request)

        assert response.status_code == 200
        assert response.content == b"OK"

    def test_call_redis_unavailable_during_initialization_retries_next_request(
        self,
    ) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()

        with patch.object(
            middleware.handler_initializer,
            "initialize_redis_handlers",
            side_effect=[GuardRedisError(503, "Redis connection failed"), None],
        ) as mock_init:
            first_response = middleware(factory.get("/"))
            first_initialized = middleware._handlers_initialized
            assert first_response.status_code == 503
            assert first_response["Retry-After"] == "5"
            assert first_initialized is False

            second_response = middleware(factory.get("/"))
            second_initialized = middleware._handlers_initialized
            assert second_response.status_code == 200
            assert second_initialized is True
            assert mock_init.call_count == 2

    def test_call_pipeline_blocks(self) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()
        request = factory.get("/")

        with patch.object(
            middleware,
            "_execute_security_pipeline",
            return_value=HttpResponse("blocked", status=403),
        ):
            response = middleware(request)
            assert response.status_code == 403

    def test_agent_init_with_mock_module(self) -> None:
        mock_agent = MagicMock()
        mock_module = MagicMock()
        mock_module.guard_agent = MagicMock(return_value=mock_agent)
        mock_config = MagicMock()

        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_agent=True,
            agent_api_key="test-key-long-enough-for-validation",
        )
        with (
            patch.object(
                SecurityConfig,
                "to_agent_config",
                return_value=mock_config,
            ),
            patch.dict(sys.modules, {"guard_agent": mock_module}),
        ):
            middleware = self._make_middleware(config)
            middleware._initialize_handlers()
            assert middleware.handler_initializer is not None
            composite = middleware.handler_initializer.composite_handler
            assert composite is not None
            assert middleware.agent_handler is composite
            assert mock_agent in composite._handlers

    def test_agent_init_import_blocked(self) -> None:
        import builtins

        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_agent=True,
            agent_api_key="test-key-long-enough-for-validation",
        )
        fake_agent_config = config.to_agent_config()
        original_import = builtins.__import__
        saved_modules = {
            k: sys.modules.pop(k)
            for k in list(sys.modules)
            if k.startswith("guard_agent")
        }

        def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "guard_agent":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        try:
            with (
                patch.object(
                    SecurityConfig,
                    "to_agent_config",
                    return_value=fake_agent_config,
                ),
                patch(
                    "builtins.__import__",
                    side_effect=mock_import,
                ),
            ):
                middleware = self._make_middleware(config)
                assert middleware.agent_handler is None
        finally:
            sys.modules.update(saved_modules)

    def test_agent_init_runtime_error(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_agent=True,
            agent_api_key="test-key-long-enough-for-validation",
        )
        mock_module = MagicMock()
        mock_module.guard_agent = MagicMock(side_effect=RuntimeError("init failed"))
        mock_config = MagicMock()

        with (
            patch.object(
                SecurityConfig,
                "to_agent_config",
                return_value=mock_config,
            ),
            patch.dict(sys.modules, {"guard_agent": mock_module}),
        ):
            middleware = self._make_middleware(config)
            assert middleware.agent_handler is None

    def test_agent_init_config_returns_none(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_agent=True,
            agent_api_key="test-key-long-enough-for-validation",
        )
        with patch.object(SecurityConfig, "to_agent_config", return_value=None):
            middleware = self._make_middleware(config)
            assert middleware.agent_handler is None

    def test_process_response_method(self) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        response = HttpResponse("OK")

        result = middleware._process_response(request, response, 0.01, None)
        assert result.status_code == 200

    def test_refresh_cloud_ip_ranges(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            block_cloud_providers={"AWS"},
        )
        middleware = self._make_middleware(config)
        middleware.last_cloud_ip_refresh = 0
        with patch.object(cloud_handler, "refresh_async"):
            middleware.refresh_cloud_ip_ranges()
        assert middleware.last_cloud_ip_refresh > 0

    def test_create_error_response(self) -> None:
        middleware = self._make_middleware()
        result = middleware.create_error_response(403, "Forbidden")
        assert result.status_code == 403

    def test_adapter_scope(self) -> None:
        request = HttpRequest()
        request.META["SERVER_NAME"] = "localhost"
        guard_request = DjangoGuardRequest(request)
        assert "META" in guard_request.scope

    def test_adapter_url_replace_scheme_https(self) -> None:
        from djangoapi_guard.adapters import DjangoGuardRequest as DGR

        mock_request = MagicMock()
        mock_request.build_absolute_uri.return_value = "https://example.com/test"
        guard_request = DGR(mock_request)
        result = guard_request.url_replace_scheme("wss")
        assert result.startswith("wss://")

    def test_adapter_url_replace_scheme_unknown(self) -> None:
        from djangoapi_guard.adapters import DjangoGuardRequest as DGR

        mock_request = MagicMock()
        mock_request.build_absolute_uri.return_value = "ftp://example.com/test"
        guard_request = DGR(mock_request)
        result = guard_request.url_replace_scheme("wss")
        assert result == "ftp://example.com/test"

    def test_adapter_headers_contains(self) -> None:
        from djangoapi_guard.adapters import DjangoHeadersMapping

        mapping = DjangoHeadersMapping({"HTTP_HOST": "localhost"})
        assert 123 not in mapping
        assert "Host" in mapping
        assert "Missing" not in mapping

    def test_build_event_bus_handler_initializer_none(self) -> None:
        middleware = self._make_middleware()
        middleware.handler_initializer = None
        with pytest.raises(RuntimeError, match="handler_initializer"):
            middleware._build_event_bus_and_contexts()

    def test_build_event_bus_route_resolver_none(self) -> None:
        middleware = self._make_middleware()
        middleware.route_resolver = None
        with pytest.raises(RuntimeError, match="route_resolver"):
            middleware._build_event_bus_and_contexts()

    def test_process_behavioral_usage_none(self) -> None:
        middleware = self._make_middleware()
        middleware.behavioral_processor = None
        with pytest.raises(RuntimeError, match="behavioral_processor"):
            middleware._process_behavioral_usage(
                DjangoGuardRequest(HttpRequest()), "127.0.0.1", None
            )

    def test_finalize_response_factory_none(self) -> None:
        middleware = self._make_middleware()
        middleware.response_factory = None
        with pytest.raises(RuntimeError, match="response_factory"):
            middleware._finalize_response(HttpRequest(), HttpResponse(), None)

    def test_finalize_response_behavioral_none(self) -> None:
        middleware = self._make_middleware()
        middleware.behavioral_processor = None
        with pytest.raises(RuntimeError, match="behavioral_processor"):
            middleware._finalize_response(HttpRequest(), HttpResponse(), None)

    def test_initialize_handlers_none(self) -> None:
        middleware = self._make_middleware()
        middleware.handler_initializer = None
        with pytest.raises(RuntimeError, match="handler_initializer"):
            middleware._initialize_handlers()

    def test_build_preflight_response_cors_handler_none(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
            enable_cors=True,
            cors_allow_origins=["https://example.com"],
        )
        middleware = self._make_middleware(config)
        middleware._cors_handler = None
        with pytest.raises(AssertionError):
            middleware._build_preflight_response({"origin": "https://example.com"})

    def test_check_time_window_validator_none(self) -> None:
        middleware = self._make_middleware()
        middleware.validator = None
        with pytest.raises(RuntimeError, match="validator"):
            middleware._check_time_window({"start": "09:00", "end": "17:00"})

    def test_process_response_guards(self) -> None:
        middleware = self._make_middleware()
        req = HttpRequest()
        resp = HttpResponse()

        middleware.response_factory = None
        with pytest.raises(RuntimeError, match="response_factory"):
            middleware._process_response(req, resp, 0.01, None)

        middleware = self._make_middleware()
        middleware.behavioral_processor = None
        with pytest.raises(RuntimeError, match="behavioral_processor"):
            middleware._process_response(req, resp, 0.01, None)

    def test_decorator_usage_rules_guard(self) -> None:
        middleware = self._make_middleware()
        middleware.behavioral_processor = None
        with pytest.raises(RuntimeError, match="behavioral_processor"):
            middleware._process_decorator_usage_rules(
                HttpRequest(), "127.0.0.1", Mock()
            )

    def test_decorator_return_rules_guard(self) -> None:
        middleware = self._make_middleware()
        middleware.behavioral_processor = None
        with pytest.raises(RuntimeError, match="behavioral_processor"):
            middleware._process_decorator_return_rules(
                HttpRequest(), HttpResponse(), "127.0.0.1", Mock()
            )

    def test_get_endpoint_id_guard(self) -> None:
        middleware = self._make_middleware()
        middleware.behavioral_processor = None
        with pytest.raises(RuntimeError, match="behavioral_processor"):
            middleware._get_endpoint_id(HttpRequest())

    def test_create_error_response_guard(self) -> None:
        middleware = self._make_middleware()
        middleware.response_factory = None
        with pytest.raises(RuntimeError, match="response_factory"):
            middleware.create_error_response(403, "Forbidden")

    def test_behavioral_usage_with_rules(self) -> None:
        from guard_core.sync.decorators.base import RouteConfig

        middleware = self._make_middleware()
        route_config = RouteConfig()
        route_config.behavior_rules = [Mock()]

        guard_request = DjangoGuardRequest(HttpRequest())
        with patch.object(middleware.behavioral_processor, "process_usage_rules"):
            middleware._process_behavioral_usage(
                guard_request, "127.0.0.1", route_config
            )

    def test_adapter_headers_iter_and_len(self) -> None:
        from djangoapi_guard.adapters import DjangoHeadersMapping

        mapping = DjangoHeadersMapping(
            {"HTTP_HOST": "localhost", "HTTP_ACCEPT": "text/html"}
        )
        keys = list(mapping)
        assert len(keys) == 2
        assert len(mapping) == 2

    def test_agent_stats_returns_disabled_when_agent_handler_unset(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        assert middleware.agent_handler is None
        assert middleware.agent_stats == {"enabled": False}

    def test_agent_stats_returns_enabled_with_agent_handler_stats(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)

        fake_handler = MagicMock()
        fake_handler.get_stats.return_value = {
            "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
            "transport_stats": {"circuit_breaker_state": "CLOSED"},
        }
        middleware.agent_handler = fake_handler

        stats = middleware.agent_stats
        assert stats["enabled"] is True
        assert stats["buffer_stats"] == {"events_dropped": 0, "metrics_dropped": 0}
        assert stats["transport_stats"] == {"circuit_breaker_state": "CLOSED"}
        fake_handler.get_stats.assert_called_once()

    def test_agent_stats_reflects_live_drop_counter_increments(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)

        fake_handler = MagicMock()
        fake_handler.get_stats.return_value = {
            "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
            "transport_stats": {"circuit_breaker_state": "CLOSED"},
        }
        middleware.agent_handler = fake_handler

        first = middleware.agent_stats
        assert first["buffer_stats"]["events_dropped"] == 0

        fake_handler.get_stats.return_value = {
            "buffer_stats": {"events_dropped": 7, "metrics_dropped": 3},
            "transport_stats": {"circuit_breaker_state": "OPEN"},
        }

        second = middleware.agent_stats
        assert second["buffer_stats"]["events_dropped"] == 7
        assert second["buffer_stats"]["metrics_dropped"] == 3
        assert second["transport_stats"]["circuit_breaker_state"] == "OPEN"
        assert fake_handler.get_stats.call_count == 2
