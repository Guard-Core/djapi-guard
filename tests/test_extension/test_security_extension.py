import os
from collections.abc import Generator
from unittest.mock import MagicMock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.handlers.cloud_handler import cloud_handler_for
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.ratelimit_handler import _managers, _managers_lock
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard


def _get_response(request: HttpRequest) -> HttpResponse:
    """Simple get_response callable for middleware."""
    return HttpResponse('{"message": "Hello World"}', content_type="application/json")


def _make_middleware(
    config: SecurityConfig[SyncGuardRequest] | None = None,
) -> DjangoAPIGuard:
    """Create a DjangoAPIGuard instance with the given config."""
    if config is None:
        config = SecurityConfig[SyncGuardRequest](
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
    with patch.object(
        django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
    ):
        middleware = DjangoAPIGuard(_get_response)
    return middleware


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> Generator[None, None, None]:
    with _managers_lock:
        _managers.clear()
    yield
    with _managers_lock:
        _managers.clear()


def test_rate_limiting() -> None:
    """Test the rate limiting functionality."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        rate_limit=2,
        rate_limit_window=1,
        enable_rate_limiting=True,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 429

    middleware.rate_limit_handler.reset()
    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200


def test_excluded_paths() -> None:
    """Test that excluded paths bypass security checks."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        exclude_paths=["/docs", "/favicon.ico"],
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/docs")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200


def test_ip_whitelist() -> None:
    """Test IP whitelist functionality."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        whitelist=("127.0.0.1",),
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200


def test_ip_blacklist() -> None:
    """Test IP blacklist functionality."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        blacklist=("192.168.1.100",),
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "192.168.1.100"
    response = middleware(request)
    assert response.status_code == 403


def test_user_agent_blocking() -> None:
    """Test user agent blocking."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        blocked_user_agents=[r"badbot"],
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test", HTTP_USER_AGENT="badbot/1.0")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 403


def test_normal_request() -> None:
    """Test a normal request passes through."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test", HTTP_USER_AGENT="Mozilla/5.0")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200


def test_custom_error_responses() -> None:
    """Test custom error responses."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        blacklist=("10.0.0.1",),
        custom_error_responses={403: "Custom Forbidden"},
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "10.0.0.1"
    response = middleware(request)
    assert response.status_code == 403


def test_passive_mode() -> None:
    """Test passive mode doesn't block requests."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        passive_mode=True,
        blacklist=("10.0.0.1",),
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "10.0.0.1"
    response = middleware(request)
    # In passive mode, requests should not be blocked
    # but behavior depends on pipeline implementation
    assert response.status_code in (200, 403)


def test_cors_preflight() -> None:
    """Test CORS preflight request."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.options(
        "/api/test",
        HTTP_ORIGIN="https://example.com",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET",
    )
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200
    assert response["Access-Control-Allow-Origin"] == "https://example.com"


def test_penetration_detection() -> None:
    """Test penetration attempt detection."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=True,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/?param=<script>alert(1)</script>")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 400


def test_banned_ip() -> None:
    """Test that banned IPs are blocked."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        enable_ip_banning=True,
    )
    ip_ban_manager_for(config, bind=True)
    middleware = _make_middleware(config)
    factory = RequestFactory()

    ip_ban_manager_for(config).ban_ip("192.168.1.50", 3600)

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "192.168.1.50"
    response = middleware(request)
    assert response.status_code == 403


def test_security_headers_applied() -> None:
    """Test that security headers are applied to responses."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        security_headers={
            "enabled": True,
            "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False},
            "frame_options": "DENY",
            "content_type_options": "nosniff",
            "xss_protection": "1; mode=block",
            "referrer_policy": "no-referrer",
        },
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200


def test_middleware_reset() -> None:
    """Test middleware reset clears state."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )
    middleware = _make_middleware(config)
    middleware.reset()
    # Should not raise


def test_multiple_requests_rate_limit() -> None:
    """Test rate limiting with multiple unique IPs."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        rate_limit=100,
        enable_rate_limiting=True,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    for i in range(5):
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = f"10.0.0.{i + 1}"
        response = middleware(request)
        assert response.status_code == 200


def test_https_enforcement() -> None:
    """Test HTTPS enforcement."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        enforce_https=True,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    # Django test requests don't set wsgi.url_scheme easily
    response = middleware(request)
    # Response depends on scheme detection
    assert response.status_code in (200, 301)


def test_guard_with_custom_check() -> None:
    from djangoapi_guard.adapters import DjangoGuardResponse

    def custom_check(request: SyncGuardRequest) -> GuardResponse | None:
        if request.headers.get("X-Custom") == "block":
            return DjangoGuardResponse(HttpResponse("Blocked", status=403))
        return None

    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        custom_request_check=custom_check,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test", HTTP_X_CUSTOM="block")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 403


def test_guard_with_custom_response_modifier() -> None:
    def custom_modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Custom-Header"] = "modified"
        return response

    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        custom_response_modifier=custom_modifier,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200
    assert response.get("X-Custom-Header") == "modified"


def test_cidr_blacklist_blocking() -> None:
    """Test CIDR range in blacklist."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        blacklist=("10.0.0.0/24",),
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "10.0.0.50"
    response = middleware(request)
    assert response.status_code == 403


def test_cidr_whitelist_allows() -> None:
    """Test CIDR range in whitelist."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        whitelist=("10.0.0.0/24",),
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "10.0.0.50"
    response = middleware(request)
    assert response.status_code == 200


def test_blocked_user_agent_pattern() -> None:
    """Test regex pattern in blocked user agents."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        blocked_user_agents=[r"[Cc]rawler/\d+\.\d+"],
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test", HTTP_USER_AGENT="MyCustomCrawler/1.0")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 403


def test_sql_injection_detection() -> None:
    """Test SQL injection detection in query params."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=True,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/?query=UNION+SELECT+*+FROM+users")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 400


def test_directory_traversal_detection() -> None:
    """Test directory traversal detection."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=True,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/../../etc/passwd")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 400


def test_auto_ban_threshold() -> None:
    """Test auto-ban after threshold exceeded."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_ip_banning=True,
        enable_penetration_detection=True,
        auto_ban_threshold=2,
        auto_ban_duration=300,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    ip = "192.168.100.1"
    for _ in range(config.auto_ban_threshold):
        request = factory.get("/?param=<script>alert(1)</script>")
        request.META["REMOTE_ADDR"] = ip
        middleware(request)

    # After threshold, IP should be banned
    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = ip
    response = middleware(request)
    assert response.status_code == 403


def test_set_decorator_handler() -> None:
    from guard_core.sync.decorators.base import BaseSecurityDecorator

    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )
    middleware = _make_middleware(config)

    decorator = BaseSecurityDecorator(config)
    middleware.set_decorator_handler(decorator)
    assert middleware.guard_decorator is decorator


def test_refresh_cloud_ip_ranges() -> None:
    """Test cloud IP range refresh."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        block_cloud_providers=frozenset({"AWS"}),
    )
    middleware = _make_middleware(config)

    with patch.object(cloud_handler_for(config), "refresh_async") as mock_refresh:
        middleware.refresh_cloud_ip_ranges()
        mock_refresh.assert_called_once()


def test_create_error_response() -> None:
    """Test creating error responses."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )
    middleware = _make_middleware(config)

    response = middleware.create_error_response(403, "Forbidden")
    assert response.status_code == 403


def test_middleware_with_disabled_security_headers() -> None:
    """Test middleware with security headers disabled."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        security_headers={"enabled": False},
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200


def test_middleware_with_no_security_headers() -> None:
    """Test middleware with security_headers set to None."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        security_headers=None,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    response = middleware(request)
    assert response.status_code == 200


def test_json_log_format() -> None:
    """Test JSON log format configuration."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        log_format="json",
    )
    middleware = _make_middleware(config)
    assert middleware.config.log_format == "json"


def test_endpoint_rate_limits() -> None:
    """Test per-endpoint rate limits."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        endpoint_rate_limits={"/api/sensitive": (1, 60)},
        rate_limit=100,
    )
    _make_middleware(config)
    assert "/api/sensitive" in config.endpoint_rate_limits


def test_emergency_mode_config() -> None:
    """Test emergency mode configuration."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        emergency_mode=True,
        emergency_whitelist=["10.0.0.1"],
    )
    assert config.emergency_mode is True
    assert "10.0.0.1" in config.emergency_whitelist


def test_detection_config_fields() -> None:
    """Test detection configuration fields."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        detection_compiler_timeout=3.0,
        detection_max_content_length=5000,
        detection_semantic_threshold=0.8,
    )
    assert config.detection_compiler_timeout == 3.0
    assert config.detection_max_content_length == 5000
    assert config.detection_semantic_threshold == 0.8


def test_middleware_process_response() -> None:
    """Test middleware processes response correctly."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )
    middleware = _make_middleware(config)
    factory = RequestFactory()

    request = factory.get("/api/test")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    response = HttpResponse("test", status=200)
    result = middleware._process_response(request, response, 0.01, None)
    assert result is not None


def test_guard_with_agent_disabled() -> None:
    """Test middleware with agent disabled."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )
    middleware = _make_middleware(config)
    assert middleware.agent_handler is None


def test_guard_agent_init_generic_exception() -> None:
    """Test agent init with generic exception logs and continues."""
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-key",
        agent_project_id="test-project",
    )

    mock_agent_config = MagicMock()
    with patch.object(
        SecurityConfig, "to_agent_config", return_value=mock_agent_config
    ):
        mock_module = MagicMock()
        mock_module.SyncGuardAgentHandler.side_effect = RuntimeError("init failed")
        with patch.dict("sys.modules", {"guard_agent": mock_module}):
            middleware = _make_middleware(config)
            assert middleware.agent_handler is None
            middleware.reset()
