import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard


def _make_middleware(blacklist: list[str] | None = None) -> DjangoAPIGuard:
    config = SecurityConfig[SyncGuardRequest](
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        blacklist=tuple(blacklist or ()),
    )
    django.conf.settings.GUARD_SECURITY_CONFIG = config

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("ok")

    return DjangoAPIGuard(get_response)


def test_preflight_allowed_for_legitimate_origin() -> None:
    factory = RequestFactory()
    middleware = _make_middleware()
    request = factory.options(
        "/",
        HTTP_ORIGIN="https://app.example.com",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
    )
    response = middleware(request)
    assert response.status_code == 200
    assert response["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_preflight_blocked_for_banned_ip() -> None:
    factory = RequestFactory()
    middleware = _make_middleware(blacklist=["10.0.0.99"])
    request = factory.options(
        "/",
        HTTP_ORIGIN="https://app.example.com",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
    )
    request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.99"
    request.META["REMOTE_ADDR"] = "10.0.0.99"
    response = middleware(request)
    assert response.status_code == 403


def test_normal_request_carries_cors_headers() -> None:
    factory = RequestFactory()
    middleware = _make_middleware()
    request = factory.get(
        "/",
        HTTP_ORIGIN="https://app.example.com",
    )
    response = middleware(request)
    assert response.status_code == 200
    assert response["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert response["Access-Control-Allow-Credentials"] == "true"


def test_preflight_disallowed_origin_returns_400() -> None:
    factory = RequestFactory()
    middleware = _make_middleware()
    request = factory.options(
        "/",
        HTTP_ORIGIN="https://evil.example.com",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
    )
    response = middleware(request)
    assert response.status_code == 400


def test_options_without_acr_method_is_not_preflight() -> None:
    factory = RequestFactory()
    middleware = _make_middleware()
    request = factory.options(
        "/",
        HTTP_ORIGIN="https://app.example.com",
    )
    response = middleware(request)
    assert response.status_code == 200


def test_blocked_response_carries_cors_headers() -> None:
    factory = RequestFactory()
    middleware = _make_middleware(blacklist=["10.0.0.1"])
    request = factory.get(
        "/",
        HTTP_ORIGIN="https://app.example.com",
    )
    request.META["REMOTE_ADDR"] = "10.0.0.1"
    response = middleware(request)
    assert response.status_code == 403
    assert response["Access-Control-Allow-Origin"] == "https://app.example.com"


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH"])
def test_cors_headers_on_regular_methods(method: str) -> None:
    factory = RequestFactory()
    middleware = _make_middleware()
    request_func = getattr(factory, method.lower())
    request = request_func(
        "/",
        HTTP_ORIGIN="https://app.example.com",
    )
    response = middleware(request)
    assert "Access-Control-Allow-Origin" in response


def _make_passthrough_middleware() -> DjangoAPIGuard:
    config = SecurityConfig[SyncGuardRequest](
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        exclude_paths=["/health"],
    )
    django.conf.settings.GUARD_SECURITY_CONFIG = config

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("ok")

    return DjangoAPIGuard(get_response)


def test_preflight_to_passthrough_path_returns_cors_response() -> None:
    factory = RequestFactory()
    middleware = _make_passthrough_middleware()
    request = factory.options(
        "/health",
        HTTP_ORIGIN="https://app.example.com",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET",
    )
    response = middleware(request)
    assert response.status_code == 200
    assert response["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_normal_request_to_passthrough_path_carries_cors_headers() -> None:
    factory = RequestFactory()
    middleware = _make_passthrough_middleware()
    request = factory.get(
        "/health",
        HTTP_ORIGIN="https://app.example.com",
    )
    response = middleware(request)
    assert response.status_code == 200
    assert response["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert response["Access-Control-Allow-Credentials"] == "true"
