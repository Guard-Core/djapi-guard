import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from typing import Any

from django.http import HttpResponse
from django.test import RequestFactory

from djangoapi_guard.adapters import (
    DjangoGuardRequest,
    DjangoGuardResponse,
    DjangoHeadersMapping,
    DjangoResponseFactory,
    unwrap_response,
)


def test_django_guard_request_url_path() -> None:
    factory = RequestFactory()
    request = factory.get("/test")
    guard_request = DjangoGuardRequest(request)
    assert guard_request.url_path == "/test"


def test_django_guard_request_method() -> None:
    factory = RequestFactory()
    request = factory.post("/")
    guard_request = DjangoGuardRequest(request)
    assert guard_request.method == "POST"


def test_django_guard_request_client_host() -> None:
    factory = RequestFactory()
    request = factory.get("/", REMOTE_ADDR="10.0.0.1")
    guard_request = DjangoGuardRequest(request)
    assert guard_request.client_host == "10.0.0.1"


def test_django_guard_request_headers() -> None:
    factory = RequestFactory()
    request = factory.get("/", HTTP_X_CUSTOM="value")
    guard_request = DjangoGuardRequest(request)
    assert guard_request.headers.get("X-Custom") == "value"


def test_django_guard_request_query_params() -> None:
    factory = RequestFactory()
    request = factory.get("/?key=val")
    guard_request = DjangoGuardRequest(request)
    assert guard_request.query_params.get("key") == "val"


def test_django_guard_request_scheme() -> None:
    factory = RequestFactory()
    request = factory.get("/", secure=True)
    guard_request = DjangoGuardRequest(request)
    assert guard_request.url_scheme == "https"


def test_django_guard_request_body() -> None:
    factory = RequestFactory()
    request = factory.post("/", data=b"hello", content_type="application/octet-stream")
    guard_request = DjangoGuardRequest(request)
    assert guard_request.body() == b"hello"


def test_django_guard_request_read_body_prefix() -> None:
    factory = RequestFactory()
    request = factory.post(
        "/", data=b"hello world", content_type="application/octet-stream"
    )
    guard_request = DjangoGuardRequest(request)
    assert guard_request.read_body_prefix(5) == b"hello"
    assert guard_request.read_body_prefix(0) == b""
    assert guard_request.read_body_prefix(-1) == b""


def test_django_guard_request_read_body_prefix_full() -> None:
    factory = RequestFactory()
    request = factory.post("/", data=b"abc", content_type="application/octet-stream")
    guard_request = DjangoGuardRequest(request)
    assert guard_request.read_body_prefix(100) == b"abc"


def test_django_guard_response_properties() -> None:
    response = HttpResponse("test", status=200)
    guard_response = DjangoGuardResponse(response)
    assert guard_response.status_code == 200
    assert guard_response.body == b"test"


def test_django_guard_response_read_body_prefix() -> None:
    response = HttpResponse("hello world", status=200)
    guard_response = DjangoGuardResponse(response)
    assert guard_response.read_body_prefix(5) == b"hello"
    assert guard_response.read_body_prefix(0) == b""
    assert guard_response.read_body_prefix(-1) == b""


def test_django_guard_response_read_body_prefix_full() -> None:
    response = HttpResponse("abc", status=200)
    guard_response = DjangoGuardResponse(response)
    assert guard_response.read_body_prefix(100) == b"abc"


def test_django_guard_response_read_body_prefix_streaming() -> None:
    from django.http import StreamingHttpResponse

    def gen() -> Any:
        yield b"chunk"

    response = StreamingHttpResponse(gen(), status=200)
    guard_response = DjangoGuardResponse(response)
    assert guard_response.read_body_prefix(10) == b""


def test_django_headers_mapping() -> None:
    meta = {
        "HTTP_X_CUSTOM": "value",
        "CONTENT_TYPE": "text/plain",
        "SERVER_NAME": "localhost",
    }
    mapping = DjangoHeadersMapping(meta)
    assert mapping.get("X-Custom") == "value"
    assert mapping.get("Content-Type") == "text/plain"
    assert len(mapping) == 2
    assert "X-Custom" in list(mapping)


def test_django_response_factory_create() -> None:
    factory = DjangoResponseFactory()
    guard_resp = factory.create_response("error", 403)
    assert guard_resp.status_code == 403
    assert guard_resp.headers["Content-Type"] == "text/plain; charset=utf-8"


def test_django_response_factory_redirect() -> None:
    factory = DjangoResponseFactory()
    guard_resp = factory.create_redirect_response("https://example.com", 301)
    assert guard_resp.status_code == 301


def test_unwrap_response_django() -> None:
    response = HttpResponse("test", status=200)
    guard_response = DjangoGuardResponse(response)
    unwrapped = unwrap_response(guard_response)
    assert unwrapped is response


def test_unwrap_response_generic() -> None:
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.body = b"body"
    mock_resp.status_code = 404
    mock_resp.headers = {"X-Test": "val"}
    unwrapped = unwrap_response(mock_resp)
    assert unwrapped.status_code == 404
