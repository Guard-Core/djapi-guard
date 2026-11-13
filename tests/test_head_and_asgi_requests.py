import io
from collections.abc import Callable
from typing import Any

from django.core.handlers.asgi import ASGIRequest
from django.http import HttpRequest, HttpResponse
from django.test import override_settings
from django.urls import path

from djangoapi_guard.middleware import DjangoAPIGuard
from tests.wsgi_sweep_support import config, served


def index(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


def test_head_is_guarded_and_answers_without_a_body() -> None:
    with served([path("", index)], config(blacklist=["203.0.113.9"])) as client:
        allowed = client.head("/", REMOTE_ADDR="198.51.100.4")
        blocked = client.head("/", REMOTE_ADDR="203.0.113.9")

    assert (allowed.status_code, bytes(allowed.content)) == (200, b"")
    assert (blocked.status_code, bytes(blocked.content)) == (403, b"")


def _asgi_request(client: str, body: bytes) -> ASGIRequest:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [
            (b"content-type", b"text/plain"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": (client, 5000),
        "server": ("testserver", 80),
        "scheme": "http",
        "http_version": "1.1",
        "root_path": "",
    }
    return ASGIRequest(scope, io.BytesIO(body))


def _guard(
    get_response: Callable[[HttpRequest], HttpResponse] | None = None,
    **fields: Any,
) -> DjangoAPIGuard:
    with override_settings(GUARD_SECURITY_CONFIG=config(**fields)):
        return DjangoAPIGuard(get_response or (lambda request: HttpResponse("ok")))


def test_an_asgi_request_from_a_blacklisted_client_is_refused() -> None:
    guard = _guard(blacklist=["203.0.113.9"])

    assert guard(_asgi_request("203.0.113.9", b"hello")).status_code == 403
    assert guard(_asgi_request("198.51.100.4", b"hello")).status_code == 200


def test_an_asgi_request_body_is_scanned_and_stays_readable() -> None:
    payload = b"<script>alert(1)</script>"
    seen: list[bytes] = []

    def view(request: HttpRequest) -> HttpResponse:
        seen.append(request.body)
        return HttpResponse("ok")

    clean = b"just text"
    guard = _guard(view, enable_penetration_detection=True)
    attack = guard(_asgi_request("198.51.100.4", payload))
    passed = guard(_asgi_request("198.51.100.4", clean))

    assert attack.status_code == 400
    assert (passed.status_code, seen) == (200, [clean])
