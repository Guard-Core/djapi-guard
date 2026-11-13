import io
from collections.abc import Callable

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from django.urls import path

from djangoapi_guard.adapters import DjangoGuardRequest
from tests.wsgi_sweep_support import config, served

PEER = "203.0.113.9"


def index(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


def who(request: HttpRequest) -> HttpResponse:
    return HttpResponse(str(request.__dict__.get("client_ip")))


class ForeignClientIp:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request.__dict__["client_ip"] = "198.51.100.1"
        return self.get_response(request)


_ORDER = (
    "tests.test_guard_state_is_owned.ForeignClientIp",
    "djangoapi_guard.middleware.DjangoAPIGuard",
)


def test_a_client_ip_another_middleware_set_does_not_replace_the_resolved_one() -> None:
    with served(
        [path("", index)], config(blacklist=["203.0.113.9"]), middleware=_ORDER
    ) as client:
        assert client.get("/", REMOTE_ADDR=PEER).status_code == 403


def test_what_the_guard_records_on_the_state_is_mirrored_on_the_request() -> None:
    request = RequestFactory().get("/")

    DjangoGuardRequest(request).state.guard_route_template = "/x"

    assert request.__dict__["guard_route_template"] == "/x"
    assert DjangoGuardRequest(request).state.guard_route_template == "/x"


def test_a_value_set_only_on_the_request_is_not_on_the_state() -> None:
    request = RequestFactory().get("/")
    request.__dict__["client_ip"] = "198.51.100.1"

    assert getattr(DjangoGuardRequest(request).state, "client_ip", None) is None


def test_read_body_prefix_does_not_read_past_the_prefix() -> None:
    class Counting(io.BytesIO):
        delivered = 0

        def read(self, size: int | None = -1) -> bytes:
            chunk = super().read(size)
            self.delivered += len(chunk)
            return chunk

    stream = Counting(b"x" * 1_000_000)
    request = RequestFactory().post("/", data=b"", content_type="text/plain")
    request.META["CONTENT_LENGTH"] = "1000000"
    request.__dict__["_stream"] = stream
    request.__dict__.pop("_body", None)

    prefix = DjangoGuardRequest(request).read_body_prefix(10)

    assert prefix == b"x" * 10
    assert stream.delivered <= 65536


def test_the_body_is_whole_for_the_view_after_a_prefix_read() -> None:
    body = bytes(range(256)) * 400
    request = RequestFactory().post("/", data=body, content_type="text/plain")
    request.__dict__["_stream"] = io.BytesIO(body)
    request.__dict__.pop("_body", None)
    request.META["CONTENT_LENGTH"] = str(len(body))

    DjangoGuardRequest(request).read_body_prefix(10)

    assert request.body == body


def test_a_state_value_can_be_deleted_from_the_state_and_the_request() -> None:
    request = RequestFactory().get("/")
    state = DjangoGuardRequest(request).state
    state.guard_route_id = "x"

    del state.guard_route_id

    assert getattr(state, "guard_route_id", None) is None
    assert "guard_route_id" not in request.__dict__
    with pytest.raises(AttributeError):
        del state.guard_route_id
