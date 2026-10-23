"""The response wrapper declares whether the body is in memory, and tees a stream.

The sync engine reads ``body_is_materialized`` once per response
(``ErrorResponseFactory.apply_modifier``): True hands the modifier the real
response, anything else takes the bounded path, reading the prefix lazily on the
first ``.body`` access.
"""

import hashlib
import io
import logging
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from django.http import (
    FileResponse,
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
    StreamingHttpResponse,
)
from django.http.response import HttpResponseBase
from django.test import RequestFactory, override_settings
from guard_core.models import SecurityConfig
from guard_core.sync.core.responses import reads_response_body
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory

from djangoapi_guard.adapters import DjangoGuardRequest, DjangoGuardResponse
from djangoapi_guard.middleware import DjangoAPIGuard
from tests import engine_parity_urls

_BODY = bytes(range(256)) * 40
_CAP = 262144


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Pulled:
    def __init__(self) -> None:
        self.chunks = 0


def _counting_stream(chunks: list[bytes], pulled: _Pulled) -> Iterator[bytes]:
    for chunk in chunks:
        pulled.chunks += 1
        yield chunk


def _split(body: bytes, size: int) -> list[bytes]:
    return [body[i : i + size] for i in range(0, len(body), size)]


def _drain(native: HttpResponseBase) -> bytes:
    if isinstance(native, StreamingHttpResponse):
        return native.getvalue()
    assert isinstance(native, HttpResponse)
    return native.content


async def _async_chunks(pulled: _Pulled) -> AsyncIterator[bytes]:
    pulled.chunks += 1
    yield b"a"


_MATERIALIZED = {
    "HttpResponse": True,
    "JsonResponse": True,
    "HttpResponseRedirect": True,
    "StreamingHttpResponse": False,
    "FileResponse": False,
    "async StreamingHttpResponse": False,
}


def _native(name: str) -> HttpResponseBase:
    return {
        "HttpResponse": lambda: HttpResponse(_BODY),
        "JsonResponse": lambda: JsonResponse({"a": 1}),
        "HttpResponseRedirect": lambda: HttpResponseRedirect("/elsewhere"),
        "StreamingHttpResponse": lambda: StreamingHttpResponse(iter([b"a"])),
        "FileResponse": lambda: FileResponse(io.BytesIO(_BODY)),
        "async StreamingHttpResponse": lambda: StreamingHttpResponse(
            _async_chunks(_Pulled())
        ),
    }[name]()


@pytest.mark.parametrize("name", sorted(_MATERIALIZED))
def test_the_capability_matches_the_native_response_type(name: str) -> None:
    native = _native(name)
    assert DjangoGuardResponse(native).body_is_materialized is _MATERIALIZED[name]
    native.close()


def test_a_response_class_outside_http_response_is_not_assumed_materialized() -> None:
    assert DjangoGuardResponse(HttpResponseBase()).body_is_materialized is False


def test_reading_the_capability_pulls_no_chunk() -> None:
    pulled = _Pulled()
    native = StreamingHttpResponse(_counting_stream([b"a", b"b"], pulled))
    wrapper = DjangoGuardResponse(native)
    assert wrapper.body_is_materialized is False
    assert wrapper.body_is_materialized is False
    assert pulled.chunks == 0


class _Seen:
    def __init__(self) -> None:
        self.calls = 0
        self.body: bytes | None = None
        self.refused = False


def _modifier(seen: _Seen, marked: bool = False) -> Any:
    def modifier(response: Any) -> Any:
        seen.calls += 1
        try:
            seen.body = response.body
        except AttributeError:
            seen.refused = True
        response.headers["x-modified"] = "1"
        return response

    return reads_response_body(modifier) if marked else modifier


def _engine(modifier: Any, **overrides: Any) -> ErrorResponseFactory:
    config = SecurityConfig(enable_redis=False, **overrides)
    config.custom_response_modifier = modifier
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("djangoapi_guard.test_response_body_capability"),
            metrics_collector=MagicMock(),
            response_factory=None,
        )
    )


def _apply(modifier: Any, native: HttpResponseBase, **overrides: Any) -> None:
    request = DjangoGuardRequest(RequestFactory().get("/"))
    _engine(modifier, **overrides).apply_modifier(DjangoGuardResponse(native), request)


def test_a_modifier_on_an_in_memory_response_gets_the_real_bytes_in_one_call() -> None:
    seen = _Seen()
    big = _BODY * 30
    assert len(big) > _CAP
    native = HttpResponse(big)
    _apply(_modifier(seen), native)
    assert seen.calls == 1
    assert seen.body == big
    assert native.headers["x-modified"] == "1"


def test_a_modifier_on_a_declared_stream_under_the_cap_gets_every_byte() -> None:
    seen = _Seen()
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = StreamingHttpResponse(
        _counting_stream(chunks, pulled), headers={"Content-Length": str(len(_BODY))}
    )
    _apply(_modifier(seen), native)
    assert seen.calls == 1
    assert seen.body == _BODY
    assert pulled.chunks == len(chunks)
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_an_undeclared_stream_is_refused_and_nothing_is_lost() -> None:
    seen = _Seen()
    pulled = _Pulled()
    native = StreamingHttpResponse(_counting_stream(_split(_BODY, 1000), pulled))
    _apply(_modifier(seen), native)
    assert seen.refused
    assert seen.calls == 1
    assert native.headers["x-modified"] == "1"
    assert pulled.chunks == 0
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_a_declared_stream_over_the_cap_reads_one_chunk_at_most() -> None:
    seen = _Seen()
    pulled = _Pulled()
    native = StreamingHttpResponse(
        _counting_stream(_split(_BODY, 1000), pulled),
        headers={"Content-Length": str(len(_BODY))},
    )
    _apply(_modifier(seen), native, custom_response_modifier_max_body_bytes=2048)
    assert seen.refused
    assert pulled.chunks <= 1
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_server_sent_events_is_refused_and_nothing_is_lost() -> None:
    seen = _Seen()
    pulled = _Pulled()
    native = StreamingHttpResponse(
        _counting_stream(_split(_BODY, 1000), pulled),
        content_type="text/event-stream",
        headers={"Content-Length": str(len(_BODY))},
    )
    _apply(_modifier(seen), native)
    assert seen.refused
    assert pulled.chunks == 0
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_a_file_response_reads_the_file_and_the_client_gets_it_all() -> (
    None
):
    seen = _Seen()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "file.bin"
        path.write_bytes(_BODY)
        native = FileResponse(path.open("rb"))
        try:
            assert DjangoGuardResponse(native).body_is_materialized is False
            _apply(_modifier(seen), native)
            assert seen.body == _BODY
            assert _sha(_drain(native)) == _sha(_BODY)
        finally:
            native.close()


def test_an_async_stream_is_never_consumed_and_a_modifier_is_refused() -> None:
    seen = _Seen()
    pulled = _Pulled()
    native = StreamingHttpResponse(
        _async_chunks(pulled), headers={"Content-Length": "1"}
    )
    _apply(_modifier(seen), native)
    assert seen.refused
    assert pulled.chunks == 0
    assert native.streaming


def test_read_body_prefix_reads_a_declared_length_to_its_end_and_replays_it() -> None:
    native = StreamingHttpResponse(
        _counting_stream(_split(_BODY, 700), _Pulled()),
        headers={"Content-Length": str(len(_BODY))},
    )
    assert DjangoGuardResponse(native).read_body_prefix(_CAP) == _BODY
    assert _sha(_drain(native)) == _sha(_BODY)


def test_read_body_prefix_stops_at_the_declared_length_not_the_stream_end() -> None:
    pulled = _Pulled()
    native = StreamingHttpResponse(
        _counting_stream(_split(_BODY, 1000), pulled),
        headers={"Content-Length": "2500"},
    )
    assert DjangoGuardResponse(native).read_body_prefix(_CAP) == _BODY[:3000]
    assert pulled.chunks == 3
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_later_longer_read_continues_the_same_tee() -> None:
    pulled = _Pulled()
    native = StreamingHttpResponse(
        _counting_stream(_split(_BODY, 1000), pulled),
        headers={"Content-Length": "2500"},
    )
    wrapper = DjangoGuardResponse(native)
    assert wrapper.read_body_prefix(1500) == _BODY[:1000]
    assert pulled.chunks == 1
    assert wrapper.read_body_prefix(_CAP) == _BODY[:3000]
    assert pulled.chunks == 3
    assert wrapper.read_body_prefix(_CAP) == _BODY[:3000]
    assert pulled.chunks == 3
    assert _sha(_drain(native)) == _sha(_BODY)


@pytest.mark.parametrize(
    "headers",
    [{}, {"Content-Length": "abc"}, {"Content-Length": "999999"}],
)
def test_read_body_prefix_stops_at_the_first_chunk_without_a_usable_length(
    headers: dict[str, str],
) -> None:
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = StreamingHttpResponse(_counting_stream(chunks, pulled), headers=headers)
    assert DjangoGuardResponse(native).read_body_prefix(1500) == chunks[0]
    assert pulled.chunks == 1
    assert _sha(_drain(native)) == _sha(_BODY)


def test_read_body_prefix_returns_what_a_short_declared_stream_produced() -> None:
    native = StreamingHttpResponse(
        _counting_stream([b"ab"], _Pulled()), headers={"Content-Length": "50"}
    )
    assert DjangoGuardResponse(native).read_body_prefix(_CAP) == b"ab"
    assert _drain(native) == b"ab"


def test_read_body_prefix_of_a_response_class_outside_http_response_is_empty() -> None:
    assert DjangoGuardResponse(HttpResponseBase()).read_body_prefix(10) == b""


@pytest.fixture(autouse=True)
def _urlconf() -> Iterator[None]:
    with override_settings(ROOT_URLCONF="tests.engine_parity_urls", MIDDLEWARE=[]):
        yield


def _guard(route: str, path: Path, seen: _Seen) -> DjangoAPIGuard:
    def view(request: HttpRequest) -> HttpResponseBase:
        if route == "memory":
            return HttpResponse(_BODY)
        if route == "stream-declared":
            return StreamingHttpResponse(
                _counting_stream(_split(_BODY, 900), _Pulled()),
                headers={"Content-Length": str(len(_BODY))},
            )
        if route == "stream-undeclared":
            return StreamingHttpResponse(
                _counting_stream(_split(_BODY, 900), _Pulled())
            )
        if route == "sse":
            return StreamingHttpResponse(
                _counting_stream(_split(_BODY, 900), _Pulled()),
                content_type="text/event-stream",
                headers={"Content-Length": str(len(_BODY))},
            )
        return FileResponse(path.open("rb"))

    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        whitelist=None,
        blacklist=(),
        custom_response_modifier=_modifier(seen),
    )
    with override_settings(GUARD_SECURITY_CONFIG=config):
        guard = DjangoAPIGuard(view)
    guard.set_decorator_handler(engine_parity_urls.security)
    return guard


@pytest.mark.parametrize(
    ("route", "readable"),
    [
        ("memory", True),
        ("stream-declared", True),
        ("stream-undeclared", False),
        ("sse", False),
        ("file", True),
    ],
)
def test_through_the_middleware_the_client_gets_every_byte(
    route: str, readable: bool
) -> None:
    seen = _Seen()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "file.bin"
        path.write_bytes(_BODY)
        request = RequestFactory().get("/open/")
        request.META["REMOTE_ADDR"] = "203.0.113.9"
        response = _guard(route, path, seen)(request)
        content = _drain(response)
        response.close()
    assert response.status_code == 200
    assert response.headers["x-modified"] == "1"
    assert _sha(content) == _sha(_BODY)
    assert seen.calls == 1
    assert seen.refused is not readable
    assert (seen.body == _BODY) is readable
