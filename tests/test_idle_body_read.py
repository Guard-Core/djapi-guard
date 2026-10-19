import io
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest
from django.core.handlers.wsgi import WSGIHandler
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from guard_core.exceptions import BodyReadStalledError
from guard_core.models import SecurityConfig

from djangoapi_guard.adapters import DjangoGuardRequest
from djangoapi_guard.middleware import DjangoAPIGuard


class _DrippingInput(io.RawIOBase):
    def __init__(self, chunks: list[bytes], then: BaseException | None = None) -> None:
        self._chunks = list(chunks)
        self._then = then

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if self._chunks:
            chunk = self._chunks.pop(0)[: len(buffer)]
            buffer[: len(chunk)] = chunk
            return len(chunk)
        if self._then is not None:
            raise self._then
        return 0


class _FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float | None] = [None]

    def gettimeout(self) -> float | None:
        return self.timeouts[-1]

    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)


def _post(body: bytes, **extra: Any) -> Any:
    return RequestFactory().post("/echo", data=body, content_type="text/plain", **extra)


def _streamed(stream: Any, length: int, **extra: Any) -> Any:
    request = RequestFactory().generic(
        "POST", "/echo", data=b"", content_type="text/plain", **extra
    )
    request.META["CONTENT_LENGTH"] = str(length)
    request.META["wsgi.input"] = stream
    request._stream = type(request._stream)(stream, length)
    return request


def test_the_idle_read_returns_the_prefix_and_the_app_still_reads_everything() -> None:
    request = _post(b"hello world")

    assert DjangoGuardRequest(request).read_body_prefix_until_idle(5, 1.0) == b"hello"
    assert request.body == b"hello world"


def test_the_idle_read_of_a_short_body_returns_all_of_it() -> None:
    request = _post(b"tiny")
    guard_request = DjangoGuardRequest(request)

    assert guard_request.read_body_prefix_until_idle(1024, 1.0) == b"tiny"
    assert guard_request.read_body_prefix_until_idle(0, 1.0) == b""
    assert request.body == b"tiny"


def test_the_replayed_stream_serves_the_form_parser() -> None:
    request = RequestFactory().post("/echo", data={"a": "1", "b": "two"})

    DjangoGuardRequest(request).read_body_prefix_until_idle(4, 1.0)

    assert request.POST["a"] == "1"
    assert request.POST["b"] == "two"


def test_a_cached_body_is_answered_from_the_cache() -> None:
    request = _post(b"hello world")
    assert request.body == b"hello world"

    assert DjangoGuardRequest(request).read_body_prefix_until_idle(5, 1.0) == b"hello"


def test_the_replayed_stream_serves_lines_and_boundary_reads() -> None:
    request = _post(b"a\nbb\nccc")
    DjangoGuardRequest(request).read_body_prefix_until_idle(3, 1.0)

    stream = request._stream
    assert stream.readline() == b"a\n"
    assert stream.read(1) == b"b"
    assert list(stream) == [b"b\n", b"ccc"]


def test_the_replayed_read_larger_than_the_prefix_continues_into_the_stream() -> None:
    request = _post(b"abcdefgh")
    DjangoGuardRequest(request).read_body_prefix_until_idle(3, 1.0)

    assert request._stream.read(5) == b"abcde"
    assert request._stream.read() == b"fgh"
    assert request._stream.read(2) == b""


def test_a_replayed_read_smaller_than_the_prefix_stays_inside_the_prefix() -> None:
    request = _post(b"abcdef")
    DjangoGuardRequest(request).read_body_prefix_until_idle(4, 1.0)

    assert request._stream.read(2) == b"ab"
    assert request._stream.read() == b"cdef"


def test_a_size_limited_replayed_line_stops_at_the_limit() -> None:
    request = _post(b"abcdef\nghi")
    DjangoGuardRequest(request).read_body_prefix_until_idle(3, 1.0)

    assert request._stream.readline(2) == b"ab"
    assert request._stream.readline(4) == b"cdef"
    assert request._stream.readline(None) == b"\n"
    assert request._stream.read(None) == b"ghi"


def test_the_servers_socket_timeout_is_a_stalled_read_and_no_byte_is_lost() -> None:
    stream = _DrippingInput([b"abc"], then=TimeoutError("timed out"))
    request = _streamed(stream, 10)

    with pytest.raises(BodyReadStalledError):
        DjangoGuardRequest(request).read_body_prefix_until_idle(1024, 1.0)

    assert request._stream.read(3) == b"abc"


def test_a_client_that_disconnects_is_not_reported_as_a_stall() -> None:
    stream = _DrippingInput([], then=ConnectionResetError("reset by peer"))
    request = _streamed(stream, 10)

    with pytest.raises(Exception) as error:
        DjangoGuardRequest(request).read_body_prefix_until_idle(5, 1.0)

    assert not isinstance(error.value, BodyReadStalledError)


def test_the_server_socket_gets_the_idle_timeout_for_the_read_and_gets_it_back() -> (
    None
):
    fake = _FakeSocket()
    request = _post(b"hello", **{"gunicorn.socket": fake})

    DjangoGuardRequest(request).read_body_prefix_until_idle(5, 0.25)

    assert fake.timeouts == [None, 0.25, None]


def test_the_server_socket_is_restored_when_the_read_stalls() -> None:
    fake = _FakeSocket()
    request = _streamed(
        _DrippingInput([], then=TimeoutError("timed out")),
        4,
        **{"werkzeug.socket": fake},
    )

    with pytest.raises(BodyReadStalledError):
        DjangoGuardRequest(request).read_body_prefix_until_idle(5, 0.25)

    assert fake.timeouts == [None, 0.25, None]


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": True,
        "enable_rate_limiting": False,
        "fail_secure": True,
        "body_read_timeout": 0.3,
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


class _TimingOutHandler(WSGIRequestHandler):
    timeout = 0.3

    def log_message(self, format: str, *args: Any) -> None:
        return None


@contextmanager
def _serve(config: SecurityConfig) -> Iterator[int]:
    with override_settings(
        ROOT_URLCONF="tests.urls_idle_body", GUARD_SECURITY_CONFIG=config
    ):
        server: WSGIServer = make_server(
            "127.0.0.1", 0, WSGIHandler(), handler_class=_TimingOutHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield int(server.server_port)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)


def _raw_post(
    port: int, chunks: list[tuple[float, bytes]], declared: int = 0
) -> tuple[int, float]:
    body_length = declared or sum(len(chunk) for _, chunk in chunks)
    head = (
        "POST /echo HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {body_length}\r\nConnection: close\r\n\r\n"
    ).encode()
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(head)
        for pause, chunk in chunks:
            time.sleep(pause)
            try:
                sock.sendall(chunk)
            except OSError:
                break
        data = b""
        while b"\r\n" not in data:
            piece = sock.recv(4096)
            if not piece:
                break
            data += piece
    return int(data.split(b" ", 2)[1]), time.monotonic() - started


def test_wsgiref_server_the_servers_own_socket_timeout_gets_408() -> None:
    with _serve(_config(body_read_timeout=30.0)) as port:
        status, elapsed = _raw_post(port, [], declared=10)

    assert status == 408
    assert elapsed < 2.0


def test_wsgiref_server_a_slow_client_within_the_server_timeout_gets_through() -> None:
    with _serve(_config()) as port:
        status, _ = _raw_post(port, [(0.1, b"abcd")] * 3)

    assert status == 200


def test_wsgiref_server_a_complete_body_is_scanned_and_passed_on() -> None:
    with _serve(_config()) as port:
        status, _ = _raw_post(port, [(0.0, b"hello world")])

    assert status == 200


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/shop/cart.php", 200),
        ("/forum/viewtopic.php", 200),
        ("/files/shop/cart.php", 400),
        ("/missing/cart.php", 400),
        ("/shop/other.php", 400),
    ],
)
def test_a_script_path_is_clean_only_when_the_app_declares_it(
    path: str, status: int
) -> None:
    import django.conf

    with override_settings(ROOT_URLCONF="tests.urls_idle_body"):
        django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
            ban_on_hostile_signals=False,
        )
        middleware = DjangoAPIGuard(lambda request: HttpResponse("OK"))
        assert middleware(RequestFactory().get(path)).status_code == status


def test_closing_the_replayed_stream_closes_the_underlying_stream() -> None:
    from djangoapi_guard.adapters import _ReplayStream

    closed: list[bool] = []

    class _Closable(io.BytesIO):
        def close(self) -> None:
            closed.append(True)
            super().close()

    _ReplayStream(b"abc", _Closable(b"def")).close()

    assert closed == [True]


def test_closing_a_replayed_stream_whose_source_cannot_close_is_harmless() -> None:
    from djangoapi_guard.adapters import _ReplayStream

    _ReplayStream(b"abc", object()).close()
