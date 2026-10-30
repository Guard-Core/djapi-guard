import io
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Protocol, runtime_checkable

from django.http import HttpRequest, HttpResponse, StreamingHttpResponse
from django.http.response import HttpResponseBase
from guard_core.exceptions import BodyReadStalledError
from guard_core.protocols import GuardResponse, GuardResponseHeaders

_READ_CHUNK_BYTES = 65536
_SERVER_SOCKET_KEYS = ("gunicorn.socket", "werkzeug.socket")


def set_request_attribute(request: HttpRequest, name: str, value: object) -> None:
    # Django declares none of these per-request attributes (and types _stream as
    # a BinaryIO a replay stream is not) and has no public way to attach them
    setattr(request, name, value)


def _caused_by_timeout(error: BaseException | None) -> bool:
    seen: set[int] = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, TimeoutError):
            return True
        seen.add(id(error))
        error = error.__cause__ or error.__context__
    return False


class _ByteSource(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...

    def readline(self, size: int = -1, /) -> bytes: ...


class _ReplayStream:
    def __init__(self, prefix: bytes, rest: _ByteSource) -> None:
        self._prefix = io.BytesIO(prefix)
        self._rest = rest

    def read(self, size: int | None = -1) -> bytes:
        head = self._prefix.read(-1 if size is None else size)
        if size is None or size < 0:
            return head + self._rest.read()
        if len(head) == size:
            return head
        return head + self._rest.read(size - len(head))

    def readline(self, size: int | None = -1) -> bytes:
        head = self._prefix.readline(-1 if size is None else size)
        if head.endswith(b"\n") or (size is not None and 0 <= size <= len(head)):
            return head
        remaining = -1 if size is None or size < 0 else size - len(head)
        return head + self._rest.readline(remaining)

    def __iter__(self) -> Iterator[bytes]:
        while line := self.readline():
            yield line

    def seekable(self) -> bool:
        return False

    def close(self) -> None:
        self._prefix.close()
        close = getattr(self._rest, "close", None)
        if close is not None:
            close()


@runtime_checkable
class _TimeoutSocket(Protocol):
    def gettimeout(self) -> float | None: ...

    def settimeout(self, value: float | None) -> None: ...


@contextmanager
def _idle_socket_timeout(
    environ: Mapping[str, object], idle_timeout: float
) -> Iterator[None]:
    server_socket = next(
        (environ[key] for key in _SERVER_SOCKET_KEYS if key in environ), None
    )
    if not isinstance(server_socket, _TimeoutSocket):
        yield
        return
    previous = server_socket.gettimeout()
    server_socket.settimeout(idle_timeout)
    try:
        yield
    finally:
        server_socket.settimeout(previous)


class DjangoGuardRequest:
    def __init__(self, request: HttpRequest) -> None:
        self._request = request

    @property
    def url_path(self) -> str:
        result: str = self._request.path_info
        return result

    @property
    def url_scheme(self) -> str:
        result: str = self._request.scheme or ""
        return result

    @property
    def url_full(self) -> str:
        result: str = self._request.build_absolute_uri()
        return result

    def url_replace_scheme(self, scheme: str) -> str:
        url: str = self._request.build_absolute_uri()
        if url.startswith("http://"):
            return scheme + "://" + url[7:]
        if url.startswith("https://"):
            return scheme + "://" + url[8:]
        return url

    @property
    def method(self) -> str:
        result: str = self._request.method or ""
        return result

    @property
    def client_host(self) -> str | None:
        result: str | None = self._request.META.get("REMOTE_ADDR")
        return result

    @property
    def headers(self) -> Mapping[str, str]:
        return DjangoHeadersMapping(self._request.META)

    @property
    def query_params(self) -> Mapping[str, str]:
        result: Mapping[str, str] = self._request.GET
        return result

    def body(self) -> bytes:
        result: bytes = self._request.body
        return result

    def read_body_prefix(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        return self._request.body[:max_bytes]

    def read_body_prefix_until_idle(self, max_bytes: int, idle_timeout: float) -> bytes:
        if max_bytes <= 0:
            return b""
        request = self._request
        if hasattr(request, "_body"):
            return request._body[:max_bytes]
        stream = request._stream
        chunks: list[bytes] = []
        received = 0
        try:
            with _idle_socket_timeout(request.META, idle_timeout):
                while received < max_bytes:
                    piece = stream.read(min(_READ_CHUNK_BYTES, max_bytes - received))
                    if not piece:
                        break
                    chunks.append(piece)
                    received += len(piece)
        except Exception as exc:
            if _caused_by_timeout(exc):
                raise BodyReadStalledError() from exc
            raise
        finally:
            prefix = b"".join(chunks)
            set_request_attribute(request, "_stream", _ReplayStream(prefix, stream))
        return prefix

    @property
    def state(self) -> HttpRequest:
        return self._request

    @property
    def scope(self) -> dict[str, object]:
        return {"META": self._request.META}


class DjangoHeadersMapping(Mapping[str, str]):
    def __init__(self, meta: Mapping[str, object]) -> None:
        self._headers: dict[str, str] = {}
        for key, value in meta.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                self._headers[header_name] = str(value)
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                header_name = key.replace("_", "-").title()
                self._headers[header_name] = str(value)

    def __getitem__(self, key: str) -> str:
        return self._headers[key.title()]

    def __iter__(self) -> Iterator[str]:
        return iter(self._headers)

    def __len__(self) -> int:
        return len(self._headers)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return key.title() in self._headers


class _TeedStreamingContent:
    def __init__(self, source: Iterator[bytes]) -> None:
        self._source = source
        self.head: list[bytes] = []

    def read_until(self, wanted: int) -> None:
        received = sum(map(len, self.head))
        if received >= wanted:
            return
        for chunk in self._source:
            self.head.append(chunk)
            received += len(chunk)
            if received >= wanted:
                return

    def __iter__(self) -> Iterator[bytes]:
        while self.head:
            yield self.head.pop(0)
        yield from self._source


def _tee_streaming_content(native: HttpResponseBase) -> _TeedStreamingContent | None:
    if not isinstance(native, StreamingHttpResponse):
        return None
    content = native.streaming_content
    # an async stream is never consumed here: the sync tee cannot read it
    if not isinstance(content, Iterator):
        return None
    tee = _TeedStreamingContent(content)
    native.streaming_content = tee
    return tee


class DjangoGuardResponse:
    body_is_materialized: bool

    def __init__(self, response: HttpResponseBase) -> None:
        self._response = response
        self._tee: _TeedStreamingContent | None = None
        # a streaming response (StreamingHttpResponse, FileResponse) never holds
        # its body, and a response class outside HttpResponse is not assumed to
        self.body_is_materialized = (
            isinstance(response, HttpResponse) and not response.streaming
        )

    @property
    def status_code(self) -> int:
        result: int = self._response.status_code
        return result

    @property
    def headers(self) -> GuardResponseHeaders:
        return self._response.headers

    @property
    def body(self) -> bytes | None:
        if isinstance(self._response, HttpResponse):
            return self._response.content
        return None

    def read_body_prefix(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        native = self._response
        if isinstance(native, HttpResponse):
            return native.content[:max_bytes]
        if self._tee is None:
            self._tee = _tee_streaming_content(native)
        if self._tee is None:
            return b""
        # a declared length within the cap is read to its end; any other stream
        # stops at the first chunk, so an endless stream never stalls the scan
        declared = native.get("Content-Length", "")
        self._tee.read_until(
            int(declared)
            if declared.isascii() and declared.isdigit() and int(declared) <= max_bytes
            else 1
        )
        return b"".join(self._tee.head)[:max_bytes]


class DjangoResponseFactory:
    def create_response(self, content: str, status_code: int) -> DjangoGuardResponse:
        return DjangoGuardResponse(
            HttpResponse(
                content, status=status_code, content_type="text/plain; charset=utf-8"
            )
        )

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> DjangoGuardResponse:
        response = HttpResponse(status=status_code)
        response["Location"] = url
        return DjangoGuardResponse(response)


def unwrap_response(guard_response: GuardResponse) -> HttpResponseBase:
    if isinstance(guard_response, DjangoGuardResponse):
        return guard_response._response
    response = HttpResponse(
        guard_response.body,
        status=guard_response.status_code,
    )
    for key, value in guard_response.headers.items():
        response[key] = value
    return response
