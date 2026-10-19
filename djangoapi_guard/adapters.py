import io
from collections.abc import Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from typing import Any, cast

from django.http import HttpRequest, HttpResponse
from guard_core.exceptions import BodyReadStalledError

_READ_CHUNK_BYTES = 65536
_SERVER_SOCKET_KEYS = ("gunicorn.socket", "werkzeug.socket")


def _caused_by_timeout(error: BaseException | None) -> bool:
    seen: set[int] = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, TimeoutError):
            return True
        seen.add(id(error))
        error = error.__cause__ or error.__context__
    return False


class _ReplayStream:
    def __init__(self, prefix: bytes, rest: Any) -> None:
        self._prefix = io.BytesIO(prefix)
        self._rest = rest

    def read(self, size: int | None = -1) -> bytes:
        head = self._prefix.read(-1 if size is None else size)
        if size is None or size < 0:
            return head + cast(bytes, self._rest.read())
        if len(head) == size:
            return head
        return head + cast(bytes, self._rest.read(size - len(head)))

    def readline(self, size: int | None = -1) -> bytes:
        head = self._prefix.readline(-1 if size is None else size)
        if head.endswith(b"\n") or (size is not None and 0 <= size <= len(head)):
            return head
        remaining = -1 if size is None or size < 0 else size - len(head)
        return head + cast(bytes, self._rest.readline(remaining))

    def __iter__(self) -> Iterator[bytes]:
        while line := self.readline():
            yield line

    def close(self) -> None:
        self._prefix.close()
        close = getattr(self._rest, "close", None)
        if close is not None:
            close()


@contextmanager
def _idle_socket_timeout(
    environ: Mapping[str, Any], idle_timeout: float
) -> Iterator[None]:
    server_socket = next(
        (environ[key] for key in _SERVER_SOCKET_KEYS if key in environ), None
    )
    if server_socket is None:
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
        result: str = self._request.path
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
        request = cast(Any, self._request)
        if hasattr(request, "_body"):
            return cast(bytes, request._body[:max_bytes])
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
            request._stream = _ReplayStream(prefix, stream)
        return prefix

    @property
    def state(self) -> Any:
        return self._request

    @property
    def scope(self) -> dict[str, Any]:
        return {"META": self._request.META}


class DjangoHeadersMapping(Mapping[str, str]):
    def __init__(self, meta: dict[str, Any]) -> None:
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


class DjangoGuardResponse:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        result: int = self._response.status_code
        return result

    @property
    def headers(self) -> MutableMapping[str, str]:
        return cast(MutableMapping[str, str], self._response)

    @property
    def body(self) -> bytes | None:
        result: bytes | None = self._response.content
        return result

    def read_body_prefix(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        content: bytes | None = getattr(self._response, "content", None)
        if content is None:
            return b""
        return content[:max_bytes]


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


def unwrap_response(guard_response: Any) -> HttpResponse:
    if isinstance(guard_response, DjangoGuardResponse):
        return guard_response._response
    response = HttpResponse(
        guard_response.body,
        status=guard_response.status_code,
    )
    for key, value in guard_response.headers.items():
        response[key] = value
    return response
