import http.server
import logging
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import Mock

import pytest

import djangoapi_guard.middleware as middleware_module
from tests.agent_loop import close_the_agent_event_loop

_CHILD = textwrap.dedent(
    """
    import logging, sys
    logging.disable(logging.CRITICAL)
    import django
    from django.conf import settings
    from guard_core import SecurityConfig
    from guard_core.sync.protocols.request_protocol import SyncGuardRequest
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False, rate_limit=1000, trusted_proxies=[], enable_agent=True,
        agent_api_key="k" * 32, agent_project_id="p", agent_endpoint=sys.argv[1],
        agent_flush_interval=3600, agent_retry_attempts=3,
    )
    urlpatterns = []
    settings.configure(
        SECRET_KEY="x", ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__, MIDDLEWARE=[],
        GUARD_SECURITY_CONFIG=config,
    )
    django.setup()
    from django.http import HttpResponse
    from django.test import RequestFactory
    import djangoapi_guard.middleware as middleware_module
    from djangoapi_guard.middleware import DjangoAPIGuard
    middleware_module._AGENT_EXIT_WAIT_SECONDS = float(sys.argv[2])
    middleware = DjangoAPIGuard(lambda request: HttpResponse("ok"))
    factory = RequestFactory()
    for query in ("", "?q=<script>alert(1)</script>", ""):
        middleware(factory.get("/ok" + query, REMOTE_ADDR="203.0.113.5"))
    """
)


class _Recorder(http.server.BaseHTTPRequestHandler):
    received: list[tuple[str, bytes]]

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.received.append((self.path, self.rfile.read(length)))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, _format: str, *args: object) -> None:
        return None


@contextmanager
def _stub_agent_endpoint() -> Iterator[tuple[str, list[tuple[str, bytes]]]]:
    received: list[tuple[str, bytes]] = []
    handler = type("Recorder", (_Recorder,), {"received": received})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", received
    finally:
        server.shutdown()
        server.server_close()


@contextmanager
def _black_hole_endpoint() -> Iterator[str]:
    """Accepts connections and never answers."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    held: list[socket.socket] = []

    def accept() -> None:
        while True:
            try:
                held.append(listener.accept()[0])
            except OSError:
                return

    threading.Thread(target=accept, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        listener.close()
        for connection in held:
            connection.close()


_EXIT_BOUND = 1.0
# Process start and three requests take a couple of seconds; an unbounded stop()
# against a refused endpoint takes 14 s and against a black hole over a minute.
_EXIT_LIMIT = 8.0


def _run_child(endpoint: str, tmp_path: object) -> float:
    started = time.perf_counter()
    subprocess.run(
        [sys.executable, "-c", _CHILD, endpoint, str(_EXIT_BOUND)],
        check=True,
        timeout=120,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
        cwd=str(tmp_path),
    )
    return time.perf_counter() - started


def test_buffered_events_reach_the_agent_endpoint_at_process_exit(
    tmp_path: object,
) -> None:
    with _stub_agent_endpoint() as (endpoint, received):
        _run_child(endpoint, tmp_path)

    paths = {path for path, _ in received}
    assert {"/api/v1/events", "/api/v1/metrics"} <= paths


def test_exit_waits_no_longer_than_the_bound_for_a_refused_endpoint(
    tmp_path: object,
) -> None:
    unused = socket.socket()
    unused.bind(("127.0.0.1", 0))
    endpoint = f"http://127.0.0.1:{unused.getsockname()[1]}"
    unused.close()

    elapsed = _run_child(endpoint, tmp_path)

    assert elapsed < _EXIT_LIMIT


def test_exit_waits_no_longer_than_the_bound_for_a_black_holed_endpoint(
    tmp_path: object,
) -> None:
    with _black_hole_endpoint() as endpoint:
        elapsed = _run_child(endpoint, tmp_path)

    assert elapsed < _EXIT_LIMIT


def test_a_handler_is_registered_for_exit_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        middleware_module.atexit, "register", lambda *args: calls.append(args)
    )
    handler = Mock()
    logger = middleware_module.logging.getLogger("t")

    for _ in range(2):
        middleware_module._stop_agent_at_exit(handler, logger)

    assert len(calls) == 1
    middleware_module._agent_exit_registered.discard(id(handler))


def _running_handler() -> Mock:
    handler = Mock()
    handler._thread.is_alive.return_value = True
    handler._loop.is_closed.return_value = False
    return handler


def test_the_exit_hook_stops_the_agent_and_stays_quiet_when_it_finishes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = _running_handler()

    with caplog.at_level(logging.WARNING, logger="t"):
        middleware_module._stop_agent_within(handler, 5.0, logging.getLogger("t"))

    handler.stop.assert_called_once_with()
    assert caplog.records == []


def test_the_exit_hook_logs_a_stop_that_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = _running_handler()
    handler.stop.side_effect = RuntimeError("endpoint gone")

    with caplog.at_level(logging.ERROR, logger="t"):
        middleware_module._stop_agent_within(handler, 5.0, logging.getLogger("t"))

    assert "did not stop cleanly at exit: endpoint gone" in caplog.text


def test_the_exit_hook_gives_up_on_a_stop_that_outlasts_the_bound(
    caplog: pytest.LogCaptureFixture,
) -> None:
    release = threading.Event()
    handler = _running_handler()
    handler.stop.side_effect = lambda: release.wait(10)

    try:
        with caplog.at_level(logging.WARNING, logger="t"):
            middleware_module._stop_agent_within(handler, 0.05, logging.getLogger("t"))
    finally:
        release.set()

    assert "did not finish flushing within 0.1 s at exit" in caplog.text


def test_the_exit_hook_skips_a_handler_whose_loop_thread_has_ended() -> None:
    handler = Mock()
    handler._thread.is_alive.return_value = False
    handler._loop.is_closed.return_value = False

    started = time.perf_counter()
    middleware_module._stop_agent_within(handler, 30.0, logging.getLogger("t"))

    handler.stop.assert_not_called()
    assert time.perf_counter() - started < 1.0


def test_the_exit_hook_skips_a_handler_whose_loop_is_closed() -> None:
    handler = Mock()
    handler._thread.is_alive.return_value = True
    handler._loop.is_closed.return_value = True

    middleware_module._stop_agent_within(handler, 30.0, logging.getLogger("t"))

    handler.stop.assert_not_called()


def test_a_handler_the_user_already_stopped_costs_the_exit_nothing() -> None:
    from guard_agent import SyncGuardAgentHandler
    from guard_agent.models import AgentConfig

    close_the_agent_event_loop()
    with _stub_agent_endpoint() as (endpoint, _):
        handler = SyncGuardAgentHandler(
            AgentConfig(api_key="k" * 32, project_id="p", endpoint=endpoint)
        )
        handler.start()
        handler.stop()

        started = time.perf_counter()
        middleware_module._stop_agent_within(handler, 30.0, logging.getLogger("t"))
        elapsed = time.perf_counter() - started
    close_the_agent_event_loop()

    assert elapsed < 1.0
