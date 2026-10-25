from collections.abc import Iterator
from typing import Any

import pytest
from django.test import Client, override_settings
from guard_core.models import SecurityConfig
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

CAP = 1024
LARGE_LIMIT = 7000
_PAYLOAD = b"1' UNION SELECT password FROM users--"
_PAST_THE_CAP_PAYLOAD = b"A" * (LARGE_LIMIT - len(_PAYLOAD) - 1) + _PAYLOAD
_ONE_BYTE_PAST = b"A" * (CAP + 1)
_AT_THE_CAP = b"A" * CAP
_FORWARDED = {"X-Forwarded-For": "203.0.113.50"}


@pytest.fixture
def captured_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    original = SecurityEventBus.send_middleware_event

    def _capture(self: SecurityEventBus, *args: Any, **kwargs: Any) -> None:
        events.append(kwargs)
        original(self, *args, **kwargs)

    monkeypatch.setattr(SecurityEventBus, "send_middleware_event", _capture)
    return events


def _config(fail_secure: bool) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=True,
        detection_max_body_inspect_bytes=CAP,
        fail_secure=fail_secure,
        trusted_proxies=("127.0.0.1",),
        auto_ban_threshold=2,
    )


@pytest.fixture
def served_fail_secure() -> Iterator[Client]:
    with override_settings(
        ROOT_URLCONF="tests.urls_body_past_inspect_cap",
        GUARD_SECURITY_CONFIG=_config(True),
        GUARD_DECORATOR="tests.urls_body_past_inspect_cap.guard_deco",
    ):
        yield Client()


@pytest.fixture
def served_fail_open() -> Iterator[Client]:
    with override_settings(
        ROOT_URLCONF="tests.urls_body_past_inspect_cap",
        GUARD_SECURITY_CONFIG=_config(False),
        GUARD_DECORATOR="tests.urls_body_past_inspect_cap.guard_deco",
    ):
        yield Client()


def _post(client: Client, path: str, body: bytes) -> tuple[int, bytes]:
    response = client.post(
        path, data=body, content_type="text/plain", headers=_FORWARDED
    )
    return response.status_code, response.content


def _body_read_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if "Request body read failed" in e.get("reason", "")]


@pytest.mark.parametrize("body", [_ONE_BYTE_PAST, _PAST_THE_CAP_PAYLOAD])
def test_a_body_past_the_cap_is_refused_with_an_event_and_no_strike(
    body: bytes, served_fail_secure: Client, captured_events: list[dict[str, Any]]
) -> None:
    statuses = [_post(served_fail_secure, "/small", body)[0] for _ in range(4)]
    after = _post(served_fail_secure, "/small", b"hello")

    assert statuses == [400, 400, 400, 400]
    assert after[0] == 200
    assert len(_body_read_events(captured_events)) == 4
    assert {e["action_taken"] for e in _body_read_events(captured_events)} == {
        "request_blocked"
    }


def test_a_body_past_the_cap_passes_with_an_event_without_fail_secure(
    served_fail_open: Client, captured_events: list[dict[str, Any]]
) -> None:
    response = _post(served_fail_open, "/small", _PAST_THE_CAP_PAYLOAD)

    assert response[0] == 200
    assert [e["action_taken"] for e in _body_read_events(captured_events)] == [
        "logged_only"
    ]


def test_a_route_with_max_request_size_above_the_cap_is_scanned_in_full(
    served_fail_secure: Client,
) -> None:
    raised = _post(served_fail_secure, "/large", _PAST_THE_CAP_PAYLOAD)
    sibling = _post(served_fail_secure, "/small", _PAST_THE_CAP_PAYLOAD)

    assert raised[0] == 400
    assert b"Suspicious activity detected" in raised[1]
    assert sibling[0] == 400
    assert b"Suspicious activity detected" not in sibling[1]


def test_a_body_at_exactly_the_cap_is_scanned_in_full_and_unchanged(
    served_fail_secure: Client, captured_events: list[dict[str, Any]]
) -> None:
    hit = _AT_THE_CAP[: CAP - len(_PAYLOAD)] + _PAYLOAD

    clean = _post(served_fail_secure, "/small", _AT_THE_CAP)
    attack = _post(served_fail_secure, "/small", hit)

    assert clean[0] == 200
    assert attack[0] == 400
    assert b"Suspicious activity detected" in attack[1]
    assert _body_read_events(captured_events) == []
