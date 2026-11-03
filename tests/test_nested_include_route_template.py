"""A real request through nested ``include()`` calls makes the security event
carry the joined, normalised ``route_template``, and a ``detection_exclusion`` on
a path parameter of an included route matches (LEDGER 6.565, Django part)."""

import sys
from collections.abc import Iterator

import pytest
from django.test import Client, override_settings
from django.urls import clear_url_caches
from guard_agent import SyncGuardAgentHandler
from guard_agent.models import SecurityEvent
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

URLCONF = "tests.nested_include_urls"
PREFIX = "/orgs/5/teams/x"
PROBE_IN_THE_VALUE = "readme.md"


@pytest.fixture(autouse=True)
def _fresh_urlconf() -> Iterator[None]:
    sys.modules.pop(URLCONF, None)
    clear_url_caches()
    yield
    sys.modules.pop(URLCONF, None)
    clear_url_caches()


def _blocked_events(monkeypatch: pytest.MonkeyPatch, path: str) -> list[SecurityEvent]:
    sent: list[SecurityEvent] = []

    def record(self: SyncGuardAgentHandler, event: SecurityEvent) -> None:
        sent.append(event)

    monkeypatch.setattr(SyncGuardAgentHandler, "send_event", record)
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_rate_limiting=False,
        enable_ip_banning=False,
        enable_agent=True,
        agent_api_key="sk-test-0123456789",
        blocked_user_agents=["badbot"],
    )
    with override_settings(ROOT_URLCONF=URLCONF, GUARD_SECURITY_CONFIG=config):
        assert Client().get(path, headers={"user-agent": "badbot"}).status_code == 403
    return sent


@pytest.mark.parametrize(
    ("path", "template"),
    [
        (f"{PREFIX}/items/7/", "/orgs/{org}/teams/{team}/items/{pk}/"),
        (f"{PREFIX}/old/2024/", "/orgs/{org}/teams/{team}/old/{year}/"),
    ],
)
def test_the_event_carries_the_joined_normalised_template(
    monkeypatch: pytest.MonkeyPatch, path: str, template: str
) -> None:
    events = _blocked_events(monkeypatch, path)

    assert [event.route_template for event in events] == [template]


def _get(path: str) -> int:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_rate_limiting=False,
        enable_ip_banning=False,
        enable_penetration_detection=True,
    )
    with override_settings(ROOT_URLCONF=URLCONF, GUARD_SECURITY_CONFIG=config):
        return Client().get(path).status_code


def test_a_probe_token_in_a_path_parameter_of_an_included_route_is_refused() -> None:
    assert _get(f"{PREFIX}/guarded/{PROBE_IN_THE_VALUE}/") == 400


def test_a_detection_exclusion_matches_a_path_parameter_of_an_included_route() -> None:
    assert _get(f"{PREFIX}/excluded/{PROBE_IN_THE_VALUE}/") == 200
