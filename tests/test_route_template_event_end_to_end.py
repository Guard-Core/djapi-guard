"""A real request to a routed endpoint makes the security event carry the
normalised ``route_template`` (LEDGER 6.549)."""

import pytest
from django.test import Client, override_settings
from guard_agent import SyncGuardAgentHandler
from guard_agent.models import SecurityEvent
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def test_a_blocked_request_event_carries_the_route_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[SecurityEvent] = []

    def record(self: SyncGuardAgentHandler, event: SecurityEvent) -> None:
        sent.append(event)

    monkeypatch.setattr(SyncGuardAgentHandler, "send_event", record)
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=True,
        agent_api_key="sk-test-0123456789",
        enable_rate_limiting=False,
        enable_ip_banning=False,
        blocked_user_agents=["badbot"],
    )

    with override_settings(
        ROOT_URLCONF="tests.route_template_event_urls", GUARD_SECURITY_CONFIG=config
    ):
        response = Client().get("/items/42", headers={"user-agent": "badbot"})

    assert response.status_code == 403
    assert [event.endpoint for event in sent] == ["/items/42"]
    assert [event.route_template for event in sent] == ["/items/{item_id}"]
