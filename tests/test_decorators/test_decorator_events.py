import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import sys
import types
from collections.abc import Iterator
from typing import Any, cast
from unittest.mock import Mock, patch

import pytest
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.adapters import DjangoGuardRequest


def _install_mock_guard_agent() -> types.ModuleType:
    mock_module = types.ModuleType("guard_agent")

    class MockSecurityEvent:
        def __init__(self, **kwargs: object) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    cast(Any, mock_module).SecurityEvent = MockSecurityEvent
    sys.modules["guard_agent"] = mock_module
    return mock_module


def _uninstall_mock_guard_agent() -> None:
    sys.modules.pop("guard_agent", None)


@pytest.fixture(autouse=True)
def _mock_guard_agent() -> Iterator[None]:
    _install_mock_guard_agent()
    yield
    _uninstall_mock_guard_agent()


@pytest.fixture()
def rf() -> RequestFactory:
    return RequestFactory()


@pytest.fixture()
def decorator() -> BaseSecurityDecorator:
    config = SecurityConfig[SyncGuardRequest](enable_redis=False, enable_agent=False)
    return BaseSecurityDecorator(config)


class TestDecoratorEvents:
    def test_send_decorator_event(
        self, rf: RequestFactory, decorator: BaseSecurityDecorator
    ) -> None:
        agent = Mock()
        decorator.agent_handler = agent

        request = rf.post(
            "/api/test",
            content_type="application/json",
            HTTP_USER_AGENT="TestAgent",
        )

        with patch(
            "guard_core.sync.utils.extract_client_ip",
            return_value="127.0.0.1",
        ):
            decorator.send_decorator_event(
                event_type="test_event",
                request=DjangoGuardRequest(request),
                action_taken="blocked",
                reason="test reason",
                decorator_type="test_decorator",
                extra_key="extra_val",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "test_event"
        assert event.action_taken == "blocked"
        assert event.reason == "test reason"
        assert event.endpoint == "/api/test"
        assert event.method == "POST"
        assert event.decorator_type == "test_decorator"
        assert event.user_agent == "TestAgent"
        assert event.metadata["extra_key"] == "extra_val"

    def test_send_decorator_event_no_agent(
        self, rf: RequestFactory, decorator: BaseSecurityDecorator
    ) -> None:
        decorator.agent_handler = None

        request = rf.get("/test")

        decorator.send_decorator_event(
            event_type="test",
            request=DjangoGuardRequest(request),
            action_taken="blocked",
            reason="test",
            decorator_type="test",
        )

    def test_send_decorator_event_exception(
        self, rf: RequestFactory, decorator: BaseSecurityDecorator
    ) -> None:
        agent = Mock()
        agent.send_event.side_effect = RuntimeError("agent down")
        decorator.agent_handler = agent

        request = rf.get("/test")

        with patch(
            "guard_core.sync.utils.extract_client_ip",
            return_value="127.0.0.1",
        ):
            decorator.send_decorator_event(
                event_type="test",
                request=DjangoGuardRequest(request),
                action_taken="blocked",
                reason="test",
                decorator_type="test",
            )

    def test_send_access_denied_event(
        self, rf: RequestFactory, decorator: BaseSecurityDecorator
    ) -> None:
        agent = Mock()
        decorator.agent_handler = agent

        request = rf.get("/secure")

        with patch(
            "guard_core.sync.utils.extract_client_ip",
            return_value="1.2.3.4",
        ):
            decorator.send_access_denied_event(
                request=DjangoGuardRequest(request),
                reason="IP blocked",
                decorator_type="access_control",
                source_ip="1.2.3.4",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "access_denied"
        assert event.action_taken == "blocked"
        assert event.reason == "IP blocked"
        assert event.decorator_type == "access_control"

    def test_send_authentication_failed_event(
        self, rf: RequestFactory, decorator: BaseSecurityDecorator
    ) -> None:
        agent = Mock()
        decorator.agent_handler = agent

        request = rf.get("/auth")

        with patch(
            "guard_core.sync.utils.extract_client_ip",
            return_value="127.0.0.1",
        ):
            decorator.send_authentication_failed_event(
                request=DjangoGuardRequest(request),
                reason="Invalid API key",
                auth_type="api_key",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "authentication_failed"
        assert event.action_taken == "blocked"
        assert event.decorator_type == "authentication"
        assert event.metadata["auth_type"] == "api_key"

    def test_send_rate_limit_event(
        self, rf: RequestFactory, decorator: BaseSecurityDecorator
    ) -> None:
        agent = Mock()
        decorator.agent_handler = agent

        request = rf.get("/api/data")

        with patch(
            "guard_core.sync.utils.extract_client_ip",
            return_value="127.0.0.1",
        ):
            decorator.send_rate_limit_event(
                request=DjangoGuardRequest(request),
                limit=100,
                window=60,
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "rate_limited"
        assert event.action_taken == "blocked"
        assert event.reason == "Rate limit exceeded: 100 requests per 60s"
        assert event.decorator_type == "rate_limiting"
        assert event.metadata["limit"] == 100
        assert event.metadata["window"] == 60

    def test_send_decorator_violation_event(
        self, rf: RequestFactory, decorator: BaseSecurityDecorator
    ) -> None:
        agent = Mock()
        decorator.agent_handler = agent

        request = rf.get("/admin")

        with patch(
            "guard_core.sync.utils.extract_client_ip",
            return_value="127.0.0.1",
        ):
            decorator.send_decorator_violation_event(
                request=DjangoGuardRequest(request),
                violation_type="content_filter",
                reason="Invalid content type",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.action_taken == "blocked"
        assert event.reason == "Invalid content type"
        assert event.decorator_type == "content_filter"
