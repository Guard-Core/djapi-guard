from collections.abc import Callable
from typing import Any
from unittest.mock import patch

from django.http import HttpRequest, HttpResponse
from guard_core.models import SecurityConfig
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard


def _noop_get_response() -> Callable[[HttpRequest], HttpResponse]:
    def _get_response(_: HttpRequest) -> HttpResponse:
        return HttpResponse("ok")

    return _get_response


def _build(settings_override: Any) -> DjangoAPIGuard:
    with patch(
        "djangoapi_guard.middleware.settings",
        settings_override,
    ):
        middleware = DjangoAPIGuard(_noop_get_response())
    middleware._initialize_handlers()
    return middleware


class _Settings:
    def __init__(self, config: SecurityConfig[SyncGuardRequest]) -> None:
        self.GUARD_SECURITY_CONFIG = config


def test_event_bus_routes_through_composite_when_otel_enabled() -> None:
    config = SecurityConfig[SyncGuardRequest](
        enable_otel=True, otel_service_name="wire-test"
    )
    mw = _build(_Settings(config))

    assert mw.event_bus is not None
    assert mw.metrics_collector is not None
    assert isinstance(mw.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(mw.metrics_collector.agent_handler, CompositeAgentHandler)


def test_event_bus_routes_through_composite_when_logfire_enabled() -> None:
    config = SecurityConfig[SyncGuardRequest](
        enable_logfire=True, logfire_service_name="wire-test"
    )
    mw = _build(_Settings(config))

    assert mw.event_bus is not None
    assert mw.metrics_collector is not None
    assert isinstance(mw.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(mw.metrics_collector.agent_handler, CompositeAgentHandler)


def test_event_bus_stays_bare_when_no_telemetry_configured() -> None:
    config = SecurityConfig[SyncGuardRequest]()
    mw = _build(_Settings(config))

    assert mw.event_bus is not None
    assert mw.metrics_collector is not None
    assert not isinstance(mw.event_bus.agent_handler, CompositeAgentHandler)
    assert not isinstance(mw.metrics_collector.agent_handler, CompositeAgentHandler)


def test_contexts_use_the_post_initialize_event_bus() -> None:
    config = SecurityConfig[SyncGuardRequest](
        enable_otel=True, otel_service_name="wire-test"
    )
    mw = _build(_Settings(config))

    assert mw.validator is not None
    assert mw.bypass_handler is not None
    assert mw.behavioral_processor is not None
    assert mw.response_factory is not None
    assert mw.validator.context.event_bus is mw.event_bus
    assert mw.bypass_handler.context.event_bus is mw.event_bus
    assert mw.behavioral_processor.context.event_bus is mw.event_bus
    assert mw.response_factory.context.metrics_collector is mw.metrics_collector
