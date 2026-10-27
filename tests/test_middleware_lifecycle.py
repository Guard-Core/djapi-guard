from collections.abc import Callable
from unittest.mock import patch

from django.http import HttpRequest, HttpResponse
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard


def _noop_get_response() -> Callable[[HttpRequest], HttpResponse]:
    def _get_response(_: HttpRequest) -> HttpResponse:
        return HttpResponse("ok")

    return _get_response


class _Settings:
    def __init__(self, config: SecurityConfig[SyncGuardRequest]) -> None:
        self.GUARD_SECURITY_CONFIG = config


def _build(config: SecurityConfig[SyncGuardRequest]) -> DjangoAPIGuard:
    with patch("djangoapi_guard.middleware.settings", _Settings(config)):
        middleware = DjangoAPIGuard(_noop_get_response())
    middleware._initialize_handlers()
    return middleware


def test_init_rebinds_agent_handler_to_composite() -> None:
    config = SecurityConfig[SyncGuardRequest](
        enable_otel=True,
        otel_service_name="guard-test",
        otel_exporter_endpoint="http://localhost:4318",
        enable_redis=False,
    )
    mw = _build(config)

    assert mw.handler_initializer is not None
    assert mw.handler_initializer.composite_handler is not None
    assert mw.agent_handler is mw.handler_initializer.composite_handler


def test_no_telemetry_leaves_agent_handler_bare() -> None:
    mw = _build(SecurityConfig[SyncGuardRequest](enable_redis=False))

    assert mw.handler_initializer is not None
    assert mw.handler_initializer.composite_handler is None
    assert mw.agent_handler is None


def test_behavior_tracker_threaded_through_behavioral_context() -> None:
    config = SecurityConfig[SyncGuardRequest](
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
        enable_enrichment=True,
        enable_otel=True,
        otel_exporter_endpoint="http://localhost:4318",
        enable_redis=False,
    )
    mw = _build(config)

    assert mw.handler_initializer is not None
    assert mw.behavioral_processor is not None
    assert mw.handler_initializer.behavior_tracker is not None
    assert (
        mw.behavioral_processor.context.behavior_tracker
        is mw.handler_initializer.behavior_tracker
    )


def test_execute_security_pipeline_returns_none_when_pipeline_unbuilt() -> None:
    mw = _build(SecurityConfig[SyncGuardRequest](enable_redis=False))
    from django.test import RequestFactory

    from djangoapi_guard.adapters import DjangoGuardRequest

    request = RequestFactory().get("/")
    guard_request = DjangoGuardRequest(request)

    mw.security_pipeline = None
    assert mw._execute_security_pipeline(guard_request) is None


def test_set_decorator_handler_noop_when_not_initialized() -> None:
    mw = _build(SecurityConfig[SyncGuardRequest](enable_redis=False))

    mw.behavioral_processor = None
    mw.response_factory = None
    mw.handler_initializer = None

    mw.set_decorator_handler(None)

    assert mw.guard_decorator is None
