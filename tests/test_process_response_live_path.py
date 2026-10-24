import time
from typing import Any, cast
from unittest.mock import patch

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseBase
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.adapters import DjangoGuardRequest, DjangoGuardResponse
from djangoapi_guard.middleware import DjangoAPIGuard, unwrap_response

ORIGIN = "https://app.example.com"


def _make_middleware(enable_cors: bool) -> DjangoAPIGuard:
    config = SecurityConfig[SyncGuardRequest](
        enable_cors=enable_cors,
        cors_allow_origins=[ORIGIN],
        cors_allow_methods=["GET", "POST"],
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )
    django.conf.settings.GUARD_SECURITY_CONFIG = config

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("ok", status=201, headers={"X-App": "1"})

    return DjangoAPIGuard(get_response)


def _reference_finalize(
    middleware: DjangoAPIGuard,
    request: HttpRequest,
    response: HttpResponse,
    start_time: float,
) -> HttpResponseBase:
    assert middleware.response_factory is not None
    assert middleware.behavioral_processor is not None
    result = middleware.response_factory.process_response(
        DjangoGuardRequest(request),
        DjangoGuardResponse(response),
        time.time() - start_time,
        None,
        process_behavioral_rules=middleware.behavioral_processor.process_return_rules,
        process_global_behavioral_rules=(
            middleware.behavioral_processor.process_global_return_rules
        ),
    )
    return middleware._attach_cors_headers(unwrap_response(result), request)


@pytest.mark.parametrize("enable_cors", [False, True])
def test_real_request_goes_through_process_response(enable_cors: bool) -> None:
    middleware = _make_middleware(enable_cors)
    request = RequestFactory().get("/", HTTP_ORIGIN=ORIGIN)
    with patch.object(
        DjangoAPIGuard, "_process_response", autospec=True
    ) as process_response:
        process_response.side_effect = lambda self, req, resp, rt, rc: resp
        response = middleware(request)
    assert process_response.call_count == 1
    assert isinstance(process_response.call_args.args[3], float)
    assert response.status_code == 201


@pytest.mark.parametrize("enable_cors", [False, True])
def test_finalize_response_matches_inline_implementation(enable_cors: bool) -> None:
    middleware = _make_middleware(enable_cors)
    start_time = time.time() - 5.0
    expected_request = RequestFactory().get("/", HTTP_ORIGIN=ORIGIN)
    actual_request = RequestFactory().get("/", HTTP_ORIGIN=ORIGIN)
    cast(Any, actual_request)._guard_request_start_time = start_time

    expected = _reference_finalize(
        middleware,
        expected_request,
        HttpResponse("ok", status=201, headers={"X-App": "1"}),
        start_time,
    )
    actual = middleware._finalize_response(
        actual_request,
        HttpResponse("ok", status=201, headers={"X-App": "1"}),
        None,
    )

    assert actual.status_code == expected.status_code == 201
    assert actual.content == expected.content == b"ok"
    assert dict(actual.headers) == dict(expected.headers)
    assert ("Access-Control-Allow-Origin" in actual.headers) is enable_cors


def test_finalize_response_passes_elapsed_time_from_request_start() -> None:
    middleware = _make_middleware(False)
    request = RequestFactory().get("/")
    cast(Any, request)._guard_request_start_time = time.time() - 5.0
    with patch.object(
        DjangoAPIGuard, "_process_response", autospec=True
    ) as process_response:
        process_response.side_effect = lambda self, req, resp, rt, rc: resp
        middleware._finalize_response(request, HttpResponse("ok"), None)
    assert 5.0 <= process_response.call_args.args[3] < 10.0
