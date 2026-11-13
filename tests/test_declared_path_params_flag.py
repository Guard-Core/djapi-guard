"""fail_on_misconfiguration governs the first-request report of a declared
detection_exclusion path param, and the kind travels with every report."""

import logging
import pathlib
from typing import cast

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from django.urls.resolvers import URLPattern, URLResolver
from guard_core.exceptions import MisconfigurationError

import djangoapi_guard
from djangoapi_guard import SecurityDecorator
from djangoapi_guard._declared_path_params import check_declared_path_params
from djangoapi_guard.middleware import DjangoAPIGuard
from tests.test_declared_path_params import (
    CASES,
    LOGGER,
    Build,
    build_missing,
    build_rootless,
    serving,
)


def _first_request_middleware(
    decorator: SecurityDecorator, monkeypatch: pytest.MonkeyPatch
) -> DjangoAPIGuard:
    monkeypatch.setattr("djangoapi_guard.middleware.resolve_decorator", lambda: None)
    middleware = DjangoAPIGuard(lambda request: HttpResponse("OK"))
    middleware.set_decorator_handler(decorator)
    return middleware


@pytest.mark.parametrize(("build", "path_", "tail"), CASES)
def test_with_the_flag_on_the_first_request_refuses_instead_of_warning(
    build: Build, path_: str, tail: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with serving(build, True) as decorator:
        middleware = _first_request_middleware(decorator, monkeypatch)

        with pytest.raises(MisconfigurationError) as refused:
            middleware(RequestFactory().get(path_))

    assert tail in str(refused.value)


def test_with_the_flag_on_every_request_refuses_until_it_is_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with serving(build_missing, True) as decorator:
        middleware = _first_request_middleware(decorator, monkeypatch)

        for _ in range(2):
            with pytest.raises(MisconfigurationError):
                middleware(RequestFactory().get("/items/7/"))


@pytest.mark.parametrize(
    ("build", "kind", "subject"),
    [
        (build_missing, "decorator.detection_exclusion.param_not_in_template", "ghost"),
        (
            build_rootless,
            "decorator.detection_exclusion.param_without_literal_segment",
            "tail",
        ),
    ],
)
def test_the_refusal_carries_the_kind_and_the_declared_name(
    build: Build, kind: str, subject: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with serving(build, True) as decorator:
        middleware = _first_request_middleware(decorator, monkeypatch)

        with pytest.raises(MisconfigurationError) as refused:
            middleware(RequestFactory().get("/items/7/"))

    assert [(p.kind, p.subject) for p in refused.value.problems] == [(kind, subject)]


def test_with_the_flag_off_the_warning_carries_its_kind(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    with serving(build_missing, False) as decorator:
        middleware = _first_request_middleware(decorator, monkeypatch)
        assert middleware(RequestFactory().get("/items/7/")).status_code == 200

    carried = [
        r.__dict__["problems"] for r in caplog.records if "problems" in r.__dict__
    ]
    assert (
        ("decorator.detection_exclusion.param_not_in_template", "ghost"),
    ) in carried


def test_the_system_check_message_is_the_engine_text() -> None:
    with serving(build_missing, True):
        [message] = check_declared_path_params()

    assert message.msg.startswith("@detection_exclusion(path_params=...) on route")


def test_the_adapter_holds_no_copy_of_the_engine_text() -> None:
    root = pathlib.Path(djangoapi_guard.__file__).parent
    assert not [
        p.name
        for p in root.rglob("*.py")
        if "@detection_exclusion(path_params=...) on route" in p.read_text()
    ]


@pytest.mark.parametrize(
    ("fail_secure", "passive_mode"),
    [(True, False), (False, False), (True, True)],
    ids=["fail_secure", "fail_open", "passive"],
)
def test_the_refusal_is_a_500_and_the_endpoint_never_runs(
    fail_secure: bool, passive_mode: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.core.handlers.exception import convert_exception_to_response
    from django.http import JsonResponse
    from django.urls import path

    ran: list[int] = []

    def build(decorator: SecurityDecorator) -> list[URLPattern | URLResolver]:
        def view(request: HttpRequest, pk: int) -> JsonResponse:
            ran.append(pk)
            return JsonResponse({})

        guarded = decorator.detection_exclusion(path_params={"ghost"})(view)
        return [path("items/<int:pk>/", guarded)]

    with serving(
        build, True, fail_secure=fail_secure, passive_mode=passive_mode
    ) as decorator:
        monkeypatch.setattr(
            "djangoapi_guard.middleware.resolve_decorator", lambda: None
        )
        middleware = DjangoAPIGuard(lambda request: HttpResponse("OK"))
        middleware.set_decorator_handler(decorator)
        refusing = convert_exception_to_response(middleware)
        codes = [
            cast(HttpResponse, refusing(RequestFactory().get("/items/7/"))).status_code
            for _ in range(3)
        ]

    assert codes == [500, 500, 500]
    assert ran == []
