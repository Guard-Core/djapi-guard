"""A route added after startup is checked when the urlconf changes, not when it is
first requested: one warning without fail_on_misconfiguration, a fresh refusal on
every request with it, and no whole-table walk while the table holds."""

import gc
import logging
import sys
import threading
import traceback
import types
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import clear_url_caches, get_resolver, include, path
from guard_core.exceptions import MisconfigurationError

from djangoapi_guard import SecurityDecorator, _declared_path_params
from djangoapi_guard.middleware import DjangoAPIGuard
from tests.test_declared_path_params import (
    LOGGER,
    URLCONF,
    Patterns,
    _missing,
    _new_view,
    _problems,
    serving,
)

REFUSAL = "Every request is refused until this is fixed"
HOST_URLCONF = "wp756_host_urls"
INNER: list[Any] = []


def _refusals(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if REFUSAL in r.getMessage()]


def build_ok_and_included(decorator: SecurityDecorator) -> Patterns:
    INNER.clear()
    INNER.append(path("seed/", _new_view()))
    return [
        path("ok/", _new_view()),
        path("other/", _new_view()),
        path("inc/", include(INNER)),
    ]


def _late_route(decorator: SecurityDecorator, name: str, declared: str) -> Any:
    view = decorator.detection_exclusion(path_params={declared})(_new_view())
    return path(f"late/<str:{name}>/", view)


def _bad(decorator: SecurityDecorator) -> Any:
    return _late_route(decorator, "item_id", "ghost")


def _good(decorator: SecurityDecorator) -> Any:
    return _late_route(decorator, "item_id", "item_id")


def _patterns(variant: str) -> list[Any]:
    modules = {"root": URLCONF, "host": HOST_URLCONF}
    patterns: list[Any] = INNER
    if variant in modules:
        patterns = sys.modules[modules[variant]].urlpatterns
    return patterns


def _template(variant: str) -> str:
    return "inc/late/<str:item_id>/" if variant == "included" else "late/<str:item_id>/"


def _request(variant: str) -> Any:
    request = RequestFactory().get("/ok/")
    if variant == "host":
        request.urlconf = HOST_URLCONF
    return request


@contextmanager
def _served(
    flag: bool, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[SecurityDecorator, DjangoAPIGuard]]:
    with serving(build_ok_and_included, flag) as decorator:
        host = types.ModuleType(HOST_URLCONF)
        host.__dict__["urlpatterns"] = [path("ok/", _new_view())]
        sys.modules[HOST_URLCONF] = host
        clear_url_caches()
        monkeypatch.setattr(
            "djangoapi_guard.middleware.resolve_decorator", lambda: None
        )
        middleware = DjangoAPIGuard(lambda request: HttpResponse("OK"))
        middleware.set_decorator_handler(decorator)
        try:
            yield decorator, middleware
        finally:
            del sys.modules[HOST_URLCONF]


VARIANTS = pytest.mark.parametrize("variant", ["root", "included", "host"])


@VARIANTS
def test_l1_late_route_with_the_flag_off_warns_once_on_an_unrelated_request(
    variant: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    with _served(False, monkeypatch) as (decorator, middleware):
        assert middleware(_request(variant)).status_code == 200
        assert _problems(caplog) == []

        _patterns(variant).append(_bad(decorator))
        assert middleware(_request(variant)).status_code == 200
        assert middleware(_request(variant)).status_code == 200

    (problem,) = _problems(caplog)
    assert _missing(_template(variant)) in problem


@VARIANTS
def test_l1_late_route_with_the_flag_on_refuses_every_request_and_logs_once(
    variant: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger=LOGGER)
    with _served(True, monkeypatch) as (decorator, middleware):
        assert middleware(_request(variant)).status_code == 200

        _patterns(variant).append(_bad(decorator))
        for _ in range(2):
            with pytest.raises(MisconfigurationError):
                middleware(_request(variant))

    assert len(_refusals(caplog)) == 1


def test_l1_alternating_host_urlconfs_keep_a_state_each_and_walk_the_host_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    walks: list[int] = []
    real = _declared_path_params.declared_path_param_problems

    def counting(*args: Any, **kwargs: Any) -> Any:
        walks.append(1)
        return real(*args, **kwargs)

    with _served(False, monkeypatch) as (_, middleware):
        assert middleware(_request("root")).status_code == 200
        monkeypatch.setattr(
            _declared_path_params, "declared_path_param_problems", counting
        )
        for _ in range(10):
            assert middleware(_request("root")).status_code == 200
            assert middleware(_request("host")).status_code == 200

    assert len(walks) == 1


@VARIANTS
def test_l2_the_table_is_walked_once_per_change_and_never_per_request(
    variant: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    walks: list[int] = []
    real = _declared_path_params.declared_path_param_problems

    def counting(*args: Any, **kwargs: Any) -> Any:
        walks.append(1)
        return real(*args, **kwargs)

    with _served(False, monkeypatch) as (decorator, middleware):
        assert middleware(_request(variant)).status_code == 200
        monkeypatch.setattr(
            _declared_path_params, "declared_path_param_problems", counting
        )
        for _ in range(50):
            assert middleware(_request(variant)).status_code == 200
        assert walks == []

        _patterns(variant).append(_good(decorator))
        for _ in range(50):
            assert middleware(_request(variant)).status_code == 200

    assert len(walks) == 1


def test_f_fresh_every_refusal_is_a_new_error_of_the_same_depth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    errors: list[MisconfigurationError] = []
    with _served(True, monkeypatch) as (decorator, middleware):
        assert middleware(_request("root")).status_code == 200
        _patterns("root").append(_bad(decorator))
        for _ in range(3):
            with pytest.raises(MisconfigurationError) as refused:
                middleware(_request("root"))
            errors.append(refused.value)

    assert len({id(error) for error in errors}) == 3
    assert len({len(traceback.extract_tb(e.__traceback__)) for e in errors}) == 1


def test_t_threads_two_threads_and_one_change_warn_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []
    with _served(False, monkeypatch) as (decorator, middleware):
        assert middleware(_request("root")).status_code == 200
        _patterns("root").append(_bad(decorator))

        def serve() -> None:
            try:
                barrier.wait()
                middleware(_request("root"))
            except BaseException as error:
                failures.append(error)

        threads = [threading.Thread(target=serve) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert failures == []
    assert len(_problems(caplog)) == 1


@VARIANTS
def test_g_a_late_route_with_a_correct_declaration_reports_nothing(
    variant: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    with _served(True, monkeypatch) as (decorator, middleware):
        assert middleware(_request(variant)).status_code == 200
        _patterns(variant).append(_good(decorator))
        assert middleware(_request(variant)).status_code == 200

    assert _problems(caplog) == []
    assert _refusals(caplog) == []


def test_g_leak_the_state_dies_with_its_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _served(False, monkeypatch) as (_, middleware):
        assert middleware(_request("root")).status_code == 200
        weak_maps = [
            value
            for value in vars(middleware).values()
            if isinstance(value, weakref.WeakKeyDictionary)
        ]
        resolver_reference = weakref.ref(get_resolver(None))

        clear_url_caches()
        gc.collect()

        assert resolver_reference() is None
        assert [len(weak_map) for weak_map in weak_maps] == [0] * len(weak_maps)
