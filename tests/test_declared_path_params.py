"""LEDGER 6.851: a declared detection_exclusion path param the route does not have is
a system check Error (a Warning with fail_on_misconfiguration=False) and a WARNING
logged once at the first request (a refusal with the flag on), read from the urlconf."""

import logging
import sys
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from io import StringIO

import pytest
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.core.wsgi import get_wsgi_application
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory, override_settings
from django.urls import clear_url_caches, include, path, re_path
from django.urls.resolvers import URLPattern, URLResolver
from django.utils.decorators import method_decorator
from django.views import View
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityDecorator
from djangoapi_guard._declared_path_params import check_declared_path_params
from djangoapi_guard.middleware import DjangoAPIGuard

LOGGER = "guard_core.models"
URLCONF = "wp718_urls"
Patterns = list[URLPattern | URLResolver]
Build = Callable[[SecurityDecorator], Patterns]


def _missing(template: str, name: str = "ghost") -> str:
    return (
        f"declares {name!r}, which is not in the route template {template!r}, so it "
        "exempts nothing."
    )


def _rootless(template: str, name: str = "tail") -> str:
    return (
        f"declares {name!r}, which has no literal segment before it in the route "
        f"template {template!r}: it would exempt the whole path from the probe rows, "
        "so the whole path is scanned."
    )


def _new_view() -> Callable[..., JsonResponse]:
    def view(request: HttpRequest, *args: str, **kwargs: str) -> JsonResponse:
        return JsonResponse({})

    return view


def build_missing(decorator: SecurityDecorator) -> Patterns:
    view = decorator.detection_exclusion(path_params={"ghost"})(_new_view())
    return [path("items/<int:pk>/", view)]


def build_rootless(decorator: SecurityDecorator) -> Patterns:
    view = decorator.detection_exclusion(path_params={"tail"})(_new_view())
    return [path("<path:tail>", view)]


def build_regex_groups(decorator: SecurityDecorator) -> Patterns:
    view = decorator.detection_exclusion(path_params={"ghost"})(_new_view())
    return [re_path(r"^named/(?P<year>[0-9]{4})/$", view)]


def build_positional_group(decorator: SecurityDecorator) -> Patterns:
    view = decorator.detection_exclusion(path_params={"ghost"})(_new_view())
    return [re_path(r"^pos/([0-9]+)/$", view)]


def build_nested_include(decorator: SecurityDecorator) -> Patterns:
    view = decorator.detection_exclusion(path_params={"ghost"})(_new_view())
    inner = [path("things/<slug:thing>/", view)]
    return [path("orgs/<int:org>/", include([path("teams/", include(inner))]))]


def build_class_based(decorator: SecurityDecorator) -> Patterns:
    class Things(View):
        @method_decorator(decorator.detection_exclusion(path_params={"ghost"}))
        def get(self, request: HttpRequest, *args: str, **kwargs: str) -> JsonResponse:
            return JsonResponse({})

    return [path("things/<slug:thing>/", Things.as_view())]


def build_one_view_on_two_routes(decorator: SecurityDecorator) -> Patterns:
    view = decorator.detection_exclusion(path_params={"ghost"})(_new_view())
    return [path("a/<str:x>/", view), path("b/<str:y>/", view)]


def build_valid(decorator: SecurityDecorator) -> Patterns:
    view = decorator.detection_exclusion(path_params={"pk"})(_new_view())
    return [path("items/<int:pk>/", view)]


def build_unguarded_and_empty(decorator: SecurityDecorator) -> Patterns:
    other = decorator.detection_exclusion(headers={"x-trace"})(_new_view())
    return [path("plain/<str:x>/", _new_view()), path("headers/<str:y>/", other)]


CASES = [
    (build_missing, "/items/7/", _missing("items/<int:pk>/")),
    (build_rootless, "/anything", _rootless("<path:tail>")),
    (build_regex_groups, "/named/2026/", _missing("^named/(?P<year>[0-9]{4})/$")),
    (build_positional_group, "/pos/7/", _missing("^pos/([0-9]+)/$")),
    (
        build_nested_include,
        "/orgs/5/teams/things/x/",
        _missing("orgs/<int:org>/teams/things/<slug:thing>/"),
    ),
    (build_class_based, "/things/x/", _missing("things/<slug:thing>/")),
]


def _config(flag: bool) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False, rate_limit=100000, fail_on_misconfiguration=flag
    )


@contextmanager
def serving(build: Build, flag: bool = True) -> Iterator[SecurityDecorator]:
    config = _config(flag)
    decorator = SecurityDecorator(config)
    module = types.ModuleType(URLCONF)
    module.__dict__["urlpatterns"] = build(decorator)
    sys.modules[URLCONF] = module
    clear_url_caches()
    try:
        with override_settings(
            ROOT_URLCONF=URLCONF,
            GUARD_SECURITY_CONFIG=config,
            GUARD_DECORATOR=decorator,
            INSTALLED_APPS=[*settings.INSTALLED_APPS, "djangoapi_guard"],
        ):
            yield decorator
    finally:
        del sys.modules[URLCONF]
        clear_url_caches()


def _problems(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and "@detection_exclusion" in r.getMessage()
    ]


@pytest.mark.parametrize(("build", "path_", "tail"), CASES)
def test_manage_py_check_fails_on_a_problem(
    build: Build, path_: str, tail: str
) -> None:
    with serving(build):
        with pytest.raises(SystemCheckError) as failure:
            call_command("check", stdout=StringIO(), stderr=StringIO())

    assert "djangoapi_guard.E001" in str(failure.value)
    assert tail in str(failure.value).replace("\n", " ")


@pytest.mark.parametrize(("build", "path_", "tail"), CASES)
def test_the_check_is_a_warning_with_the_flag_off(
    build: Build, path_: str, tail: str
) -> None:
    with serving(build, flag=False):
        messages = check_declared_path_params()
        call_command("check", stdout=StringIO(), stderr=StringIO())

    assert [message.id for message in messages] == ["djangoapi_guard.W001"]
    assert tail in messages[0].msg


def test_one_view_on_two_routes_is_checked_per_route() -> None:
    with serving(build_one_view_on_two_routes):
        messages = check_declared_path_params()

    assert [message.id for message in messages] == ["djangoapi_guard.E001"] * 2
    assert any(_missing("a/<str:x>/") in message.msg for message in messages)
    assert any(_missing("b/<str:y>/") in message.msg for message in messages)


@pytest.mark.parametrize("build", [build_valid, build_unguarded_and_empty])
def test_a_sound_declaration_passes_the_check(build: Build) -> None:
    with serving(build):
        assert check_declared_path_params() == []
        call_command("check", stdout=StringIO(), stderr=StringIO())


@pytest.mark.parametrize(("build", "path_", "tail"), CASES)
def test_the_boot_fails_with_the_flag_on(build: Build, path_: str, tail: str) -> None:
    with serving(build, True):
        with pytest.raises(ValueError) as failure:
            get_wsgi_application()

    assert tail in str(failure.value)
    assert "Set fail_on_misconfiguration=False to start with it anyway." in str(
        failure.value
    )


@pytest.mark.parametrize("with_the_app", [True, False])
@pytest.mark.parametrize(("build", "path_", "tail"), CASES)
def test_the_boot_warns_once_with_the_flag_off_and_requests_do_not_repeat_it(
    with_the_app: bool,
    build: Build,
    path_: str,
    tail: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    with serving(build, False):
        apps = [app for app in settings.INSTALLED_APPS if app != "djangoapi_guard"]
        with override_settings(
            INSTALLED_APPS=[*apps, *(["djangoapi_guard"] if with_the_app else [])]
        ):
            application = get_wsgi_application()
            for _ in range(2):
                response = application.get_response(RequestFactory().get(path_))
                assert response.status_code == 200

    (problem,) = _problems(caplog)
    assert tail in problem
    assert "fail_on_misconfiguration=False keeps starting with it." in problem


@pytest.mark.parametrize(("build", "path_", "tail"), CASES)
def test_a_decorator_set_after_the_boot_warns_once_at_the_first_request(
    build: Build,
    path_: str,
    tail: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    with serving(build, False) as decorator:
        monkeypatch.setattr(
            "djangoapi_guard.middleware.resolve_decorator", lambda: None
        )
        middleware = DjangoAPIGuard(lambda request: HttpResponse("OK"))
        middleware.set_decorator_handler(decorator)
        for _ in range(2):
            assert middleware(RequestFactory().get(path_)).status_code == 200

    (problem,) = _problems(caplog)
    assert tail in problem


def test_an_ambiguous_decorator_is_left_to_the_middleware_to_refuse() -> None:
    config = _config(True)
    decorators = [SecurityDecorator(config), SecurityDecorator(config)]

    with override_settings(GUARD_DECORATOR=None):
        assert check_declared_path_params() == []

    assert len(decorators) == 2
