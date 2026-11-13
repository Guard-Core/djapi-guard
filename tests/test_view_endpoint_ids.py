import functools
from typing import Any

import pytest
from django.http import HttpRequest, HttpResponse
from django.urls import path
from django.views import View

from djangoapi_guard import SecurityDecorator
from tests.wsgi_sweep_support import config, served

PEER = "203.0.113.9"


def show(request: HttpRequest, tag: str = "") -> HttpResponse:
    return HttpResponse(str(request.__dict__["guard_endpoint_id"]))


class Callable_:
    def __call__(self, request: HttpRequest) -> HttpResponse:
        return show(request)


class FirstView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        return show(request)


class SecondView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        return show(request)


def test_a_plain_function_keeps_its_module_and_qualname_id() -> None:
    with served([path("f/", show)], config()) as client:
        assert (
            client.get("/f/", REMOTE_ADDR=PEER).content
            == f"{show.__module__}.show".encode()
        )


def test_an_undecorated_partial_does_not_crash() -> None:
    patterns = [path("p/", functools.partial(show, tag="a"))]
    with served(patterns, config()) as client:
        response = client.get("/p/", REMOTE_ADDR=PEER)

    assert (response.status_code, response.content) == (200, b"functools.partial@p/")


def test_an_undecorated_callable_instance_does_not_crash() -> None:
    with served([path("c/", Callable_())], config()) as client:
        response = client.get("/c/", REMOTE_ADDR=PEER)

    expected = f"{Callable_.__module__}.Callable_@c/".encode()
    assert (response.status_code, response.content) == (200, expected)


def test_two_partials_of_one_function_get_distinct_ids() -> None:
    patterns = [
        path("a/", functools.partial(show, tag="a")),
        path("b/", functools.partial(show, tag="b")),
    ]
    with served(patterns, config()) as client:
        first = client.get("/a/", REMOTE_ADDR=PEER).content
        second = client.get("/b/", REMOTE_ADDR=PEER).content

    assert first != second


@pytest.mark.parametrize("make", [lambda: functools.partial(show, tag="a"), Callable_])
def test_a_stamped_callable_uses_the_id_the_engine_stamped(make: Any) -> None:
    guard_config = config()
    decorator = SecurityDecorator(guard_config)
    view = decorator.rate_limit(requests=100, window=60)(make())
    with served([path("s/", view)], guard_config) as client:
        content = client.get("/s/", REMOTE_ADDR=PEER).content

    assert content.decode() == vars(view)["_guard_route_id"]


def test_two_stamped_partials_of_one_function_get_distinct_ids() -> None:
    guard_config = config()
    decorator = SecurityDecorator(guard_config)
    first = decorator.rate_limit(requests=100, window=60)(functools.partial(show))
    second = decorator.rate_limit(requests=100, window=60)(functools.partial(show))
    with served([path("a/", first), path("b/", second)], guard_config) as client:
        one = client.get("/a/", REMOTE_ADDR=PEER).content
        two = client.get("/b/", REMOTE_ADDR=PEER).content

    assert one != two


def test_class_based_views_are_named_after_their_class() -> None:
    patterns = [path("one/", FirstView.as_view()), path("two/", SecondView.as_view())]
    with served(patterns, config()) as client:
        one = client.get("/one/", REMOTE_ADDR=PEER).content
        two = client.get("/two/", REMOTE_ADDR=PEER).content

    assert (one, two) == (
        f"{FirstView.__module__}.FirstView".encode(),
        f"{SecondView.__module__}.SecondView".encode(),
    )
