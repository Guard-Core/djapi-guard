import functools
from collections.abc import Callable
from typing import Any

from django.conf.urls.i18n import i18n_patterns
from django.http import HttpRequest, HttpResponse
from django.urls import path, re_path
from django.views import View


def login(request: HttpRequest) -> HttpResponse:
    return HttpResponse("login")


def user(request: HttpRequest, user_id: int) -> HttpResponse:
    return HttpResponse(f"user {user_id}")


def account(request: HttpRequest) -> HttpResponse:
    return HttpResponse("account")


def plain(request: HttpRequest) -> HttpResponse:
    return HttpResponse("plain")


class Panel(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse("panel")


def wrapped(view: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    @functools.wraps(view)
    def inner(*args: Any, **kwargs: Any) -> HttpResponse:
        return view(*args, **kwargs)

    return inner


urlpatterns = [
    re_path(r"^login/?$", login),
    path("users/<int:user_id>/", user),
    path("panel/", Panel.as_view()),
    path("wrapped/", wrapped(plain)),
    *i18n_patterns(path("account/", account)),
]
