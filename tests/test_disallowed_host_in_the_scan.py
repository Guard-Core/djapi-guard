import logging

import pytest
from django.http import HttpRequest, HttpResponse
from django.urls import path

from djangoapi_guard.adapters import DjangoGuardRequest
from tests.wsgi_sweep_support import config, served


def index(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


def test_a_host_django_disallows_does_not_raise_inside_the_scan(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with served(
        [path("", index)],
        config(enable_penetration_detection=True),
        ALLOWED_HOSTS=["example.com"],
    ) as client:
        with caplog.at_level(logging.ERROR):
            response = client.get(
                "/?q=<script>alert(1)</script>", HTTP_HOST="evil.invalid"
            )

    assert response.status_code == 400
    assert not [m for m in caplog.messages if "DisallowedHost" in m]


def test_url_full_of_a_disallowed_host_carries_the_host_as_it_arrived() -> None:
    from django.test import RequestFactory, override_settings

    with override_settings(ALLOWED_HOSTS=["example.com"]):
        request = RequestFactory().get("/?q=1", HTTP_HOST="evil.invalid")
        guard_request = DjangoGuardRequest(request)

        assert guard_request.url_full == "http://evil.invalid/?q=1"
