import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig

from djangoapi_guard.middleware import DjangoAPIGuard

ORIGIN = "https://app.example.com"


def _middleware(app_vary: str | None) -> DjangoAPIGuard:
    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=[ORIGIN],
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
    )

    def get_response(request: HttpRequest) -> HttpResponse:
        response = HttpResponse("ok")
        if app_vary is not None:
            response["Vary"] = app_vary
        return response

    return DjangoAPIGuard(get_response)


@pytest.mark.parametrize(
    ("app_vary", "expected"),
    [
        (None, "Origin"),
        ("Accept-Encoding", "Accept-Encoding, Origin"),
        ("Accept-Encoding, Cookie", "Accept-Encoding, Cookie, Origin"),
        ("origin", "origin"),
        ("*", "*"),
    ],
)
def test_cors_vary_is_merged_into_the_vary_of_the_application(
    app_vary: str | None, expected: str
) -> None:
    request = RequestFactory().get("/", HTTP_ORIGIN=ORIGIN)

    response = _middleware(app_vary)(request)

    assert response["Vary"] == expected
