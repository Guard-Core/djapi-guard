import sys

import pytest
from django.test import Client, RequestFactory, override_settings
from django.urls import clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.adapters import DjangoGuardRequest

CLIENT = "1.2.3.4"


def test_the_guard_request_path_is_the_path_without_the_script_prefix() -> None:
    request = RequestFactory().get("/hello/", SCRIPT_NAME="/app")

    assert request.path == "/app/hello/"
    assert DjangoGuardRequest(request).url_path == "/hello/"


@pytest.mark.parametrize("script_name", ["", "/app"])
def test_a_decorator_route_is_enforced_under_a_script_prefix(script_name: str) -> None:
    sys.modules.pop("tests.script_prefix_urls", None)
    clear_url_caches()
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_ip_banning=False,
        rate_limit=100000,
    )
    try:
        with override_settings(
            ROOT_URLCONF="tests.script_prefix_urls", GUARD_SECURITY_CONFIG=config
        ):
            response = Client(REMOTE_ADDR=CLIENT).get(
                "/admin-only/", SCRIPT_NAME=script_name
            )
    finally:
        sys.modules.pop("tests.script_prefix_urls", None)
        clear_url_caches()

    assert response.status_code == 403
