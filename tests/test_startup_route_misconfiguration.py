import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import override_settings
from django.urls import clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import djangoapi_guard._decorator_adoption as adoption
from djangoapi_guard import DjangoAPIGuard

COUNTRY_URLCONF = "tests.country_rule_urls"
TWO_CONFIG_URLCONF = "tests.country_rule_two_config_urls"


@pytest.fixture(autouse=True)
def _isolated() -> Iterator[None]:
    adoption._created.clear()
    yield
    adoption._created.clear()


def _config(
    ipinfo_token: str | None = None, fail_on_misconfiguration: bool = True
) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        ban_on_hostile_signals=False,
        ipinfo_token=ipinfo_token,
        fail_on_misconfiguration=fail_on_misconfiguration,
    )


def _ok(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


@contextmanager
def _settings(urlconf: str, config: SecurityConfig[SyncGuardRequest]) -> Iterator[None]:
    sys.modules.pop(urlconf, None)
    clear_url_caches()
    try:
        with override_settings(ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config):
            yield
    finally:
        sys.modules.pop(urlconf, None)
        clear_url_caches()


def test_a_country_rule_without_a_geo_source_refuses_to_start() -> None:
    with _settings(COUNTRY_URLCONF, _config()):
        with pytest.raises(ValueError, match="no GeoIP database is configured"):
            DjangoAPIGuard(_ok)


def test_the_two_config_case_refuses_to_start() -> None:
    with _settings(TWO_CONFIG_URLCONF, _config(ipinfo_token="tok")):
        with pytest.raises(ValueError, match="no GeoIP database is configured"):
            DjangoAPIGuard(_ok)


def test_false_starts_and_warns_once_at_startup(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _settings(COUNTRY_URLCONF, _config(fail_on_misconfiguration=False)):
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            guard = DjangoAPIGuard(_ok)
            assert caplog.text.count("no GeoIP database") == 1
            guard(_request())
            guard(_request())

    assert caplog.text.count("no GeoIP database") == 1


def test_a_token_means_no_report_and_the_app_starts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _settings(COUNTRY_URLCONF, _config(ipinfo_token="tok")):
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            DjangoAPIGuard(_ok)

    assert "no GeoIP database" not in caplog.text


def _request() -> HttpRequest:
    from django.test import RequestFactory

    return RequestFactory().get("/open", REMOTE_ADDR="198.51.100.9")
