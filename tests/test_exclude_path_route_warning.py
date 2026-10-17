import logging
from collections.abc import Iterator

import pytest
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from guard_core.models import SecurityConfig

from djangoapi_guard.middleware import DjangoAPIGuard

URLCONF = override_settings(
    ROOT_URLCONF="tests.urls_exclude_prefixes",
    USE_I18N=True,
    LANGUAGE_CODE="en",
    LANGUAGES=[("en", "English"), ("fr", "French")],
)


@pytest.fixture(autouse=True)
def _urlconf() -> Iterator[None]:
    with URLCONF:
        yield


def _middleware(entries: list[str]) -> DjangoAPIGuard:
    import django.conf

    django.conf.settings.GUARD_SECURITY_CONFIG = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        exclude_paths=entries,
        ban_on_hostile_signals=False,
    )
    return DjangoAPIGuard(lambda request: HttpResponse("OK"))


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and "exclude_paths entry" in r.getMessage()
    ]


def _typo(entry: str) -> str:
    return (
        f"exclude_paths entry {entry!r} matches no registered route; check it for "
        "a typo."
    )


def test_only_a_typo_entry_warns_once_on_a_real_urlconf(
    caplog: pytest.LogCaptureFixture,
) -> None:
    entries = [
        "/docs",
        "/health",
        "/items",
        "/items/7",
        "/admin",
        "/admin/panel",
        "/admin/typo",
        "/en/account",
        "/fr/account",
        "/static",
        "/typo",
    ]
    middleware = _middleware(entries)
    factory = RequestFactory()
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(3):
            middleware(factory.get("/health"))

    assert _warnings(caplog) == [_typo("/admin/typo"), _typo("/typo")]


def test_the_prefixes_list_every_pattern_head_through_include() -> None:
    prefixes = _middleware([]).static_route_prefixes()

    assert set(prefixes) == {
        "/health",
        "/items/",
        "/admin/panel",
        "/en/account",
        "/fr/account",
    }
