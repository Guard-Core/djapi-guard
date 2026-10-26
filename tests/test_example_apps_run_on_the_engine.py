import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from django.test import Client, override_settings
from django.urls import URLPattern, URLResolver
from django.urls.resolvers import RoutePattern
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityConfig
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BLOCKED_COUNTRY_IP = "10.0.0.5"
ALLOWED_COUNTRY_IP = "10.0.0.6"
EXAMPLE_PROJECTS = {
    "simple": ("example_project", ("example_app",)),
    "advanced": ("advanced_project", ("advanced_app",)),
}
GUARD_MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
]


class _CountryStubGeoIPHandler:
    def __init__(
        self,
        token: str,
        db_path: Path | None = None,
        max_age: int = 86400,
        download_url: str | None = None,
    ) -> None:
        self.is_initialized = True

    def initialize(self) -> None:
        return

    def initialize_redis(self, redis_handler: object) -> None:
        return

    def initialize_agent(self, agent_handler: object) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return "CN" if ip == BLOCKED_COUNTRY_IP else "US"

    def refresh(self) -> None:
        return

    def close(self) -> None:
        return


def _documented_paths(patterns: list[URLPattern | URLResolver]) -> Iterator[str]:
    for entry in patterns:
        assert isinstance(entry.pattern, RoutePattern)
        route = str(entry.pattern)
        if isinstance(entry, URLResolver):
            for nested in _documented_paths(entry.url_patterns):
                yield route + nested
        elif "<" not in route:
            yield route


def _first_answer_status(client: Client, path: str) -> int:
    for method in (client.get, client.post, client.put):
        status = method(path).status_code
        if status != 405:
            return status
    return 405


def _load_example(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> tuple[SecurityConfig[SyncGuardRequest], str]:
    project, app_packages = EXAMPLE_PROJECTS[name]
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("REDIS_PREFIX", REDIS_PREFIX)
    monkeypatch.setattr(
        "guard_core.sync.handlers.ipinfo_handler.IPInfoManager",
        _CountryStubGeoIPHandler,
    )
    monkeypatch.syspath_prepend(str(EXAMPLES / name))
    for loaded in [
        m for m in sys.modules if m.split(".")[0] in (project, *app_packages)
    ]:
        monkeypatch.delitem(sys.modules, loaded)
    config = importlib.import_module(f"{project}.settings").GUARD_SECURITY_CONFIG
    config.enable_ip_banning = False
    config.rate_limit = 100000
    return config, f"{project}.urls"


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_every_documented_example_route_answers_without_a_server_error(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        client = Client(REMOTE_ADDR=ALLOWED_COUNTRY_IP, raise_request_exception=False)
        patterns = importlib.import_module(urlconf).urlpatterns
        answers = {
            path: _first_answer_status(client, "/" + path)
            for path in _documented_paths(patterns)
        }
    assert answers
    assert {path: code for path, code in answers.items() if code >= 500} == {}


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_example_country_block_route_blocks_the_blocked_country_only(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        blocked = Client(REMOTE_ADDR=BLOCKED_COUNTRY_IP).get("/access/country-block")
        allowed = Client(REMOTE_ADDR=ALLOWED_COUNTRY_IP).get("/access/country-block")
    assert (blocked.status_code, allowed.status_code) == (403, 200)
