import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from django.test import Client, override_settings
from django.urls import clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import djangoapi_guard._decorator_adoption as adoption
from tests.geo_database import CLIENT_IP, country_database_bytes

URLCONF = "tests.country_rule_urls"


@pytest.fixture(autouse=True)
def _isolated() -> Iterator[None]:
    adoption._created.clear()
    IPInfoManager._instance = None
    yield
    adoption._created.clear()
    IPInfoManager._instance = None


def _config(
    tmp_path: Path, blocked_countries: frozenset[str] = frozenset()
) -> SecurityConfig[SyncGuardRequest]:
    db_path = tmp_path / "geo.mmdb"
    db_path.write_bytes(country_database_bytes("CN"))
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        ban_on_hostile_signals=False,
        ipinfo_token="tok",
        ipinfo_db_path=db_path,
        lazy_init=False,
        blocked_countries=blocked_countries,
    )


@contextmanager
def _served(config: SecurityConfig[SyncGuardRequest]) -> Iterator[Client]:
    sys.modules.pop(URLCONF, None)
    clear_url_caches()
    try:
        with override_settings(ROOT_URLCONF=URLCONF, GUARD_SECURITY_CONFIG=config):
            yield Client(REMOTE_ADDR=CLIENT_IP)
    finally:
        sys.modules.pop(URLCONF, None)
        clear_url_caches()


def test_global_blocked_countries_from_the_token_block_on_the_sync_engine(
    tmp_path: Path,
) -> None:
    with _served(_config(tmp_path, blocked_countries=frozenset({"CN"}))) as client:
        assert client.get("/open").status_code == 403


def test_route_block_countries_blocks_without_a_global_country_rule(
    tmp_path: Path,
) -> None:
    with _served(_config(tmp_path)) as client:
        assert client.get("/blocked").status_code == 403
        assert client.get("/open").status_code == 200
