import importlib
import sys
import time
from pathlib import Path

import pytest
from django.test import Client, override_settings
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityConfig
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
EXAMPLE_PROJECTS = {
    "simple": ("example_project", "example_app"),
    "advanced": ("advanced_project", "advanced_app"),
}
GUARD_MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
]
BANNED_IP = "203.0.113.5"
WINDOWED_IP = "203.0.113.6"


def _load_example(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> tuple[SecurityConfig[SyncGuardRequest], str]:
    project, app_package = EXAMPLE_PROJECTS[name]
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("REDIS_PREFIX", REDIS_PREFIX)
    monkeypatch.syspath_prepend(str(EXAMPLES / name))
    for loaded in [m for m in sys.modules if m.split(".")[0] in (project, app_package)]:
        monkeypatch.delitem(sys.modules, loaded)
    config = importlib.import_module(f"{project}.settings").GUARD_SECURITY_CONFIG
    return config, f"{project}.urls"


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_clear_cache_route_drops_the_bans_and_the_rate_windows(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    assert config.redis_prefix != "djangoapi_guard:"
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        client = Client(REMOTE_ADDR="127.0.0.1")
        client.get("/")
        bans = ip_ban_manager_for(config)
        windows = RateLimitManager(config)
        bans.ban_ip(BANNED_IP, 300, "test")
        windows.request_timestamps[WINDOWED_IP].append(time.time())
        assert bans.is_ip_banned(BANNED_IP)
        assert windows.request_timestamps[WINDOWED_IP]

        response = client.post("/admin/clear-cache")

        assert response.status_code == 200
        assert not bans.is_ip_banned(BANNED_IP)
        assert not windows.request_timestamps.get(WINDOWED_IP)
        assert b"geo_cache" not in response.content


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_clear_cache_route_stays_behind_the_localhost_gate(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        response = Client(REMOTE_ADDR="203.0.113.5").post("/admin/clear-cache")
    assert response.status_code == 403
