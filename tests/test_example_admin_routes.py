import importlib
import json
import sys
import time
from pathlib import Path
from typing import Any

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


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_unban_route_lifts_the_ban_it_names(
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
        bans.ban_ip(BANNED_IP, 300, "test")
        assert bans.is_ip_banned(BANNED_IP)

        response = client.post(
            "/admin/unban-ip", {"ip": BANNED_IP}, content_type="application/json"
        )

        assert response.status_code == 200
        assert not bans.is_ip_banned(BANNED_IP)
        assert response.json()["details"]["ip"] == BANNED_IP


@pytest.mark.parametrize("garbage", ["not-an-ip", "203.0.113.0/24", "", "1.2.3.999"])
@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_unban_route_refuses_input_that_is_not_an_ip(
    name: str, garbage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        response = Client(REMOTE_ADDR="127.0.0.1").post(
            "/admin/unban-ip", {"ip": garbage}, content_type="application/json"
        )
    assert response.status_code == 400


def _put(client: Client, body: object) -> Any:
    return client.put(
        "/admin/emergency-mode", json.dumps(body), content_type="application/json"
    )


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_emergency_switch_refuses_outsiders_and_keeps_the_admin(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        admin = Client(REMOTE_ADDR="127.0.0.1")
        outsider = Client(REMOTE_ADDR="10.0.0.6")
        assert outsider.get("/").status_code == 200

        on = _put(admin, {"enable": True})
        assert on.status_code == 200
        assert on.json()["details"]["emergency_mode"] is True
        assert config.emergency_mode is True
        assert outsider.get("/").status_code == 503
        assert admin.get("/").status_code == 200

        off = _put(admin, {"enable": False})
        assert off.json()["details"]["emergency_mode"] is False
        assert outsider.get("/").status_code == 200
        assert admin.get("/").status_code == 200


@pytest.mark.parametrize("body", [{"enable": "yes"}, {"enable": 1}, {}, [True]])
@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_emergency_switch_refuses_a_body_that_is_not_a_boolean(
    name: str, body: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        response = _put(Client(REMOTE_ADDR="127.0.0.1"), body)
    assert response.status_code == 400
    assert config.emergency_mode is False


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_emergency_switch_defers_to_the_dashboard_when_dynamic_rules_are_on(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    config.agent_api_key = "test-key-0123456789"
    config.enable_agent = True
    config.enable_dynamic_rules = True
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        response = _put(Client(REMOTE_ADDR="127.0.0.1"), {"enable": True})
    assert response.status_code == 409
    assert b"dashboard" in response.content
    assert config.emergency_mode is False


def _stats(client: Client) -> dict[str, Any]:
    body = client.get("/admin/stats").json()
    payload: dict[str, Any] = body.get("details", body)
    return payload


@pytest.mark.parametrize("name", EXAMPLE_PROJECTS)
def test_stats_come_from_the_engine_and_carry_no_invented_numbers(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, urlconf = _load_example(name, monkeypatch)
    with override_settings(
        ROOT_URLCONF=urlconf, GUARD_SECURITY_CONFIG=config, MIDDLEWARE=GUARD_MIDDLEWARE
    ):
        client = Client(REMOTE_ADDR="127.0.0.1")
        client.get("/")
        bans = ip_ban_manager_for(config)
        before = _stats(client)
        bans.ban_ip(BANNED_IP, 300, "test")
        after = _stats(client)
        bans.unban_ip(BANNED_IP)
        lifted = _stats(client)

    assert BANNED_IP not in before["banned_ips"]
    assert BANNED_IP in after["banned_ips"]
    assert BANNED_IP not in lifted["banned_ips"]
    assert not {"total_requests", "blocked_requests", "suspicious_activities"} & set(
        after
    )
    assert after["active_rules"]["rate_limit"] == config.rate_limit
