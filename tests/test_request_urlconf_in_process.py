"""The per-request urlconf reads, in this process (the fresh-process pins in
test_request_urlconf_reads.py prove the cold start; these cover the same branches
under the coverage gate)."""

import logging
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import clear_url_caches
from guard_core._security_config_fields import DEFAULT_EXCLUDE_PATHS
from guard_core.exceptions import MisconfigurationError
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import djangoapi_guard._decorator_adoption as adoption
from djangoapi_guard import SecurityDecorator
from djangoapi_guard._declared_path_params import check_declared_path_params
from djangoapi_guard.middleware import DjangoAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

ROOT = "wp_inproc_root"
HOST = "wp_inproc_host"
OTHER = "wp_inproc_other"
_NAMES = (ROOT, HOST, OTHER)


def _config(**fields: Any) -> SecurityConfig[SyncGuardRequest]:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "ban_on_hostile_signals": False,
    }
    return SecurityConfig[SyncGuardRequest](**{**defaults, **fields})


PLAIN = "from django.http import HttpResponse\nfrom django.urls import path\n"
DECORATOR = (
    "from django.conf import settings\n"
    "from djangoapi_guard import SecurityDecorator\n"
    "guard_deco = SecurityDecorator(settings.GUARD_SECURITY_CONFIG)\n"
)
VIEW = "def view(request):\n    return HttpResponse('ok')\n"
GUARDED = '@guard_deco.require_headers({"X-Need": "required"})\n' + VIEW
PLAIN_ROUTES = {
    "root": PLAIN + VIEW + "urlpatterns = [path('hello/', view)]\n",
    "host": PLAIN + VIEW + "urlpatterns = [path('admin/', view)]\n",
    "other": PLAIN + VIEW + "urlpatterns = [path('other/', view)]\n",
}
ROOT_GUARDED = PLAIN + DECORATOR + GUARDED + "urlpatterns = [path('hello/', view)]\n"
ROOT_DECORATOR_ONLY = (
    PLAIN + DECORATOR + VIEW + "urlpatterns = [path('hello/', view)]\n"
)
HOST_GUARDED = PLAIN + DECORATOR + GUARDED + "urlpatterns = [path('admin/', view)]\n"
HOST_TWO_DECORATORS = (
    PLAIN
    + DECORATOR
    + "second = SecurityDecorator(settings.GUARD_SECURITY_CONFIG)\n"
    + VIEW
    + "urlpatterns = [path('admin/', view)]\n"
)
HOST_OWN_DECLARING = (
    PLAIN
    + DECORATOR
    + "@guard_deco.detection_exclusion(path_params={'{name}'})\n"
    + "def view(request, item_id):\n    return HttpResponse('ok')\n"
    + "urlpatterns = [path('item/<str:item_id>/', view)]\n"
)
HOST_DECLARING = (
    PLAIN
    + "from wp_inproc_root import guard_deco\n"
    + "@guard_deco.detection_exclusion(path_params={'{name}'})\n"
    + "def view(request, item_id):\n    return HttpResponse('ok')\n"
    + "urlpatterns = [path('item/<str:item_id>/', view)]\n"
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path) -> Iterator[None]:
    adoption._created.clear()
    sys.path.insert(0, str(tmp_path))
    clear_url_caches()
    yield
    sys.path.remove(str(tmp_path))
    for name in _NAMES:
        sys.modules.pop(name, None)
    clear_url_caches()
    adoption._created.clear()
    rate_limit_handler(_config()).reset()


@pytest.fixture
def write(tmp_path: Path) -> Callable[[str, str], None]:
    def write_module(name: str, source: str) -> None:
        (tmp_path / f"{name}.py").write_text(source)

    return write_module


def _guard(config: SecurityConfig[SyncGuardRequest], **extra: Any) -> DjangoAPIGuard:
    with override_settings(ROOT_URLCONF=ROOT, GUARD_SECURITY_CONFIG=config, **extra):
        guard = DjangoAPIGuard(lambda request: HttpResponse("ok"))
    return guard


def _call(
    guard: DjangoAPIGuard,
    target: str,
    urlconf: str | None = None,
    *,
    config: SecurityConfig[SyncGuardRequest],
    need: bool = False,
    extra: dict[str, Any] | None = None,
) -> int:
    request = RequestFactory().get(target, headers={"X-Need": "1"} if need else None)
    if urlconf is not None:
        request.urlconf = urlconf
    with override_settings(
        ROOT_URLCONF=ROOT, GUARD_SECURITY_CONFIG=config, **(extra or {})
    ):
        return guard(request).status_code


def _decorator_of(guard: DjangoAPIGuard) -> object:
    return guard.guard_decorator


def _geo_of(guard: DjangoAPIGuard) -> object:
    return guard.geo_ip_handler


def _hints(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        m for m in (r.getMessage() for r in caplog.records) if "GUARD_URLCONFS" in m
    ]


def test_the_decorator_of_a_urlconf_first_read_by_a_request_is_adopted(
    write: Callable[[str, str], None],
) -> None:
    config = _config()
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, HOST_GUARDED)
    guard = _guard(config)

    assert _decorator_of(guard) is None
    assert _call(guard, "/admin/", HOST, config=config) == 400
    assert _decorator_of(guard) is not None
    assert _call(guard, "/admin/", HOST, config=config, need=True) == 200
    assert _call(guard, "/hello/", config=config) == 200


def test_a_second_decorator_refuses_every_request_while_the_flag_is_on(
    write: Callable[[str, str], None],
) -> None:
    config = _config(fail_on_misconfiguration=True)
    write(ROOT, ROOT_GUARDED)
    write(HOST, HOST_GUARDED)
    guard = _guard(config)

    assert _call(guard, "/hello/", config=config) == 400
    for target, urlconf in (("/admin/", HOST), ("/hello/", None), ("/admin/", HOST)):
        with pytest.raises(ImproperlyConfigured, match="share one decorator"):
            _call(guard, target, urlconf, config=config)


def test_a_second_decorator_without_the_flag_logs_once_and_serves(
    write: Callable[[str, str], None], caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(fail_on_misconfiguration=False)
    write(ROOT, ROOT_GUARDED)
    write(HOST, HOST_GUARDED)
    guard = _guard(config)

    with caplog.at_level(logging.ERROR):
        assert _call(guard, "/admin/", HOST, config=config) == 200
        assert _call(guard, "/admin/", HOST, config=config) == 200
    ambiguous = [r for r in caplog.records if "instances are registered" in r.message]
    assert len(ambiguous) == 1
    assert "keeps serving" in ambiguous[0].message


def test_two_decorators_in_one_late_urlconf_refuse_with_none_adopted(
    write: Callable[[str, str], None],
) -> None:
    config = _config(fail_on_misconfiguration=True)
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, HOST_TWO_DECORATORS)
    guard = _guard(config)

    assert _call(guard, "/hello/", config=config) == 200
    with pytest.raises(ImproperlyConfigured):
        _call(guard, "/admin/", HOST, config=config)
    assert guard.guard_decorator is None
    with pytest.raises(ImproperlyConfigured):
        _call(guard, "/hello/", config=config)


def test_a_decorator_set_by_the_call_is_not_refused_for_a_second_one(
    write: Callable[[str, str], None],
) -> None:
    config = _config(fail_on_misconfiguration=True)
    write(ROOT, ROOT_GUARDED)
    write(HOST, HOST_GUARDED)
    guard = _guard(config)
    chosen = sys.modules[ROOT].guard_deco
    guard.set_decorator_handler(chosen)

    assert _call(guard, "/admin/", HOST, config=config) == 200
    assert guard.guard_decorator is chosen


def test_a_decorator_named_by_the_setting_is_not_refused_for_a_second_one(
    write: Callable[[str, str], None],
) -> None:
    config = _config(fail_on_misconfiguration=True)
    write(ROOT, ROOT_GUARDED)
    write(HOST, HOST_GUARDED)
    setting = {"GUARD_DECORATOR": f"{ROOT}.guard_deco"}
    guard = _guard(config, **setting)

    assert _call(guard, "/admin/", HOST, config=config, extra=setting) == 200
    assert guard.guard_decorator is sys.modules[ROOT].guard_deco


def test_the_root_urlconf_and_a_listed_one_are_not_named_as_unlisted(
    write: Callable[[str, str], None], caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(exclude_paths=["/admin"])
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, PLAIN_ROUTES["host"])
    listed = {"GUARD_URLCONFS": [HOST]}
    guard = _guard(config, **listed)

    with caplog.at_level(logging.WARNING):
        assert _call(guard, "/hello/", ROOT, config=config, extra=listed) == 200
        assert _call(guard, "/admin/", HOST, config=config, extra=listed) == 200
    assert _hints(caplog) == []


def test_an_unlisted_urlconf_is_named_once_each_with_what_the_checks_missed(
    write: Callable[[str, str], None], caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(exclude_paths=["/admin", "/other"])
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, PLAIN_ROUTES["host"])
    write(OTHER, PLAIN_ROUTES["other"])
    guard = _guard(config)

    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            _call(guard, "/admin/", HOST, config=config)
            _call(guard, "/other/", OTHER, config=config)
    hints = _hints(caplog)
    assert len(hints) == 2
    assert HOST in hints[0]
    assert OTHER in hints[1]
    assert "the exclude_paths route check" in hints[0]
    assert "path_params" not in hints[0]


def test_an_unlisted_urlconf_declaring_path_params_is_named(
    write: Callable[[str, str], None], caplog: pytest.LogCaptureFixture
) -> None:
    config = _config()
    write(ROOT, ROOT_DECORATOR_ONLY)
    write(HOST, HOST_DECLARING.replace("{name}", "item_id"))
    guard = _guard(config)

    with caplog.at_level(logging.WARNING):
        _call(guard, "/item/1/", HOST, config=config)
    hints = _hints(caplog)
    assert len(hints) == 1
    assert "the path_params report" in hints[0]
    assert "exclude_paths" not in hints[0]


def test_an_unlisted_urlconf_with_nothing_to_check_is_not_named(
    write: Callable[[str, str], None], caplog: pytest.LogCaptureFixture
) -> None:
    config = _config()
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, PLAIN_ROUTES["host"])
    guard = _guard(config)

    with caplog.at_level(logging.WARNING):
        _call(guard, "/admin/", HOST, config=config)
    assert _hints(caplog) == []


@pytest.mark.parametrize("listed", ["wp_inproc_host", 5, [5], ["no_such_urlconf"]])
def test_a_bad_guard_urlconfs_stops_the_start(
    write: Callable[[str, str], None], listed: object
) -> None:
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, PLAIN_ROUTES["host"])
    with pytest.raises(ImproperlyConfigured, match="GUARD_URLCONFS"):
        _guard(_config(), GUARD_URLCONFS=listed)


def test_the_startup_reads_every_listed_urlconf(
    write: Callable[[str, str], None],
) -> None:
    config = _config(fail_on_misconfiguration=False)
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, HOST_OWN_DECLARING.replace("{name}", "ghost"))
    listed = {"GUARD_URLCONFS": [HOST]}
    guard = _guard(config, **listed)

    with override_settings(GUARD_SECURITY_CONFIG=config, ROOT_URLCONF=ROOT, **listed):
        messages = [str(m.msg) for m in check_declared_path_params()]
        prefixes = guard.static_route_prefixes()
        resolvers = adoption.startup_resolvers()
    assert guard.guard_decorator is not None
    assert any("ghost" in message for message in messages)
    assert "/item/" in prefixes
    assert [r.urlconf_name for r in resolvers] == [ROOT, HOST]


def test_a_root_app_with_no_decorator_never_asks_for_a_resolver_per_request(
    write: Callable[[str, str], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    write(ROOT, PLAIN_ROUTES["root"])
    guard = _guard(config)

    def refuse(*args: object) -> None:
        raise AssertionError("the root path asked for a resolver")

    monkeypatch.setattr("djangoapi_guard.middleware.get_resolver", refuse)
    assert _call(guard, "/hello/", config=config) == 200


HOST_COUNTRY_RULE = (
    PLAIN
    + DECORATOR
    + "@guard_deco.block_countries(['CN'])\n"
    + VIEW
    + "urlpatterns = [path('admin/', view)]\n"
)


def _redis_config(prefix: str, **fields: Any) -> SecurityConfig[SyncGuardRequest]:
    return _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX + prefix,
        **fields,
    )


def test_a_decorator_adopted_after_init_tracks_behavior_on_the_shared_redis(
    write: Callable[[str, str], None],
) -> None:
    config = _redis_config("late-adopt-redis:")
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, HOST_GUARDED)
    guard = _guard(config)

    assert _call(guard, "/hello/", config=config) == 200
    assert _call(guard, "/admin/", HOST, config=config) == 400
    adopted = guard.guard_decorator
    assert adopted is not None
    assert guard.redis_handler is not None
    assert adopted.behavior_tracker.redis_handler is guard.redis_handler


class _AgentStub:
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def flush_buffer(self) -> None: ...

    def send_event(self, event: object) -> None: ...

    def send_metric(self, metric: object) -> None: ...

    def initialize_redis(self, redis_handler: object) -> None: ...

    def get_dynamic_rules(self) -> None:
        return None

    def get_status(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, object]:
        return {}


def test_a_decorator_adopted_after_init_gets_the_telemetry_handler(
    write: Callable[[str, str], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "guard_agent",
        SimpleNamespace(SyncGuardAgentHandler=lambda _cfg: _AgentStub()),
    )
    config = _config(enable_agent=True, agent_api_key="x")
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, HOST_GUARDED)
    with patch.object(SecurityConfig, "to_agent_config", return_value=object()):
        guard = _guard(config)

    assert _call(guard, "/hello/", config=config) == 200
    assert _call(guard, "/admin/", HOST, config=config) == 400
    adopted = guard.guard_decorator
    initializer = guard.handler_initializer
    assert adopted is not None
    assert initializer is not None
    assert initializer.composite_handler is not None
    assert adopted.agent_handler is initializer.composite_handler


def test_a_country_rule_of_a_decorator_adopted_after_init_is_reported_and_refused(
    write: Callable[[str, str], None],
) -> None:
    config = _config(fail_on_misconfiguration=True)
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, HOST_COUNTRY_RULE)
    guard = _guard(config)

    assert _call(guard, "/hello/", config=config) == 200
    for _ in range(2):
        with pytest.raises(MisconfigurationError, match="block_countries"):
            _call(guard, "/admin/", HOST, config=config)
    assert _decorator_of(guard) is None


def test_a_decorator_set_by_the_call_after_init_gets_the_same_steps(
    write: Callable[[str, str], None],
) -> None:
    config = _redis_config("late-set-redis:")
    write(ROOT, PLAIN_ROUTES["root"])
    guard = _guard(config)
    assert _call(guard, "/hello/", config=config) == 200
    decorator = SecurityDecorator(config)

    guard.set_decorator_handler(decorator)

    assert guard.redis_handler is not None
    assert decorator.behavior_tracker.redis_handler is guard.redis_handler


@pytest.mark.parametrize(
    "entries",
    [list(reversed(DEFAULT_EXCLUDE_PATHS)), ["/docs"], ["/docs", "/"], []],
)
def test_a_reordered_or_reduced_default_list_gives_no_hint(
    write: Callable[[str, str], None],
    caplog: pytest.LogCaptureFixture,
    entries: list[str],
) -> None:
    config = _config(exclude_paths=entries)
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, PLAIN_ROUTES["host"])
    guard = _guard(config)

    with caplog.at_level(logging.WARNING):
        _call(guard, "/admin/", HOST, config=config)
    assert _hints(caplog) == []


def test_a_country_rule_of_a_decorator_adopted_after_init_builds_the_geo_handler(
    write: Callable[[str, str], None],
) -> None:
    config = _config(ipinfo_token="token", fail_on_misconfiguration=False)
    write(ROOT, PLAIN_ROUTES["root"])
    write(HOST, HOST_COUNTRY_RULE)
    guard = _guard(config)

    assert _call(guard, "/hello/", config=config) == 200
    assert _geo_of(guard) is None
    _call(guard, "/admin/", HOST, config=config)
    assert _geo_of(guard) is not None
    assert guard.handler_initializer is not None
    assert _geo_of(guard) is guard.handler_initializer.geo_ip_handler
