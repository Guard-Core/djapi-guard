import sys
import types
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from django.test import Client, override_settings
from django.urls import URLPattern, clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "fail_on_misconfiguration": False,
        "rate_limit": 1000,
        "trusted_proxies": [],
    }
    fields.update(overrides)
    return SecurityConfig[SyncGuardRequest](**fields)


@contextmanager
def served(
    urlpatterns: list[URLPattern],
    guard_config: SecurityConfig[SyncGuardRequest],
    *,
    middleware: tuple[str, ...] = ("djangoapi_guard.middleware.DjangoAPIGuard",),
    **extra_settings: Any,
) -> Iterator[Client]:
    name = f"tests.wsgi_sweep_urls_{uuid.uuid4().hex}"
    module = types.ModuleType(name)
    module.__dict__["urlpatterns"] = urlpatterns
    sys.modules[name] = module
    clear_url_caches()
    try:
        with override_settings(
            ROOT_URLCONF=name,
            GUARD_SECURITY_CONFIG=guard_config,
            MIDDLEWARE=list(middleware),
            **extra_settings,
        ):
            yield Client()
    finally:
        sys.modules.pop(name, None)
        clear_url_caches()
