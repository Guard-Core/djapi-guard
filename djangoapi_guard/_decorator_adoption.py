from __future__ import annotations

import weakref
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import get_resolver
from django.utils.module_loading import import_string
from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator as CoreSecurityDecorator
from guard_core.sync.decorators.base import BaseSecurityDecorator

_created: list[weakref.ReferenceType[BaseSecurityDecorator]] = []


class SecurityDecorator(CoreSecurityDecorator):
    def __init__(self, config: SecurityConfig) -> None:
        super().__init__(config)
        _created.append(weakref.ref(self))


def _alive_decorators() -> list[BaseSecurityDecorator]:
    alive = [decorator for ref in _created if (decorator := ref()) is not None]
    _created[:] = [weakref.ref(decorator) for decorator in alive]
    return alive


def _configured_decorator() -> BaseSecurityDecorator | None:
    configured: Any = getattr(settings, "GUARD_DECORATOR", None)
    if configured is None:
        return None
    if isinstance(configured, str):
        configured = import_string(configured)
    if not isinstance(configured, BaseSecurityDecorator):
        raise ImproperlyConfigured(
            "settings.GUARD_DECORATOR must be a SecurityDecorator instance "
            "or the dotted path to one"
        )
    return configured


def resolve_decorator() -> BaseSecurityDecorator | None:
    configured = _configured_decorator()
    if configured is not None:
        return configured
    list(get_resolver().url_patterns)
    alive = _alive_decorators()
    if len(alive) > 1:
        names = ", ".join(
            f"{type(decorator).__module__}.{type(decorator).__qualname__} "
            f"at {hex(id(decorator))}"
            for decorator in alive
        )
        raise ImproperlyConfigured(
            f"{len(alive)} SecurityDecorator instances are registered ({names}) "
            "and settings.GUARD_DECORATOR does not say which one to use. Set "
            "settings.GUARD_DECORATOR to the decorator or its dotted path."
        )
    return alive[0] if alive else None
