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
    return alive[0] if len(alive) == 1 else None
