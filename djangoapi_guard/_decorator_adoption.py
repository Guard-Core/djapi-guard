from __future__ import annotations

import weakref

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import URLResolver, get_resolver
from django.utils.module_loading import import_string
from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator as CoreSecurityDecorator
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

_created: list[weakref.ReferenceType[BaseSecurityDecorator]] = []


class SecurityDecorator(CoreSecurityDecorator):
    def __init__(self, config: SecurityConfig[SyncGuardRequest]) -> None:
        super().__init__(config)
        _created.append(weakref.ref(self))


def alive_decorators() -> list[BaseSecurityDecorator]:
    alive = [decorator for ref in _created if (decorator := ref()) is not None]
    _created[:] = [weakref.ref(decorator) for decorator in alive]
    return alive


def _configured_decorator() -> BaseSecurityDecorator | None:
    configured: object = getattr(settings, "GUARD_DECORATOR", None)
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


def listed_urlconfs() -> tuple[str, ...]:
    """settings.GUARD_URLCONFS: the urlconfs a middleware sets on request.urlconf,
    which Django cannot list, so an app names them to have startup read them."""
    listed: object = getattr(settings, "GUARD_URLCONFS", ())
    if not isinstance(listed, (list, tuple)) or not all(
        isinstance(name, str) for name in listed
    ):
        raise ImproperlyConfigured(
            "settings.GUARD_URLCONFS must be a list of dotted urlconf module names"
        )
    return tuple(listed)


def startup_resolvers() -> list[URLResolver]:
    """ROOT_URLCONF and each listed urlconf: what the startup checks read."""
    resolvers = [get_resolver()]
    for name in listed_urlconfs():
        resolver = get_resolver(name)
        try:
            list(resolver.url_patterns)
        except ImportError as error:
            raise ImproperlyConfigured(
                f"settings.GUARD_URLCONFS entry {name!r} is not an importable "
                f"urlconf module: {error}"
            ) from error
        resolvers.append(resolver)
    return resolvers


def ambiguity_message(alive: list[BaseSecurityDecorator]) -> str:
    names = ", ".join(
        f"{type(decorator).__module__}.{type(decorator).__qualname__} "
        f"at {hex(id(decorator))}"
        for decorator in alive
    )
    return (
        f"{len(alive)} SecurityDecorator instances are registered ({names}) "
        "and settings.GUARD_DECORATOR does not say which one to use. Set "
        "settings.GUARD_DECORATOR to the decorator or its dotted path, or share "
        "one decorator instance across the urlconfs."
    )


def resolve_decorator() -> BaseSecurityDecorator | None:
    resolvers = startup_resolvers()
    configured = _configured_decorator()
    if configured is not None:
        return configured
    for resolver in resolvers:
        list(resolver.url_patterns)
    alive = alive_decorators()
    if len(alive) > 1:
        raise ImproperlyConfigured(ambiguity_message(alive))
    return alive[0] if alive else None
