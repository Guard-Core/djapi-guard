from collections.abc import Iterable, Iterator

from django.conf import settings
from django.core.checks import CheckMessage, Error, Warning
from django.core.exceptions import ImproperlyConfigured
from django.urls import URLPattern, URLResolver, get_resolver
from guard_core._misconfiguration import config_logger, report_misconfiguration
from guard_core.models import SecurityConfig
from guard_core.sync._utils.route_gate import (
    declared_path_param_problems as engine_problems,
)
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard._decorator_adoption import resolve_decorator

_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")


def _templates_and_callbacks(
    patterns: Iterable[URLPattern | URLResolver], base: str = ""
) -> Iterator[tuple[str, object]]:
    for entry in patterns:
        template = base + str(entry.pattern)
        if isinstance(entry, URLResolver):
            yield from _templates_and_callbacks(entry.url_patterns, template)
        else:
            yield template, entry.callback


def _route_ids_of(callback: object) -> set[str]:
    view_class = getattr(callback, "view_class", None)
    places = [callback, view_class]
    places += [getattr(view_class, verb, None) for verb in _HTTP_VERBS]
    return {
        route_id
        for place in places
        if isinstance(route_id := getattr(place, "_guard_route_id", None), str)
    }


def declared_path_param_problems(
    guard_decorator: BaseSecurityDecorator | None,
) -> list[str]:
    if guard_decorator is None:
        return []
    problems: list[str] = []
    for template, callback in _templates_and_callbacks(get_resolver().url_patterns):
        for route_id in sorted(_route_ids_of(callback)):
            route_config = guard_decorator.get_route_config(route_id)
            declared = getattr(route_config, "excluded_detection_path_params", None)
            if not declared:
                continue
            for name, problem in engine_problems(template, declared).items():
                problems.append(
                    f"@detection_exclusion(path_params=...) on route {route_id!r} "
                    f"declares {name!r}, which {problem}"
                )
    return problems


def report_at_boot(
    config: SecurityConfig[SyncGuardRequest],
    guard_decorator: BaseSecurityDecorator | None,
) -> None:
    for problem in declared_path_param_problems(guard_decorator):
        report_misconfiguration(config, problem, logger=config_logger, stacklevel=2)


def warn_at_first_request(guard_decorator: BaseSecurityDecorator | None) -> None:
    for problem in declared_path_param_problems(guard_decorator):
        config_logger.warning(problem)


def check_declared_path_params(
    app_configs: object = None, **kwargs: object
) -> list[CheckMessage]:
    try:
        decorator = resolve_decorator()
    except ImproperlyConfigured:
        # DjangoAPIGuard raises the same error when it is built
        return []
    config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
    warn_only = getattr(config, "fail_on_misconfiguration", True) is False
    report, identifier = (
        (Warning, "djangoapi_guard.W001")
        if warn_only
        else (Error, "djangoapi_guard.E001")
    )
    return [
        report(problem, id=identifier)
        for problem in declared_path_param_problems(decorator)
    ]
