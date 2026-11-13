from collections.abc import Collection, Iterable, Iterator, Sequence
from dataclasses import dataclass

from django.conf import settings
from django.core.checks import CheckMessage, Error, Warning
from django.core.exceptions import ImproperlyConfigured
from django.urls import URLPattern, URLResolver
from guard_core._misconfiguration import (
    config_logger,
    report_declared_path_param_problems,
)
from guard_core._misconfiguration_kinds import Problem
from guard_core.models import SecurityConfig
from guard_core.sync._utils.route_gate import detection_exclusion_path_param_problems
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard._decorator_adoption import resolve_decorator, startup_resolvers

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


def _declared_in(
    guard_decorator: BaseSecurityDecorator, resolver: URLResolver
) -> Iterator[tuple[str, str, Collection[str]]]:
    for template, callback in _templates_and_callbacks(resolver.url_patterns):
        for route_id in sorted(_route_ids_of(callback)):
            route_config = guard_decorator.get_route_config(route_id)
            declared = getattr(route_config, "excluded_detection_path_params", None)
            if declared:
                yield route_id, template, declared


def declares_path_params(
    guard_decorator: BaseSecurityDecorator | None, resolver: URLResolver
) -> bool:
    return guard_decorator is not None and any(
        True for _ in _declared_in(guard_decorator, resolver)
    )


def declared_path_param_problems(
    guard_decorator: BaseSecurityDecorator | None,
    resolver: URLResolver | None = None,
) -> list[Problem]:
    if guard_decorator is None:
        return []
    problems: list[Problem] = []
    for walked in [resolver] if resolver else startup_resolvers():
        for route_id, template, declared in _declared_in(guard_decorator, walked):
            problems += detection_exclusion_path_param_problems(
                route_id, template, declared
            )
    return problems


def report_declared_path_params(
    config: SecurityConfig[SyncGuardRequest],
    guard_decorator: BaseSecurityDecorator | None,
    *,
    problems: list[Problem] | None = None,
    log_refusal: bool = False,
) -> None:
    """The one report point, at the boot, at the first request and again whenever
    the urlconf changes (a route can be added after startup). With
    fail_on_misconfiguration every request raises a fresh error from the cached
    problems and the refusal is logged once per change; without it each problem
    is warned once."""
    if problems is None:
        problems = declared_path_param_problems(guard_decorator)
    if log_refusal and problems and config.fail_on_misconfiguration:
        config_logger.error(
            "Every request is refused until this is fixed: %s", "; ".join(problems)
        )
    report_declared_path_param_problems(
        config, problems, logger=config_logger, stacklevel=2
    )


# One entry per pattern list: (index of the parent entry, index of the resolver in
# it, id of the list, its length). The state keeps these numbers and the problem
# strings, never a resolver or a list, so it cannot keep the resolver alive.
_Layout = tuple[tuple[int, int, int, int], ...]


@dataclass(frozen=True)
class RouteTableState:
    layout: _Layout
    problems: tuple[Problem, ...]


def _patterns_of(entry: object) -> Sequence[object] | None:
    return entry.url_patterns if isinstance(entry, URLResolver) else None


def _layout_of(root: Sequence[object]) -> _Layout:
    layout = [(-1, -1, id(root), len(root))]
    pending = [(0, root)]
    while pending:
        parent, patterns = pending.pop()
        for index, entry in enumerate(patterns):
            nested = _patterns_of(entry)
            if nested is not None:
                layout.append((parent, index, id(nested), len(nested)))
                pending.append((len(layout) - 1, nested))
    return tuple(layout)


def _layout_holds(root: Sequence[object], layout: _Layout) -> bool:
    resolved: list[Sequence[object]] = []
    for parent, index, identity, length in layout:
        if parent < 0:
            patterns: Sequence[object] | None = root
        elif index < len(resolved[parent]):
            patterns = _patterns_of(resolved[parent][index])
        else:
            return False
        if patterns is None or len(patterns) != length or id(patterns) != identity:
            return False
        resolved.append(patterns)
    return True


def route_table_holds(resolver: URLResolver, state: RouteTableState) -> bool:
    """True while no pattern list of this resolver changed: the check costs the
    number of lists, not of routes."""
    return _layout_holds(resolver.url_patterns, state.layout)


def walk_route_table(
    resolver: URLResolver, guard_decorator: BaseSecurityDecorator | None
) -> RouteTableState:
    root = resolver.url_patterns
    return RouteTableState(
        _layout_of(root),
        tuple(declared_path_param_problems(guard_decorator, resolver)),
    )


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
