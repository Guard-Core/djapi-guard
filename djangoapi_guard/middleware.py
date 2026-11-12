import atexit
import inspect
import logging
import os
import posixpath
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from pathlib import Path

from django.conf import settings
from django.contrib.staticfiles import finders
from django.contrib.staticfiles.views import serve as staticfiles_serve
from django.core.exceptions import ImproperlyConfigured, SuspiciousFileOperation
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseBase
from django.urls import ResolverMatch, URLPattern, URLResolver
from django.urls.resolvers import LocalePrefixPattern, RegexPattern, RoutePattern
from django.utils._os import safe_join
from django.utils.cache import patch_vary_headers
from django.views.static import serve as static_serve
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync import apply_security_headers_settings
from guard_core.sync._utils.app_scope import hold_app_scope, release_app_scope
from guard_core.sync._utils.sampling import observe_sampled_key
from guard_core.sync.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.sync.core.bypass import BypassContext, BypassHandler
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.checks.route_prefixes import regex_route_prefix
from guard_core.sync.core.events import MetricsCollector, SecurityEventBus
from guard_core.sync.core.initialization import HandlerInitializer
from guard_core.sync.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.sync.core.routing import RouteConfigResolver, RoutingContext
from guard_core.sync.core.validation import RequestValidator, ValidationContext
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler_for
from guard_core.sync.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.protocols.agent_protocol import JsonValue, SyncAgentHandlerProtocol
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import extract_client_ip, setup_custom_logging

from djangoapi_guard._declared_path_params import warn_at_first_request
from djangoapi_guard._decorator_adoption import resolve_decorator
from djangoapi_guard.adapters import (
    DjangoGuardRequest,
    DjangoGuardResponse,
    DjangoResponseFactory,
    set_request_attribute,
    unwrap_response,
)

_decorator_missing_warned = False
# How long process exit waits for an agent to flush and stop: its own stop() retries
# a refused endpoint for 14 s and a black-holed one for over a minute.
_AGENT_EXIT_WAIT_SECONDS = 5.0
_agent_exit_registered: set[int] = set()
_agent_exit_lock = threading.Lock()
_several_warned: set[object] = set()


# The urlconf a middleware chose for the request being served (django-hosts and
# similar set request.urlconf). The helpers the engine asks about a path have no
# request, so it is held here while the request is served.
_request_urlconf: ContextVar[str | None] = ContextVar("guard_urlconf", default=None)


def _agent_already_stopped(handler: SyncAgentHandlerProtocol) -> bool:
    """True when the handler's loop thread has ended or its loop is closed (the
    user stopped it): a second stop() would wait on a loop that never runs."""
    thread = getattr(handler, "_thread", None)
    loop = getattr(handler, "_loop", None)
    return (thread is not None and not thread.is_alive()) or (
        loop is not None and loop.is_closed()
    )


def _stop_agent_within(
    handler: SyncAgentHandlerProtocol, seconds: float, logger: logging.Logger
) -> None:
    if _agent_already_stopped(handler):
        return

    def stop() -> None:
        try:
            handler.stop()
        except Exception as error:
            logger.error("Guard Agent did not stop cleanly at exit: %s", error)

    worker = threading.Thread(target=stop, name="guard-agent-exit", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        logger.warning(
            "Guard Agent did not finish flushing within %.1f s at exit: the events "
            "it still held are dropped",
            seconds,
        )


def _stop_agent_at_exit(
    handler: SyncAgentHandlerProtocol, logger: logging.Logger
) -> None:
    """Flush and stop the agent once at process exit, waiting at most
    `_AGENT_EXIT_WAIT_SECONDS`. Registered once per handler."""
    with _agent_exit_lock:
        if id(handler) in _agent_exit_registered:
            return
        _agent_exit_registered.add(id(handler))
    atexit.register(_stop_agent_within, handler, _AGENT_EXIT_WAIT_SECONDS, logger)


def _resolve_match(path: str) -> ResolverMatch:
    from django.urls import Resolver404, resolve
    from django.utils import translation

    urlconf = _request_urlconf.get()
    try:
        return resolve(path, urlconf=urlconf)
    except Resolver404:
        language = translation.get_language_from_path(path)
        if language is None:
            raise
        with translation.override(language):
            return resolve(path, urlconf=urlconf)


def _route_ids_of_view(match: ResolverMatch, method: str) -> list[tuple[str, str]]:
    """Where a route decorator was applied to the view, as (place, route id).

    A decorator on the function, on `Class.as_view()` or through
    `method_decorator(name="dispatch")` marks the function Django resolved (as_view
    copies the dispatch attributes onto it); one applied to the class marks the
    class; `method_decorator` on a method marks that method, and only that method
    runs for its HTTP method.
    """
    func = match.func
    places: list[tuple[str, object]] = [("the view function", func)]
    view_class = getattr(func, "view_class", None)
    if view_class is not None:
        # HEAD is served by `get` unless the class defines `head`.
        verbs = [method, "get"] if method == "head" else [method]
        places.append(("the class", view_class))
        places.extend(
            (f"its {verb} method", getattr(view_class, verb, None)) for verb in verbs
        )
    found = [(place, getattr(obj, "_guard_route_id", None)) for place, obj in places]
    return [(place, route_id) for place, route_id in found if route_id]


def _route_identity(
    match: ResolverMatch,
) -> tuple[object, tuple[tuple[str, str], ...]]:
    params = [(str(index), str(value)) for index, value in enumerate(match.args)]
    params += [(name, str(value)) for name, value in match.kwargs.items()]
    return match.func, tuple(sorted(params))


def _pattern_texts(
    pattern: RegexPattern | RoutePattern | LocalePrefixPattern,
) -> list[str]:
    if isinstance(pattern, LocalePrefixPattern):
        texts = [f"{code}/" for code, _ in settings.LANGUAGES]
        return texts if pattern.prefix_default_language else [*texts, ""]
    if isinstance(pattern, RoutePattern):
        return [re.sub(r"<[^>]*>", "(.*)", str(pattern))]
    return [pattern.regex.pattern.removeprefix("^")]


def _urlconf_prefixes(
    patterns: Iterable[URLPattern | URLResolver], base: str
) -> list[str]:
    prefixes: list[str] = []
    for entry in patterns:
        for text in _pattern_texts(entry.pattern):
            if hasattr(entry, "url_patterns"):
                prefixes.extend(_urlconf_prefixes(entry.url_patterns, base + text))
                continue
            end = "$" if isinstance(entry.pattern, RoutePattern) else ""
            prefixes.append(regex_route_prefix(base + text + end))
    return prefixes


_INIT_OUTAGE_SAMPLE_WINDOW_SECONDS = 60
_INIT_OUTAGE_SAMPLE_KEY = "redis_unavailable_during_initialization"
_init_outage_lock = threading.Lock()
_init_outage_samples: OrderedDict[str, float] = OrderedDict()


def _sample_init_outage_line() -> bool:
    return observe_sampled_key(
        _init_outage_samples,
        _init_outage_lock,
        _INIT_OUTAGE_SAMPLE_KEY,
        window=_INIT_OUTAGE_SAMPLE_WINDOW_SECONDS,
        max_tracked=1,
    )


class DjangoAPIGuard:
    def __init__(
        self,
        get_response: Callable[[HttpRequest], HttpResponseBase],
    ) -> None:
        self.get_response = get_response

        config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
        if config is None:
            raise ImproperlyConfigured(
                "DjangoAPIGuard requires settings.GUARD_SECURITY_CONFIG to be "
                "a SecurityConfig instance"
            )
        self.config: SecurityConfig[SyncGuardRequest] = config

        self.logger: logging.Logger = setup_custom_logging(
            self.config.custom_log_file, log_format=self.config.log_format
        )
        self.last_cloud_ip_refresh: int = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cleanup: float = time.time()
        self.rate_limit_handler: RateLimitManager = RateLimitManager(self.config)
        self.guard_decorator: BaseSecurityDecorator | None = None
        self.geo_ip_handler: SyncGeoIPHandler | None = None
        self.redis_handler: SyncRedisHandlerProtocol | None = None
        self.agent_handler: SyncAgentHandlerProtocol | None = None
        self.security_pipeline: SecurityCheckPipeline | None = None
        self.event_bus: SecurityEventBus
        self.metrics_collector: MetricsCollector | None = None
        self.handler_initializer: HandlerInitializer | None = None
        self.response_factory: ErrorResponseFactory | None = None
        self.route_resolver: RouteConfigResolver
        self.validator: RequestValidator | None = None
        self.bypass_handler: BypassHandler | None = None
        self.behavioral_processor: BehavioralProcessor | None = None
        self._global_throttle_rules = False
        self._guard_response_factory = DjangoResponseFactory()
        self._cors_handler: CorsHandler | None = (
            CorsHandler(self.config) if self.config.enable_cors else None
        )
        self._handlers_initialized = False
        self._path_params_checked = False
        self._init_lock = threading.Lock()

        self._configure_security_headers(self.config)
        self._init_redis_handler()
        self._init_agent_handler()
        self._init_core_components()
        self._init_route_resolver()
        self._build_event_bus_and_contexts()
        self._build_security_pipeline()
        self._report_route_misconfigurations_at_startup()

    @property
    def guard_response_factory(self) -> DjangoResponseFactory:
        return self._guard_response_factory

    @property
    def agent_stats(self) -> dict[str, JsonValue]:
        if self.agent_handler is None:
            return {"enabled": False}
        handler_stats = self.agent_handler.get_stats()
        return {"enabled": True, **handler_stats}

    def _init_redis_handler(self) -> None:
        self.redis_handler = None
        if self.config.enable_redis:
            from guard_core.sync.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(self.config)

    def _init_agent_handler(self) -> None:
        self.agent_handler = None
        if not self.config.enable_agent:
            return

        agent_config = self.config.to_agent_config()
        if not agent_config:
            self.logger.warning(
                "Agent enabled but configuration is invalid. "
                "Check agent_api_key and other required fields."
            )
            return

        try:
            from guard_agent import SyncGuardAgentHandler

            self.agent_handler = SyncGuardAgentHandler(agent_config)
            _stop_agent_at_exit(self.agent_handler, self.logger)
            self.logger.info("Guard Agent initialized successfully")
        except ImportError:
            self.logger.warning(
                "Agent enabled but guard_agent package not installed. "
                "Install with: pip install guard-agent"
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Guard Agent: {e}")
            self.logger.warning("Continuing without agent functionality")

    def _init_core_components(self) -> None:
        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.config.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
            adapter="djapi-guard",
        )
        self.geo_ip_handler = self.handler_initializer.geo_ip_handler

    def _init_route_resolver(self) -> None:
        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

    def _build_event_bus_and_contexts(self) -> None:
        if self.handler_initializer is None:
            raise RuntimeError("handler_initializer not initialized")

        if self.handler_initializer.composite_handler is not None:
            self.agent_handler = self.handler_initializer.composite_handler
            self.event_bus = self.handler_initializer.build_event_bus(
                geo_ip_handler=self.geo_ip_handler
            )
            self.metrics_collector = self.handler_initializer.build_metrics_collector()
        else:
            self.event_bus = SecurityEventBus(
                self.agent_handler, self.config, self.geo_ip_handler
            )
            self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            redis_handler=self.redis_handler,
            guard_decorator=self.guard_decorator,
            response_factory=self._guard_response_factory,
        )
        self.response_factory = ErrorResponseFactory(response_context)

        validation_context = ValidationContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        bypass_context = BypassContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            route_resolver=self.route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        behavioral_context = BehavioralContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
            behavior_tracker=self.handler_initializer.behavior_tracker,
            middleware=self,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)
        self._global_throttle_rules = any(
            rule.action == "throttle" for rule in self.config.global_behavior_rules
        )

    def _assert_initialized(self) -> None:
        if self.bypass_handler is None:
            raise RuntimeError("bypass_handler not initialized")
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        if self.response_factory is None:
            raise RuntimeError("response_factory not initialized")

    def _populate_guard_state(
        self, guard_request: DjangoGuardRequest, request: HttpRequest
    ) -> None:
        from django.urls import Resolver404

        try:
            match = _resolve_match(request.path_info)
            set_request_attribute(request, "guard_route_template", match.route)
            view_func = match.func
            if hasattr(view_func, "view_class"):
                view_func = view_func.view_class
            set_request_attribute(
                request,
                "guard_endpoint_id",
                (f"{view_func.__module__}.{view_func.__qualname__}"),
            )
            route_ids = _route_ids_of_view(match, (request.method or "get").lower())
            if route_ids:
                set_request_attribute(request, "guard_route_id", route_ids[0][1])
                self._warn_once_decorator_missing()
                self._warn_once_decorators_in_several_places(view_func, route_ids)
            if getattr(self.security_pipeline, "needs_route_identity", False):
                set_request_attribute(
                    request, "guard_route_identity", _route_identity(match)
                )
        except Resolver404:
            set_request_attribute(request, "guard_route_unresolved", True)

    def _warn_once_decorators_in_several_places(
        self, view: object, route_ids: list[tuple[str, str]]
    ) -> None:
        if len({route_id for _, route_id in route_ids}) < 2 or view in _several_warned:
            return
        _several_warned.add(view)
        places = ", ".join(place for place, _ in route_ids)
        self.logger.warning(
            "Route decorators are applied to %s of %s: their rules are not merged, "
            "only those of %s are enforced. Apply the decorators in one place.",
            places,
            getattr(view, "__qualname__", view),
            route_ids[0][0],
        )

    def _warn_once_decorator_missing(self) -> None:
        global _decorator_missing_warned
        if self.guard_decorator is not None or _decorator_missing_warned:
            return
        _decorator_missing_warned = True
        self.logger.warning(
            "A decorated view was reached but no decorator is registered with "
            "DjangoAPIGuard, so its route decorators are not enforced. Build the "
            "decorator with djangoapi_guard.SecurityDecorator (adopted "
            "automatically when it is the only one) or set "
            "settings.GUARD_DECORATOR to the decorator or its dotted path."
        )

    def resolve_route(
        self, path: str
    ) -> tuple[tuple[object, tuple[tuple[str, str], ...]], ...]:
        from django.urls import Resolver404

        try:
            return (_route_identity(_resolve_match(path)),)
        except Resolver404:
            return ()

    def static_file_exists(self, path: str) -> bool:
        from django.urls import Resolver404

        try:
            match = _resolve_match(path)
        except Resolver404:
            return False
        served = match.kwargs.get("path")
        if not isinstance(served, str):
            return False
        view = inspect.unwrap(match.func)
        relative = posixpath.normpath(served).lstrip("/")
        try:
            if view is static_serve:
                root = match.kwargs.get("document_root")
                return root is not None and Path(safe_join(root, relative)).is_file()
            if view is staticfiles_serve:
                found = finders.find(relative)
                return isinstance(found, str) and os.path.isfile(found)
        except SuspiciousFileOperation:
            return False
        return False

    def static_route_prefixes(self) -> tuple[str, ...]:
        from django.urls import get_resolver

        return tuple(_urlconf_prefixes(get_resolver().url_patterns, ""))

    def _adopt_decorator(self) -> None:
        adopted = resolve_decorator() if self.guard_decorator is None else None
        if adopted is not None:
            self.set_decorator_handler(adopted)

    def _report_route_misconfigurations_at_startup(self) -> None:
        handler_initializer = self.handler_initializer
        if handler_initializer is None:
            raise RuntimeError("handler_initializer not initialized")
        self._adopt_decorator()
        handler_initializer.guard_decorator = self.guard_decorator
        handler_initializer.report_route_misconfigurations()
        self.geo_ip_handler = handler_initializer.geo_ip_handler

    def _ensure_handlers_initialized(
        self, request: HttpRequest
    ) -> HttpResponseBase | None:
        if self._handlers_initialized:
            return None
        e = self._initialize_handlers_once()
        if e is not None:
            if self.config.passive_mode:
                if _sample_init_outage_line():
                    self.logger.error(
                        "Redis unavailable during initialization: %s "
                        "(passive_mode=True, request passed through unguarded)",
                        e,
                    )
                return self.get_response(request)
            self.logger.error("Redis unavailable during initialization: %s", e)
            return self._attach_cors_headers(
                self._redis_unavailable_response(), request
            )
        return None

    def _initialize_handlers_once(self) -> GuardRedisError | None:
        with self._init_lock:
            if self._handlers_initialized:
                return None
            self._adopt_decorator()
            if not self._path_params_checked:
                self._path_params_checked = True
                warn_at_first_request(self.guard_decorator)
            try:
                self._initialize_handlers()
            except GuardRedisError as e:
                return e
            self._handlers_initialized = True
            return None

    def _handle_preflight(
        self,
        request: HttpRequest,
        guard_request: DjangoGuardRequest,
        request_headers: dict[str, str],
    ) -> HttpResponseBase | None:
        cors_handler = self._cors_handler
        if cors_handler is None:
            return None
        if not is_preflight(request.method or "", request_headers):
            return None
        blocking = self._execute_security_pipeline(guard_request)
        if blocking:
            return self._attach_cors_headers(blocking, request)
        return self._build_preflight_response(cors_handler, request_headers)

    def __call__(self, request: HttpRequest) -> HttpResponseBase:
        early_response = self._ensure_handlers_initialized(request)
        if early_response is not None:
            return early_response

        self._assert_initialized()
        token = hold_app_scope(self.config)
        urlconf_token = _request_urlconf.set(getattr(request, "urlconf", None))
        try:
            return self._call_after_init(request)
        finally:
            _request_urlconf.reset(urlconf_token)
            release_app_scope(token)

    def _call_after_init(self, request: HttpRequest) -> HttpResponseBase:
        bypass_handler = self.bypass_handler
        if bypass_handler is None:
            raise RuntimeError("bypass_handler not initialized")
        route_resolver = self.route_resolver

        set_request_attribute(request, "_guard_request_start_time", time.time())
        guard_request = DjangoGuardRequest(request)
        self._populate_guard_state(guard_request, request)

        request_headers = dict(request.headers)

        def wrapped_call_next(_guard_req: SyncGuardRequest) -> GuardResponse:
            return DjangoGuardResponse(self.get_response(request))

        preflight_response = self._handle_preflight(
            request, guard_request, request_headers
        )
        if preflight_response is not None:
            return preflight_response

        passthrough = bypass_handler.handle_passthrough(
            guard_request, wrapped_call_next
        )
        if passthrough is not None:
            return self._attach_cors_headers(unwrap_response(passthrough), request)

        client_ip = extract_client_ip(guard_request, self.config, self.agent_handler)
        route_config = route_resolver.get_route_config(guard_request)

        set_request_attribute(request, "_guard_client_ip", client_ip)
        set_request_attribute(request, "_guard_route_config", route_config)

        bypass = bypass_handler.handle_security_bypass(
            guard_request, wrapped_call_next, route_config=route_config
        )
        if bypass is not None:
            return self._attach_cors_headers(unwrap_response(bypass), request)

        blocking = self._execute_security_pipeline(guard_request)
        if blocking:
            return self._attach_cors_headers(blocking, request)

        throttled = self._process_behavioral_usage(
            guard_request, client_ip, route_config
        )
        if throttled is not None:
            return self._attach_cors_headers(throttled, request)

        response = self.get_response(request)
        return self._finalize_response(request, response, route_config)

    def _execute_security_pipeline(
        self, guard_request: DjangoGuardRequest
    ) -> HttpResponseBase | None:
        if self.security_pipeline:
            result = self.security_pipeline.execute(guard_request)
            if result is not None:
                return unwrap_response(result)
        return None

    def _process_behavioral_usage(
        self,
        guard_request: DjangoGuardRequest,
        client_ip: str,
        route_config: RouteConfig | None,
    ) -> HttpResponseBase | None:
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        has_route_rules = route_config is not None and bool(route_config.behavior_rules)
        if not client_ip or not (has_route_rules or self._global_throttle_rules):
            return None
        refused = self.behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )
        return None if refused is None else unwrap_response(refused)

    def _build_preflight_response(
        self, cors_handler: CorsHandler, request_headers: dict[str, str]
    ) -> HttpResponseBase:
        preflight = cors_handler.build_preflight_response(request_headers)
        response = HttpResponse(preflight.body, status=preflight.status_code)
        for key, value in preflight.headers.items():
            response[key] = value
        return response

    def _attach_cors_headers(
        self, response: HttpResponseBase, request: HttpRequest
    ) -> HttpResponseBase:
        if self._cors_handler is None:
            return response
        cors_headers = self._cors_handler.build_response_headers(dict(request.headers))
        for key, value in cors_headers.items():
            if key.lower() == "vary":
                patch_vary_headers(
                    response, [name.strip() for name in value.split(",")]
                )
            else:
                response[key] = value
        return response

    def _redis_unavailable_response(self) -> HttpResponseBase:
        guard_response = self.create_error_response(
            503, "Service temporarily unavailable"
        )
        guard_response.headers["Retry-After"] = "5"
        return unwrap_response(guard_response)

    def _finalize_response(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        route_config: RouteConfig | None,
    ) -> HttpResponseBase:
        start_time = getattr(request, "_guard_request_start_time", time.time())
        response_time = time.time() - start_time
        processed = self._process_response(
            request, response, response_time, route_config
        )
        return self._attach_cors_headers(processed, request)

    def _initialize_handlers(self) -> None:
        if self.handler_initializer is None:
            raise RuntimeError("handler_initializer not initialized")
        self.handler_initializer.guard_decorator = self.guard_decorator
        self.handler_initializer.initialize_redis_handlers()
        self.geo_ip_handler = self.handler_initializer.geo_ip_handler
        self.handler_initializer.initialize_agent_integrations()

        if self.handler_initializer.composite_handler is not None:
            self._build_event_bus_and_contexts()

    def _build_security_pipeline(self) -> None:
        from guard_core.sync.core.checks import build_default_pipeline

        pipeline = build_default_pipeline(self)
        self.security_pipeline = pipeline
        self.logger.info(
            f"Security pipeline initialized with {len(pipeline)} checks: "
            f"{pipeline.get_check_names()}"
        )

    def _configure_security_headers(
        self, config: "SecurityConfig[SyncGuardRequest]"
    ) -> None:
        apply_security_headers_settings(security_headers_manager, config)

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        self.guard_decorator = decorator_handler
        self.route_resolver.context.guard_decorator = decorator_handler
        if self.behavioral_processor:
            self.behavioral_processor.context.guard_decorator = decorator_handler
        if self.response_factory:
            self.response_factory.context.guard_decorator = decorator_handler
        if self.handler_initializer:
            self.handler_initializer.guard_decorator = decorator_handler

    def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        if self.validator is None:
            raise RuntimeError("validator not initialized")
        result: bool = self.validator.check_time_window(time_restrictions)
        return result

    def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        from guard_core.sync.core.checks.helpers import check_route_ip_access

        result: bool | None = check_route_ip_access(client_ip, route_config, self)
        return result

    def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        from guard_core.sync.core.checks.helpers import check_user_agent_allowed

        result: bool = check_user_agent_allowed(user_agent, route_config, self.config)
        return result

    def _process_response(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> HttpResponseBase:
        if self.response_factory is None:
            raise RuntimeError("response_factory not initialized")
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        guard_request = DjangoGuardRequest(request)
        guard_response = DjangoGuardResponse(response)
        result = self.response_factory.process_response(
            guard_request,
            guard_response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
            process_global_behavioral_rules=(
                self.behavioral_processor.process_global_return_rules
            ),
        )
        return unwrap_response(result)

    def _process_decorator_usage_rules(
        self, request: HttpRequest, client_ip: str, route_config: RouteConfig
    ) -> HttpResponseBase | None:
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        guard_request = DjangoGuardRequest(request)
        refused = self.behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )
        return None if refused is None else unwrap_response(refused)

    def _process_decorator_return_rules(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        guard_request = DjangoGuardRequest(request)
        guard_response = DjangoGuardResponse(response)
        self.behavioral_processor.process_return_rules(
            guard_request, guard_response, client_ip, route_config
        )

    def _get_endpoint_id(self, request: HttpRequest) -> str:
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        guard_request = DjangoGuardRequest(request)
        result: str = self.behavioral_processor.get_endpoint_id(guard_request)
        return result

    def refresh_cloud_ip_ranges(self) -> None:
        if not self.config.block_cloud_providers:
            return
        providers: set[str] = {
            str(provider) for provider in self.config.block_cloud_providers
        }
        cloud_handler_for(self.config).refresh_async(
            providers,
            ttl=self.config.cloud_ip_refresh_interval,
        )
        self.last_cloud_ip_refresh = int(time.time())

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        if self.response_factory is None:
            raise RuntimeError("response_factory not initialized")
        return self.response_factory.create_error_response(status_code, default_message)

    def reset(self) -> None:
        self.rate_limit_handler.reset()
