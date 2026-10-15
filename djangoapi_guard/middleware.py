import logging
import time
from collections.abc import Callable
from typing import Any, cast

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.sync.core.bypass import BypassContext, BypassHandler
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.events import MetricsCollector, SecurityEventBus
from guard_core.sync.core.initialization import HandlerInitializer
from guard_core.sync.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.sync.core.routing import RouteConfigResolver, RoutingContext
from guard_core.sync.core.validation import RequestValidator, ValidationContext
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import extract_client_ip, setup_custom_logging

from djangoapi_guard.adapters import (
    DjangoGuardRequest,
    DjangoGuardResponse,
    DjangoResponseFactory,
    unwrap_response,
)


class DjangoAPIGuard:
    def __init__(
        self,
        get_response: Callable[[HttpRequest], HttpResponse],
    ) -> None:
        self.get_response = get_response

        config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
        if config is None:
            raise ImproperlyConfigured(
                "DjangoAPIGuard requires settings.GUARD_SECURITY_CONFIG to be "
                "a SecurityConfig instance"
            )
        self.config: SecurityConfig = config

        self.logger: logging.Logger = setup_custom_logging(
            self.config.custom_log_file, log_format=self.config.log_format
        )
        self.last_cloud_ip_refresh: int = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cleanup: float = time.time()
        self.rate_limit_handler: RateLimitManager = RateLimitManager(self.config)
        self.guard_decorator: BaseSecurityDecorator | None = None
        self.geo_ip_handler: Any = None
        self.redis_handler: Any = None
        self.agent_handler: Any = None
        self.security_pipeline: SecurityCheckPipeline | None = None
        self.event_bus: SecurityEventBus | None = None
        self.metrics_collector: MetricsCollector | None = None
        self.handler_initializer: HandlerInitializer | None = None
        self.response_factory: ErrorResponseFactory | None = None
        self.route_resolver: RouteConfigResolver | None = None
        self.validator: RequestValidator | None = None
        self.bypass_handler: BypassHandler | None = None
        self.behavioral_processor: BehavioralProcessor | None = None
        self._guard_response_factory = DjangoResponseFactory()
        self._cors_handler: CorsHandler | None = (
            CorsHandler(self.config) if self.config.enable_cors else None
        )
        self._handlers_initialized = False

        self._configure_security_headers(self.config)
        self._init_geo_ip_handler()
        self._init_redis_handler()
        self._init_agent_handler()
        self._init_core_components()
        self._init_route_resolver()
        self._build_event_bus_and_contexts()
        self._build_security_pipeline()

    @property
    def guard_response_factory(self) -> DjangoResponseFactory:
        return self._guard_response_factory

    @property
    def agent_stats(self) -> dict[str, Any]:
        if self.agent_handler is None:
            return {"enabled": False}
        handler_stats = cast(Any, self.agent_handler).get_stats()
        return {"enabled": True, **handler_stats}

    def _init_geo_ip_handler(self) -> None:
        self.geo_ip_handler = None
        if self.config.whitelist_countries or self.config.blocked_countries:
            self.geo_ip_handler = self.config.geo_ip_handler

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
            from guard_agent import guard_agent

            self.agent_handler = guard_agent(agent_config)
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
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

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
        if self.route_resolver is None:
            raise RuntimeError("route_resolver not initialized")

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
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)

    def _assert_initialized(self) -> None:
        if self.bypass_handler is None:
            raise RuntimeError("bypass_handler not initialized")
        if self.route_resolver is None:
            raise RuntimeError("route_resolver not initialized")
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        if self.response_factory is None:
            raise RuntimeError("response_factory not initialized")

    def _populate_guard_state(
        self, guard_request: DjangoGuardRequest, request: HttpRequest
    ) -> None:
        from django.urls import Resolver404, resolve

        try:
            match = resolve(request.path)
            view_func = match.func
            if hasattr(view_func, "view_class"):
                view_func = view_func.view_class
            if hasattr(view_func, "_guard_route_id"):
                guard_request.state.guard_route_id = view_func._guard_route_id
                guard_request.state.guard_endpoint_id = (
                    f"{view_func.__module__}.{view_func.__qualname__}"
                )
        except Resolver404:
            guard_request.state.guard_route_unresolved = True

    def _ensure_handlers_initialized(self, request: HttpRequest) -> HttpResponse | None:
        if self._handlers_initialized:
            return None
        try:
            self._initialize_handlers()
        except GuardRedisError as e:
            self.logger.error("Redis unavailable during initialization: %s", e)
            return self._attach_cors_headers(
                self._redis_unavailable_response(), request
            )
        self._handlers_initialized = True
        return None

    def _handle_preflight(
        self,
        request: HttpRequest,
        guard_request: DjangoGuardRequest,
        request_headers: dict[str, str],
    ) -> HttpResponse | None:
        if self._cors_handler is None:
            return None
        if not is_preflight(request.method or "", request_headers):
            return None
        blocking = self._execute_security_pipeline(guard_request)
        if blocking:
            return self._attach_cors_headers(blocking, request)
        return self._build_preflight_response(request_headers)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        early_response = self._ensure_handlers_initialized(request)
        if early_response is not None:
            return early_response

        self._assert_initialized()
        assert self.bypass_handler is not None
        assert self.route_resolver is not None

        cast(Any, request)._guard_request_start_time = time.time()
        guard_request = DjangoGuardRequest(request)
        self._populate_guard_state(guard_request, request)

        request_headers = dict(request.headers)

        def wrapped_call_next(guard_req: SyncGuardRequest) -> GuardResponse:
            django_request = cast(HttpRequest, guard_req.state)
            return DjangoGuardResponse(self.get_response(django_request))

        preflight_response = self._handle_preflight(
            request, guard_request, request_headers
        )
        if preflight_response is not None:
            return preflight_response

        passthrough = self.bypass_handler.handle_passthrough(
            guard_request, wrapped_call_next
        )
        if passthrough is not None:
            return self._attach_cors_headers(unwrap_response(passthrough), request)

        client_ip = extract_client_ip(guard_request, self.config, self.agent_handler)
        route_config = self.route_resolver.get_route_config(guard_request)

        cast(Any, request)._guard_client_ip = client_ip
        cast(Any, request)._guard_route_config = route_config

        bypass = self.bypass_handler.handle_security_bypass(
            guard_request, wrapped_call_next, route_config=route_config
        )
        if bypass is not None:
            return self._attach_cors_headers(unwrap_response(bypass), request)

        blocking = self._execute_security_pipeline(guard_request)
        if blocking:
            return self._attach_cors_headers(blocking, request)

        self._process_behavioral_usage(guard_request, client_ip, route_config)

        response = self.get_response(request)
        return self._finalize_response(request, response, route_config)

    def _execute_security_pipeline(
        self, guard_request: DjangoGuardRequest
    ) -> HttpResponse | None:
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
    ) -> None:
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        if route_config and route_config.behavior_rules and client_ip:
            self.behavioral_processor.process_usage_rules(
                guard_request, client_ip, route_config
            )

    def _build_preflight_response(
        self, request_headers: dict[str, str]
    ) -> HttpResponse:
        assert self._cors_handler is not None
        preflight = self._cors_handler.build_preflight_response(request_headers)
        response = HttpResponse(preflight.body, status=preflight.status_code)
        for key, value in preflight.headers.items():
            response[key] = value
        return response

    def _attach_cors_headers(
        self, response: HttpResponse, request: HttpRequest
    ) -> HttpResponse:
        if self._cors_handler is None:
            return response
        cors_headers = self._cors_handler.build_response_headers(dict(request.headers))
        for key, value in cors_headers.items():
            response[key] = value
        return response

    def _redis_unavailable_response(self) -> HttpResponse:
        guard_response = self.create_error_response(
            503, "Service temporarily unavailable"
        )
        guard_response.headers["Retry-After"] = "5"
        return unwrap_response(guard_response)

    def _finalize_response(
        self,
        request: HttpRequest,
        response: HttpResponse,
        route_config: RouteConfig | None,
    ) -> HttpResponse:
        if self.response_factory is None:
            raise RuntimeError("response_factory not initialized")
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")

        start_time = getattr(request, "_guard_request_start_time", time.time())
        response_time = time.time() - start_time

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
        final = unwrap_response(result)
        if self._cors_handler:
            cors_headers = self._cors_handler.build_response_headers(
                dict(request.headers)
            )
            for key, value in cors_headers.items():
                final[key] = value
        return final

    def _initialize_handlers(self) -> None:
        if self.handler_initializer is None:
            raise RuntimeError("handler_initializer not initialized")
        self.handler_initializer.guard_decorator = self.guard_decorator
        self.handler_initializer.initialize_redis_handlers()
        self.handler_initializer.initialize_agent_integrations()

        if self.handler_initializer.composite_handler is not None:
            self._build_event_bus_and_contexts()

    def _build_security_pipeline(self) -> None:
        from guard_core.sync.core.checks import (
            AuthenticationCheck,
            CloudIpRefreshCheck,
            CloudProviderCheck,
            CustomRequestCheck,
            CustomValidatorsCheck,
            EmergencyModeCheck,
            HttpsEnforcementCheck,
            IpSecurityCheck,
            RateLimitCheck,
            ReferrerCheck,
            RequestLoggingCheck,
            RequestSizeContentCheck,
            RequiredHeadersCheck,
            RouteConfigCheck,
            SecurityCheckPipeline,
            SuspiciousActivityCheck,
            TimeWindowCheck,
            UserAgentCheck,
        )

        checks = [
            RouteConfigCheck(self),
            EmergencyModeCheck(self),
            HttpsEnforcementCheck(self),
            RequestLoggingCheck(self),
            RequestSizeContentCheck(self),
            RequiredHeadersCheck(self),
            AuthenticationCheck(self),
            ReferrerCheck(self),
            CustomValidatorsCheck(self),
            TimeWindowCheck(self),
            CloudIpRefreshCheck(self),
            IpSecurityCheck(self),
            CloudProviderCheck(self),
            UserAgentCheck(self),
            RateLimitCheck(self),
            SuspiciousActivityCheck(self),
            CustomRequestCheck(self),
        ]

        self.security_pipeline = SecurityCheckPipeline(checks)
        self.logger.info(
            f"Security pipeline initialized with {len(checks)} checks: "
            f"{self.security_pipeline.get_check_names()}"
        )

    def _configure_security_headers(self, config: SecurityConfig) -> None:
        if not config.security_headers:
            security_headers_manager.enabled = False
            return

        if not config.security_headers.get("enabled", True):
            security_headers_manager.enabled = False
            return

        security_headers_manager.enabled = True
        headers_config = config.security_headers
        hsts_config = headers_config.get("hsts", {})

        security_headers_manager.configure(
            enabled=headers_config.get("enabled", True),
            csp=headers_config.get("csp"),
            hsts_max_age=hsts_config.get("max_age"),
            hsts_include_subdomains=hsts_config.get("include_subdomains", True),
            hsts_preload=hsts_config.get("preload", False),
            frame_options=headers_config.get("frame_options", "SAMEORIGIN"),
            content_type_options=headers_config.get("content_type_options", "nosniff"),
            xss_protection=headers_config.get("xss_protection", "1; mode=block"),
            referrer_policy=headers_config.get(
                "referrer_policy", "strict-origin-when-cross-origin"
            ),
            permissions_policy=headers_config.get("permissions_policy", "UNSET"),
            custom_headers=headers_config.get("custom"),
            cors_origins=config.cors_allow_origins if config.enable_cors else None,
            cors_allow_credentials=config.cors_allow_credentials,
            cors_allow_methods=config.cors_allow_methods,
            cors_allow_headers=config.cors_allow_headers,
        )

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        self.guard_decorator = decorator_handler
        if self.route_resolver:
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
        response: HttpResponse,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> HttpResponse:
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
    ) -> None:
        if self.behavioral_processor is None:
            raise RuntimeError("behavioral_processor not initialized")
        guard_request = DjangoGuardRequest(request)
        self.behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )

    def _process_decorator_return_rules(
        self,
        request: HttpRequest,
        response: HttpResponse,
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
        cloud_handler.refresh_async(
            providers,
            ttl=self.config.cloud_ip_refresh_interval,
        )
        self.last_cloud_ip_refresh = int(time.time())

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> DjangoGuardResponse:
        if self.response_factory is None:
            raise RuntimeError("response_factory not initialized")
        result: DjangoGuardResponse = cast(
            DjangoGuardResponse,
            self.response_factory.create_error_response(status_code, default_message),
        )
        return result

    def reset(self) -> None:
        self.rate_limit_handler.reset()
