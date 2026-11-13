---
name: djapi-guard
description: DjAPI Guard (import djangoapi_guard), the Django security middleware over guard-core. Use when securing Django apps with IP filtering, rate limiting, penetration detection, security headers, cloud-provider blocking, route-level security decorators, or behavioral rules; when wiring DjangoAPIGuard into MIDDLEWARE and configuring GUARD_SECURITY_CONFIG in settings; when adapting sync HttpRequest/HttpResponse types to guard-core's GuardRequest/GuardResponse protocols; or when debugging sync-callable requirements, Redis connectivity, decorator-route visibility via _guard_route_id and set_decorator_handler, or pytest-django test setup (tests.settings, RequestFactory fixtures). Also use when porting fastapi-guard or flaskapi-guard patterns to Django or choosing the right Guard adapter.
---

# DjAPI Guard

Security middleware for Django: IP filtering, rate limiting, signature-based attack-pattern detection, security headers, and route-level security decorators. Import package is `djangoapi_guard` (distribution name `djapi-guard`). Current as of djapi-guard 6.0.0 over guard-core 5.0.0.

DjAPI Guard is a thin adapter: all security logic (models, handlers, decorators, detection engine, protocols) lives in `guard_core`; this package only bridges Django to it through the unasync-generated `guard_core.sync` mirror. Everything is synchronous.

## Quick Reference

* Install: `uv add djapi-guard` (or `pip install djapi-guard`).
* Wire the middleware: add `djangoapi_guard.middleware.DjangoAPIGuard` to `MIDDLEWARE` and set `GUARD_SECURITY_CONFIG = SecurityConfig(...)` in settings; see [Setup](#setup).
* All behavior is guard-core's `SecurityConfig`; do not mutate handlers directly.
* Route rules: `SecurityDecorator` from the sync mirror writes per-route `RouteConfig` the middleware resolves at request time via `_guard_route_id` on view functions.
* The middleware adopts the `djangoapi_guard.SecurityDecorator` the project built when Django builds it (server load, before the first request), so decorating views is enough. With more than one decorator, set `GUARD_DECORATOR` in settings (instance or dotted path); `middleware.set_decorator_handler` stays for code that holds the middleware.
* Sync only: custom callables must be plain functions, Redis uses `redis.Redis`, IP comes from `request.META`.

## Installation

```bash
uv add djapi-guard             # or: pip install djapi-guard
```

Requires Python 3.10-3.15 and guard-core 5.0.0 or newer (installed automatically). `import djangoapi_guard` pulls the `guard_core.sync` mirror, not the async tree.

## Setup

```python
# settings.py
from djangoapi_guard import SecurityConfig

MIDDLEWARE = [
    # Add DjAPI Guard middleware early in the stack
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.security.SecurityMiddleware",
    # ...
]

GUARD_SECURITY_CONFIG = SecurityConfig(
    whitelist=["192.168.1.0/24"],
    blacklist=["10.0.0.1"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
)
```

`GUARD_SECURITY_CONFIG` must be a `SecurityConfig` instance; when the setting is absent the middleware raises `ImproperlyConfigured` when Django builds it (`middleware.py`: `if config is None: raise ImproperlyConfigured(...)`), there is no default config. `DjangoAPIGuard` follows the standard Django middleware contract (`__init__(get_response)` / `__call__(request)`); when Django builds it, it builds the Redis manager and the agent handler and the security pipeline, and the first request initializes their connections, geo IP and cloud ranges. It runs a `SecurityCheckPipeline` from `guard_core.sync` on each request, built from guard-core's 18 default check classes (fewer when the config leaves a feature off; the first non-`None` `HttpResponse` blocks), handles CORS preflight explicitly, and finalizes passing responses through the response factory (headers, CORS, metrics, behavioral return rules). `middleware.agent_stats` exposes the agent's live buffer drop counters and circuit-breaker state for health-check views.

## Route-Level Security Decorators

Decorators from `guard_core.sync.decorators` write per-route `RouteConfig` objects. The middleware's route resolver maps Django URL patterns to those configs via the `_guard_route_id` attribute set on view functions, for both function-based and class-based views. The middleware adopts the single `djangoapi_guard.SecurityDecorator` the project built (or the one named by `settings.GUARD_DECORATOR`) when Django builds it, and again at the first request for a decorator that only a per-request urlconf loads, so the pipeline is derived from the registered routes without any call into the middleware; checks that only decorators can trigger (auth, referrer, required headers, custom validators, time window, request size/content) are built only when the middleware can see the route config.

`RouteConfig.bypassed_checks` accepts only recognized tokens (`all`, `ip_ban`, `ip`, `clouds`, `rate_limit`, `penetration`); an unknown token is dropped with a warning, so a typo cannot make a check look disabled while it stays enforced.

## Sync-Only Surface

* Custom callables (custom checks, validators, response modifiers, `auth_verifier`) must be plain sync functions: the `guard_core.sync` mirror calls them without awaiting.
* The guard keeps its per-request state in an object of its own and also sets each value as an attribute on the Django request (`request.guard_route_id`, `request.guard_endpoint_id`, ...); an attribute another middleware sets on the request, such as `request.client_ip`, is never read as the guard's own. Route identity is carried by `_guard_route_id` on view functions.
* IP extraction is proxy-aware from `request.META` (`REMOTE_ADDR` / `X-Forwarded-For`).
* Redis (`redis.Redis`) and outbound HTTP (`httpx.Client`) are synchronous, mirroring guard-core's sync handlers.

## Footguns

* **A middleware that sets `request.urlconf` goes before `DjangoAPIGuard`.** One listed after it makes the guard resolve the route in the wrong urlconf; the guard then refuses the request before the view runs (logs one error with `fail_on_misconfiguration=False`).
* **`GUARD_SECURITY_CONFIG` must be a `SecurityConfig` instance.** A plain dict from older docs is not converted by the middleware; construct `SecurityConfig(**settings_dict)` in settings if you keep a dict around.
* **`enable_redis` is off unless a Redis connection field is set.** Since guard-core 5.0.0 Redis turns on exactly when `redis_url`, `redis_prefix` or another `redis_*` connection field is set explicitly (an explicit `enable_redis` always wins), and `enable_redis=True` alone uses `redis_url="redis://localhost:6379"`. With Redis on and no reachable server, stateful checks fail; point `redis_url` at a real instance or leave the Redis fields unset.
* **Custom callables must be sync.** An `async def` custom check, validator, or modifier is not awaited by the sync mirror; write a plain function.
* **Decorator-only checks need exactly one adoptable decorator.** With several `SecurityDecorator` instances and no `settings.GUARD_DECORATOR`, the middleware raises `ImproperlyConfigured` naming the setting when Django builds it (a decorator only a per-request urlconf loads is found at that urlconf's first request, and every request raises until the setting names one). A decorator built from `guard_core.sync.decorators` directly is not registered either; import `SecurityDecorator` from `djangoapi_guard` or set `GUARD_DECORATOR`.
* **`passive_mode=True` logs but never blocks.** Use it to trial rules; switch to `False` once logs confirm the traffic you expect.
* **Tests need Django settings.** The suite uses pytest-django with `DJANGO_SETTINGS_MODULE = "tests.settings"` from pyproject; new test modules should not call `django.setup()` themselves.

## Related Projects

* [guard-core](https://github.com/Guard-Core/guard-core): framework-agnostic security engine (async source + `guard_core.sync` mirror) this adapter wraps.
* [fastapi-guard](https://github.com/Guard-Core/fastapi-guard): FastAPI/Starlette adapter (async reference implementation).
* [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard): Flask extension adapter (sync mirror).
* [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard): Tornado handler/middleware adapter.
* [guard-agent](https://github.com/Guard-Core/guard-agent): telemetry client used by `enable_agent=True`.
* [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp): MCP server for config validation and docs search.
* [guard-core-app](https://github.com/Guard-Core/guard-core-app): SaaS platform the agent reports to.
