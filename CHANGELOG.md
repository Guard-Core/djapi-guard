Changelog
=========

___

v4.3.3 (2026-10-08)
-------------------

Guard-Core org migration
------------------------

Metadata release: PyPI project URLs, the docs canonical domain, and all repository links moved to the Guard-Core org. No code changes.

___

v4.3.2 (2026-09-26)
-------------------

Block response Content-Type, guard-core 4.1.0 tracking (v4.3.2)
---------------------------------------------------------------

- **Fixed** - Blocked responses now declare `Content-Type: text/plain` (#22): the Django response factory left the content type unset, so middleware-generated 403/429/400 pages went out without an explicit content type and clients were left guessing. The factory now sets an explicit `text/plain` content type, matching the engine's reference response factory and the fastapi-guard (#144) and flaskapi-guard (#25) fixes.
- **Compatibility** - The `guard-core` floor moves from `>=4.0.0` to `>=4.1.0` in `pyproject.toml` (no upper bound), so this adapter tracks the guard-core 4.1.0 engine (the exempt_ips skip-list, the recon leading-separator gate, the raw-view recon scan, the cross-engine interop harness). The adapter delegates all security behavior to the engine through the unasync-generated sync mirror; no sync API djapi-guard uses changed shape.

___

v4.3.1 (2026-09-23)
-------------------

guard-core 4.0.x tracking: dependency floor to >=4.0.0, agent docs (v4.3.1)
---------------------------------------------------------------------------

- **Compatibility** - The `guard-core` floor moves from `>=3.15.0` to `>=4.0.0` in `pyproject.toml` (no upper bound), so this adapter tracks the guard-core 4.0.x engine line and is verified against guard-core 4.0.4. No adapter code changed: the delta since 4.3.0 is docs only, hence the patch bump. Since the adapter delegates all security behavior to the engine, no other change is required for the 4.0.x line; guard-core 4.0.0's own breaking changes (grammar-based secret redaction, exact-value `require_headers()` enforcement, `excluded_detection_headers` semantics) are documented in the guard-core changelog.
- **Documentation** - Added `AGENTS.md`/`CLAUDE.md` agent guidance and the djapi-guard package skill, and noted in the access-control decorator docs that an unknown bypass token now warns.
- **Fixed (tests)** - `test_blocked_user_agent_pattern` configured `blocked_user_agents=[r".*crawler.*"]`, which guard-core 4.x's ReDoS validator rejects (adjacent broad unbounded quantifiers), so the suite cannot construct a `SecurityConfig` against the 4.0.x line. The test now blocks through `[Cc]rawler/\d+\.\d+`, which still exercises regex-pattern matching against a real user agent while satisfying the validator.

___

v4.3.0 (2026-08-31)
-------------------

guard-core 3.15.0 compatibility: lazy Redis initialization, fail-secure client-address rejection (v4.3.0)
---------------------------------------------------------------------------------------------------------

- **Fixed** - `DjangoAPIGuard.__init__()` called `HandlerInitializer.initialize_redis_handlers()` eagerly. Django's `load_middleware()` runs this before `convert_exception_to_response` is installed, so a Redis outage at process start raised `GuardRedisError` as a raw unhandled exception at the WSGI boundary instead of a styled response, and since `__init__` runs once per worker process, recovery needed a restart. Initialization is now lazy: `__call__` runs it once, on the first request, through the new `_ensure_handlers_initialized()`. A `GuardRedisError` on that first attempt is caught, logged, and answered with `HttpResponse(status=503)` and `Retry-After: 5`; the initialized flag stays unset, so the next request retries instead of waiting on a restart. `redis_fail_open` and `fail_secure` keep their existing guard-core meaning throughout; no new policy was introduced.
- **Compatibility (GHSA-634g-4wr8-xwxv)** - A request with no client address is now rejected by default (`fail_secure=True`) instead of running the security pipeline with an "unknown" identity; this is guard-core 3.15.0's own fix, this adapter's test suite is brought in line with it here. `test_passthrough_request_no_client_host` now expects `403` instead of `200`.
- **Fixed (tests)** - `test_rate_limiter_redis_errors` asserted that a Redis error during rate limiting always falls back to the in-memory window. guard-core 3.15.0's `check_rate_limit` now honors `redis_fail_open` like every other check: with the default `redis_fail_open=False` it raises `GuardRedisError` instead of returning `None` silently, and only falls back in-memory once `redis_fail_open=True` is set. The test now asserts the raise on the default and the fallback only after opting in.
- **Internal** - The no-client-host 403 above is returned before `call_next` is ever reached, so the `wrapped_call_next` closure in `__call__` lost the only test path that invoked it. It is not dead: `handle_security_bypass` still calls it when a route bypasses all checks (`@security.bypass(["all"])`) outside `passive_mode`. Coverage is restored with a test that exercises that route instead of removing the closure. Splitting the lazy-init check into `_ensure_handlers_initialized()` and the CORS-preflight block into `_handle_preflight()` also keeps `__call__` at cyclomatic complexity rank B.
- **Compatibility** - `guard-core` moves from an unconstrained dependency to `guard-core>=3.15.0` in `pyproject.toml`; no upper bound, the floor moves with each lockstep release. No public API of this adapter changed.

___

v4.2.0 (2026-08-25)
-------------------

guard-core 3.13.0 compatibility: call_next bypass contract, bounded body readers, behavior-scan lockstep (v4.2.0)
-------------------------------------------------------------------------------------------------------------------

- **Fixed** - guard-core 3.12.0 (commit 30f43944) made `BypassHandler.handle_passthrough` and `handle_security_bypass` require a `call_next` callable, so this adapter's calls without it raised `TypeError` on every request and cascaded to HTTP 500. `DjangoAPIGuard.__call__` now builds a `wrapped_call_next` closure over `self.get_response(request)` and passes it to both bypass methods, so the no-client-host passthrough and the `@security.bypass_all` short-circuit run the downstream view and apply the response modifier instead of crashing. Django can supply a real downstream callable because its middleware contract exposes `get_response`, unlike Flask's `before_request` hook.
- **Added** - `DjangoGuardRequest.read_body_prefix(max_bytes)` and `DjangoGuardResponse.read_body_prefix(max_bytes)` implement guard-core 3.12.0's `SyncBoundedBodyReader` / `SyncBoundedResponseBodyReader` protocols, so response-body `return_pattern` rules (`json:`, `regex:`, bare substring) and bounded request-body inspection actually match for the first time in this adapter. `DjangoGuardResponse.read_body_prefix` reads `response.content` and returns `b""` for a `StreamingHttpResponse`, whose `.content` raises `AttributeError`.
- **Fixed (tests)** - The behavioral decorator fixture now sets `behavior_scan_response_body=True` before applying `return_monitor` / `behavior_analysis` decorators, since guard-core 3.12.0 rejects body-reading `return_pattern` rules at decorator-apply time when that flag is off. The stale `mock.patch` of `guard_core.sync.core.checks.implementations.suspicious_activity.detect_penetration_patterns` (removed in guard-core 3.12.0's detection-cache seam) is gone; the test patches `guard_core.sync.utils.detect_penetration_attempt` instead. The `block_all_clouds_default` assertion tracks guard-core 3.13.0's expanded `VALID_CLOUD_PROVIDERS` (DigitalOcean, Vultr, Linode), and the honeypot tests feed `read_body_prefix` on their mocked request because guard-core 3.12.0's body reader calls it when no `content-length` header is present. `--cov-branch` is now in `addopts` so branch coverage is enforced.
- **Compatibility** - Requires guard-core 3.13.0. No public API of this adapter changed: `DjangoAPIGuard`, `DjangoGuardRequest`, `DjangoGuardResponse` and the re-exported decorators keep their signatures; the new `read_body_prefix` methods are additive. Lockstep with flaskapi-guard and fastapi-guard 7.7.0 on the guard-core 3.13.0 line.

___

v4.1.0 (2026-07-29)
-------------------

Unresolvable paths are reported to guard-core (v4.1.0)
-------------------------------------------------------

- **Added** — `_populate_guard_state()` swallowed `Resolver404` and left `request.state` untouched, which is indistinguishable from a view that simply carries no decorators. guard-core reads both as "nothing to enforce", so a resolution failure silently skips every per-route check — the fail-open half of [GHSA-f2vm-w8gq-h378](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378), reported against the Starlette adapter. Django resolves URLs itself, so this adapter has no equivalent matching bug, but it now reports the failure by setting `request.state.guard_route_unresolved`. With guard-core >= 3.7.0 and `SecurityConfig.route_resolution_strict=True`, those requests are logged, emit a `route_unresolved` event, and are blocked with `500`. Behaviour is unchanged by default and on older guard-core, which ignores the attribute.
- **Fixed (tests)** — The IPv6 and mixed IPv4/IPv6 allow-list tests still encoded pre-3.2.0 guard-core semantics, where the blacklist was evaluated before the whitelist. Since guard-core 3.2.0 an explicit whitelist match overrides the blacklist, so an address inside both a whitelist CIDR and a blacklist entry is now served rather than blocked. CI floats guard-core to the latest release and had not run here since 2026-05-28, so these only surfaced now; the adapter itself was correct throughout.
- **Fixed (CI)** — The greetings workflow passed `issue-message`/`pr-message` to `actions/first-interaction@v3`, which expects `issue_message`/`pr_message`, so the job failed on every first-time issue and pull request.

___

v4.0.1 (2026-05-27)
-------------------

guard-core 3.1.0 compatibility + PEP 639 license metadata (v4.0.1)
------------------------------------------------------------------

- **Fixed** — guard-core 3.1.0 narrowed `block_cloud_providers` to `set[Literal["AWS", "GCP", "Azure"]]`; `refresh_cloud_ip_ranges()` now normalizes it to `set[str]` before calling `cloud_handler.refresh_async`, resolving a `set`-invariance mypy error. Runtime behavior is unchanged.
- **Packaging** — Migrated license metadata to PEP 639: `license = "MIT"` (SPDX expression) plus `license-files = ["LICENSE"]`, and dropped the deprecated MIT license classifier.
- **Build** — Removed the unused `setup.py`; the release workflow now builds via `python -m build` (hatchling backend) instead of `python setup.py sdist bdist_wheel`.

___

v4.0.0 (2026-04-29)
-------------------

Fail-secure by default (upstream), agent-stats surface, version reporting (v4.0.0)
----------------------------------------------------------------------------------

- **Breaking (upstream)** — `SecurityConfig.fail_secure` now defaults to `True` (inherited from `guard-core >= 3.0.0`). When any security check raises an unhandled exception, the request is now blocked with HTTP 500 instead of logging and falling through. Bugs in checks that previously slipped past as silent fail-open responses now surface immediately. Restore the old behavior on deployments that depend on it via `SecurityConfig(fail_secure=False)`. Recommended migration: keep the new default, surface any check exceptions in your monitoring, and fix them — the previous default could mask serious bugs. The djapi-guard major bump tracks this upstream change so deployments see a clear signal.
- **Added** — `DjangoAPIGuard.agent_stats` read-only `@property` returning the agent's telemetry buffer state. Returns `{"enabled": False}` when no agent is wired; otherwise returns `{"enabled": True, **agent_handler.get_stats()}` exposing `events_dropped`, `metrics_dropped`, `circuit_breaker_state`, and other agent counters. No caching — fresh on each call. Lets app teams build health endpoints that surface agent-side drops and circuit-breaker trips without scraping the agent directly.
- **Added** — `from djangoapi_guard import __version__` — package version is now exported via `importlib.metadata.version("djapi-guard")` with a `"0.0.0+unknown"` fallback if the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` so application code can wire the djapi-guard version through to the agent for SaaS-side telemetry attribution: `SecurityConfig(agent_guard_version=__version__)`.
- **Compatibility** — `DjangoAPIGuard.agent_stats` is purely additive; no existing API was changed. `__version__` was previously absent; reading it before this release returned `None` via missing-attribute fallback in some integrations.

___

v3.0.0 (2026-04-26)
-------------------

Pipeline-first CORS via guard_core.cors_handler (v3.0.0)
--------------------------------------------------------

- **Breaking** — Preflight `OPTIONS` requests are now subject to the security pipeline. Previously the middleware short-circuited preflights ahead of `_execute_security_pipeline` (the `if config.enable_cors and request.method == "OPTIONS"` block at line 227), allowing banned IPs and rate-limited clients to preflight freely.
- **Fixed** — Cross-origin preflight requests to passthrough paths (e.g. `exclude_paths=["/health"]`) now receive a valid CORS response. Preflight handling runs ahead of the passthrough/bypass short-circuit so the browser permission check works for excluded paths.
- **Fixed** — Cross-origin GETs to passthrough/bypass paths now carry CORS headers on their responses.
- **Fixed (latent)** — `middleware.py` was importing `BaseSecurityDecorator` and `RouteConfig` from `guard_core.decorators.base` (the async path) when it should have been using `guard_core.sync.decorators.base`. Sync/async protocol mismatches cascaded from there. Surfaced after removing the `[[tool.mypy.overrides]] follow_imports = "skip"` block.
- **Fixed (latent)** — `cloud_handler.refresh(ttl=...)` was being called with a `ttl` kwarg the method does not accept; correct call is `refresh_async()`.
- **Fixed (latent)** — 4 tests passed `agent_model="..."` to `SecurityConfig`; that field does not exist on the model.
- **Internal** — CORS preflight handling moved to the shared `guard_core.sync.handlers.cors_handler.CorsHandler` module. Removed all six `[[tool.mypy.overrides]]` suppression blocks (`redis.*`, `guard_agent.*`, `guard_core.*`, `django.*`, `examples.*`, `example_app.*`/`advanced_app.*`). Installed `django-stubs` as dev dep; `redis` 7.x, `guard-core` 2.2.0, `guard-agent` 2.2.0 all ship `py.typed`. Stripped `[tool.uv.sources] guard-core` local-path block from committed pyproject.toml. Added `reset_ratelimit_singleton` autouse fixture to `tests/conftest.py` so test runs no longer accumulate rate-limit state across tests.
- **Requires** — `guard-core>=2.2.0` (declared as unconstrained `guard-core` in pyproject; documented here for upgrade guidance).

___

v2.2.0 (2026-04-25)
-------------------

guard-core 2.0.0 compatibility (v2.2.0)
---------------------------------------

- **Compat** — Requires guard-core 2.0.0 or newer. Adapter middleware updated to match the new `suspicious_request_counts: dict[str, dict[str, int]]` protocol shape and `DetectionResult` return type. User code that didn't reach into those internals is unaffected.
- **Changed** — `DjangoAPIGuard.suspicious_request_counts` is now `dict[str, dict[str, int]]` to mirror the per-IP, per-category counters introduced by guard-core 2.0.0.
- **Tests** — `tests/test_middleware.py` mocks for `detect_penetration_patterns` and `detect_penetration_attempt` now return `DetectionResult(is_threat=..., trigger_info=...)` instead of the legacy `(bool, str)` tuple.

___

v2.1.1 (2026-04-25)
-------------------

Integration fixes for OTel + enrichment pipeline (v2.1.1)
---------------------------------------------------------

- **Fixed** — After composite construction, `self.agent_handler` is rebound from the bare `guard-agent` client to the composite. Downstream callers that receive `middleware.agent_handler` (most notably `guard_core.utils.extract_client_ip → send_agent_event`) now route through the composite, so enrichment and OTel see every event.
- **Fixed** — `BehavioralContext` now receives `handler_initializer.behavior_tracker`, matching the guard-core 1.2.1 wiring. This closes the architectural gap so `guard.behavior.recent_event_count` populates end-to-end when `enable_enrichment=True`.
- **Added** — `tests/test_middleware_lifecycle.py` — regression tests pinning the agent_handler rebind and behavior_tracker threading, plus coverage for unbuilt-pipeline and early-decorator-handler paths.
- **Requires** — `guard-core>=1.2.1` for the matching OTLP endpoint normalization and `BehaviorTracker` wiring fixes. Install the latest with `uv add djapi-guard guard-core` or `pip install -U djapi-guard guard-core`.
- **User-visible impact** — Users with `enable_otel=True`, `enable_logfire=True`, or `enable_enrichment=True` previously saw silent drops on a portion of events because callers using `middleware.agent_handler` directly bypassed the composite handler. After this release every downstream caller routes through the composite, so all events flow through telemetry and enrichment as configured.

___

v2.1.0 (2026-04-24)
-------------------

Telemetry pipeline wiring fix (v2.1.0)
--------------------------------------

Adopts guard-core 1.1.0 and fixes a middleware wiring bug that prevented OpenTelemetry, Logfire, and event/metric/check-log muting from seeing anything emitted by the request-path security pipeline.

- **Fixed** — `DjangoAPIGuard.__init__` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` in `_init_core_components()` using the bare `guard_agent` handler (or `None`). `_initialize_handlers()` then called `HandlerInitializer.initialize_agent_integrations()` which built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were already frozen on the bare handler. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release splits construction into `_init_core_components()` (handler_initializer only), `_init_route_resolver()`, and `_build_event_bus_and_contexts()` — the last of which consults `handler_initializer.composite_handler` and uses `build_event_bus()` / `build_metrics_collector()` when the composite is available. `_initialize_handlers()` now re-invokes `_build_event_bus_and_contexts()` after `initialize_agent_integrations()` so the dependent contexts (`ResponseContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`) bind to the post-init event bus.
- **Added** — `tests/test_middleware_wiring.py` — four regression tests that pin `mw.event_bus.agent_handler` and `mw.metrics_collector.agent_handler` to `CompositeAgentHandler` after instantiation when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** — `guard-core>=1.1.0,<2.0.0`.
- **User-visible impact** — Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) — but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.
- **Tests** — `tests/test_middleware.py` — the two coverage tests that pinned the old `_init_routing_and_validation` guards (`test_init_routing_event_bus_none`, `test_init_routing_response_factory_none`) are replaced with `test_build_event_bus_handler_initializer_none` and `test_build_event_bus_route_resolver_none` covering the new guards in `_build_event_bus_and_contexts`.

___

v2.0.0 (2026-03-26)
-------------------

Major Release (v2.0.0)
------------

- **Guard-Core migration**: DjangoAPI Guard is now a thin adapter over [guard-core](https://github.com/rennf93/guard-core), the framework-agnostic security engine. All security logic (17 checks, 8 handlers, detection engine) lives in guard-core; this package provides only the Django integration layer.
- **Production/Stable status**: Development status upgraded from Alpha to Production/Stable.
- **Zero breaking changes to public API**: All existing imports (`from djangoapi_guard import SecurityConfig`, `from djangoapi_guard import DjangoAPIGuard`, etc.) continue to work exactly as before.
- **Shared engine across frameworks**: The same security engine now powers [fastapi-guard](https://github.com/rennf93/fastapi-guard) and [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), ensuring consistent security behavior across all three frameworks.

___

v1.0.1 (2026-03-16)
-------------------

Bug Fixes (v1.0.1)
------------

- **Per-endpoint rate limit check**: Fixed rate limit check to properly evaluate endpoint-specific rate limits. Previously, the rate limit check was only evaluating global rate limits.

___

v1.0.0 (2026-03-15)
-------------------

Initial Release (v1.0.0)
------------

- Initial release of DjangoAPI Guard
- IP whitelisting/blacklisting with CIDR support
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Security headers management
- CORS configuration
- Emergency mode

___
