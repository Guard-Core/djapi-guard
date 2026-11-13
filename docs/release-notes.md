Release Notes
=============

___

Unreleased
----------

- **Changed** - **A decorator defined in a per-request urlconf is enforced, and two decorators with none configured are refused (release note, behavior change).** The middleware adopted a decorator from `ROOT_URLCONF` only, so a decorator created in a urlconf that a middleware chooses per request (`request.urlconf`, django-hosts and similar) was never adopted and its routes ran with every decorator rule off. The first request that chooses a urlconf now reads its routes and adopts the one decorator that is registered. When two decorators are registered, none is named by `settings.GUARD_DECORATOR` and the one in use was adopted automatically, every request raises `ImproperlyConfigured` naming both fixes (set `GUARD_DECORATOR`, or share one decorator instance across the urlconfs); with `fail_on_misconfiguration=False` one error is logged and the decorator in use is kept. A decorator named by the setting or given to `set_decorator_handler` is never refused. Requests served before the first request to that urlconf are not refused, because nothing at startup can see its module without `GUARD_URLCONFS`.

- **Added** - **`GUARD_URLCONFS` makes the server-load checks read the urlconfs a middleware chooses per request.** A list of dotted urlconf modules (default empty). With it set, the `exclude_paths` route check, the `detection_exclusion(path_params=...)` report, the `djangoapi_guard.E001` and `W001` system check and decorator adoption read each listed urlconf like `ROOT_URLCONF`, so an `exclude_paths` entry that matches only a listed urlconf is no longer called a typo, and a decorator defined only there is adopted and counted at server load. An entry that does not import raises `ImproperlyConfigured`. A request that chooses a urlconf that is neither `ROOT_URLCONF` nor listed logs one warning for it, when `exclude_paths` has an entry beyond the defaults or that urlconf declares `detection_exclusion(path_params=...)`.

- **Fixed** - **A route added after startup is checked when it is added, not when it is first requested (release note, behavior change).** The check of every `detection_exclusion(path_params=...)` declaration used to run at startup and at the first request, so a pattern appended to the urlconf after that was only caught when someone requested it, and a host urlconf chosen through `request.urlconf` was never read. The middleware now compares the pattern lists of the urlconf the request uses, and of every nested `include()`, with the ones it last checked, on each request, at the cost of the number of lists and not of routes, and walks the whole table again only when one changed, under a lock. Without `fail_on_misconfiguration` each new problem is warned once; with it every request is refused with a fresh `MisconfigurationError` until the route is fixed, and one line is logged per change. The state is kept per resolver and dies with it.

- **Changed** - **`fail_on_misconfiguration` now governs the first-request report of a `detection_exclusion(path_params=...)` problem (release note, behavior change).** The first request used to log one WARNING whatever the flag said; with `fail_on_misconfiguration=True` the first request, and every request while the problem stands, now raises the engine's error (a `ValueError` listing every problem) and Django answers 500. With the flag off the first request logs one WARNING per problem, as before, and the system check keeps its Error (flag on) or Warning (flag off). The system check message and the log line now share the one guard-core helper's text. Each problem carries a stable kind, `decorator.detection_exclusion.param_not_in_template` or `decorator.detection_exclusion.param_without_literal_segment`, from one guard-core helper that every adapter shares.

- **Added** - **`release_app(config)` is the host and test API for releasing an app.** Django has no app-shutdown event (`request_finished` fires on every request), so `DjangoAPIGuard` never releases its app by itself and N requests through an app leave the module-level default binding as it was. A host that stops a worker, and a test suite that builds several apps, call `djangoapi_guard.release_app(config)` (guard-core's sync `release_app`, now re-exported) with `settings.GUARD_SECURITY_CONFIG`; the default managers then go to the next app at that moment instead of whenever the cyclic garbage collector frees the earlier app. An app that is never released keeps the collector-timed handoff of guard-core 5.0.0. Calling it twice is harmless, and a request that reaches a released app is still screened with the managers its pipeline captured at build time. Never call it from `request_finished` or any per-request hook: it would release a live app on every request. The suite's `tests/conftest.py` releases every app's config between tests.

- **Fixed** - **The `guard-core` floor is `>=5.0.0,<6`.** This release's code uses engine names that guard-core 4.4.x does not have, so an environment that kept 4.4.x imported a broken package. Upgrading now installs guard-core 5.x and stops below the next major. An install that must stay on guard-core 4.x stays on the previous release of this package. The lock follows the floor once guard-core 5.0.0 is published.

- **Fixed** - **Every shipped dependency declares a lower bound with no known advisory.** The declared requirement is now `django>=5.2.17,!=6.0,!=6.0.1,!=6.0.2,!=6.0.3,!=6.0.4,!=6.0.5,!=6.0.6,!=6.0.7,!=6.1` (it had no bound). This narrows the supported Django range on purpose: Django 4.2, 5.0 and 5.1 and 5.2 before 5.2.17 have open advisories (4.2.30 has 10, 5.0.14 has 14, 5.1.15 has 10; 5.2.17, 6.0.8 and 6.1.1 have none), and the series are out of upstream support (4.2 LTS ended 2026-04-07, 5.0 2025-04-02, 5.1 2025-12-03). Django 6.0.0 to 6.0.7 and 6.1.0 have open advisories too and are excluded, because the CVE gate tests only the lowest release. The suite passes with Django at 5.2.17 on Python 3.10 and 3.11.

- **Fixed** - **The lock moved past every known advisory and the supply chain is pinned.** The lock moves `certifi` to 2026.10.18, `joserfc` to 1.7.6 and `nltk` to 3.10.4; no declared floor changes. A new CVE gate (`cve-scan.yml`, run on every pull request, push, daily and before a release) fails on any open advisory in the lock, in the declared dependency floors and in the published image, and every workflow action and tool install is pinned to a commit or version.

- **Fixed** - **A scan that only waited for a regex worker answers 503 with `Retry-After`, not 400.** With 64 uploads in flight on Flask and Django, guard-core 5.0.0 refused 1 to 4 of 64 benign 1 MiB uploads: a scan that got no regex worker within `detection_compiler_timeout` answered `400 Request body could not be read`, and a started scan that waited for the GIL past that time was refused as `400 Suspicious activity detected` with a strike. guard-core now runs its six windowed built-in rows on the request thread, judges a started custom scan by its worker's CPU, and answers a scan that got no worker in time with `503` and `Retry-After` set to `ceil(detection_compiler_timeout)`, no strike, and its own log line and event naming the wait and the surface. `custom_error_responses[503]` replaces the message, a real body read failure keeps its `400`, and `fail_secure=False` and passive mode pass with the event. `djapi-guard` carries a test that holds the regex pool busy and checks the `503`, the `Retry-After` header and the custom message.

- **Fixed** - **The detection engine pages state numbers measured on guard-core 5.0.0, each with the command that reproduces it.** The benchmark section of `performance-tuning.md` carries the engine's own CPU time per detection (interleaved with an A/A arm) and the monitor's average per-pattern time measured with `python -m perf_gate.detection_components` from a guard-core checkout. The measurement also corrected a remark: capture groups cost nothing measurable on the example pattern, so `(?:...)` is not a speed-up by itself.

- **Fixed** - **Every shipped Markdown example and stated default matches the 5.0.0 API, and a test keeps it true.** `tests/test_markdown_python_blocks.py` parses every Python block of the README, `docs/`, the examples and the packaged skill files, runs the blocks of each file one after another in a sandbox with no network, and checks every Guard import, call, keyword and attribute against the installed guard-core 5.0.0 objects. It also compares every default and range a table or bullet states with `SecurityConfig`, checks the documented signature listings, and checks the telemetry mute values against the engine. It failed on the old pages, and the pages now show what 5.0.0 accepts: `djangoapi_guard.utils.detect_penetration_attempt` and `djangoapi_guard.protocols.geo_ip_protocol` (neither module exists), a README geolocation example that passed the `GeoIPHandler` class where `SecurityConfig` needs an instance, and `SusPatternsManager` imported from `djangoapi_guard` (it lives in `guard_core.sync.handlers.suspatterns_handler`); country decorators and return monitors shown without the geo source and the response body scanning 5.0.0 requires, `block_user_agents` patterns such as `.*bot.*` that the ReDoS validator refuses, `blocked_countries` set together with `whitelist_countries`, custom GeoIP handler listings that left out members, `avg_execution_time` where the page said `average_time`, the `csp` example in `docs/index.md` (a mapping of directives to sources), `CloudManager.refresh` shown with a `ttl` it does not take, the check order (up to 18 checks), the telemetry mute values, and stale defaults (`rate_limit` 120, `enable_redis` off unless a Redis field is set, `redis_prefix` `guard_core:`, `trust_x_forwarded_proto` `False`, Python 3.10 to 3.15). The packaged skill file no longer says it is current for an older release or that `enable_redis` defaults to `True`.

- **Added** - **A test runs the packaged agent skill file.** Every Python block of `djangoapi_guard/.agents/skills/djapi-guard/SKILL.md` is executed and the middleware path it lists is imported, so a renamed or missing API in the skill file fails the suite. The file needed no change.

- **Breaking changes** - **A misconfigured route now stops the server at start instead of answering 500 to every request.** `DjangoAPIGuard.__init__` imports the URLconf, adopts the decorator and calls the engine's new `HandlerInitializer.report_route_misconfigurations()` (no Redis, no network), so a country rule or geo rate limit with no geo source, an unreachable ban threshold and the other route reports run when Django builds the middleware. With `fail_on_misconfiguration=True` (the 5.0.0 engine default) a `block_countries`, `allow_countries` or `geo_rate_limit` whose config has neither `geo_ip_handler` nor `ipinfo_token` raises `ValueError` when the view module is imported; `fail_on_misconfiguration=False` starts and logs the warning once. A decorator built from a config without a geo source and paired with a settings config that has `ipinfo_token` now raises at import: give the decorator's config the token. Needs the guard-core release that carries `report_route_misconfigurations`.

- **Fixed** - **Country rules need no global rule.** The middleware keeps `config.geo_ip_handler` whenever one is configured and reads back the handler the sync engine runs with: a handler built from `ipinfo_token` is now the synchronous `IPInfoManager`, so `blocked_countries` blocks (it never did, the engine called the async manager without awaiting it), and a route-level `block_countries`, `allow_countries` or `geo_rate_limit` works without a global country rule. The examples no longer carry a placeholder `blocked_countries`.

- **Fixed** - **Route decorators now work as the README shows.** `DjangoAPIGuard` started with no decorator and Django builds the middleware, so a view decorated with `SecurityDecorator` had every decorator-only check (route rate limits, IP and country rules, size and content-type limits, behavior rules) silently off unless code reached the middleware instance. The middleware now adopts the `djangoapi_guard.SecurityDecorator` the project built when Django builds it (at server load, together with the URLconf import, before the first request); a decorator built after that point is adopted on the first request. Projects with several decorators name one in `settings.GUARD_DECORATOR` (instance or dotted path). With several and no setting, the middleware raises `ImproperlyConfigured` when Django builds it (at server load, together with the URLconf import, before the first request) naming `GUARD_DECORATOR` and the registered decorators. With a decorator that was not built through `djangoapi_guard`, one warning per process names the fix. `set_decorator_handler` is unchanged.

- **Fixed** - **The middleware runs the engine's check order.** It builds its pipeline with the engine's `build_default_pipeline` instead of a list of its own, so the order is the engine's and a later engine change reaches it. IP security, cloud, user agent and rate limiting now run before `required_headers`, `authentication`, `referrer`, `custom_validators` and `time_window`: a banned IP that also lacks a required header gets the ban answer, and a request over the rate limit that also fails authentication gets `429`. The `cors_preflight` check now runs in the engine's position, between `user_agent` and `rate_limit`. The startup log line is unchanged in form, and the pipeline holds only the checks the config and the registered routes need, as in fastapi-guard.

- **Breaking changes** - **The base install no longer carries `redis`, `maxminddb`, `aiohttp` or `requests`.** They follow guard-core 5.0.0, whose base install is `cachetools`, `pydantic` and `typing-extensions`. `djapi-guard` gains three extras that forward to guard-core's: `djapi-guard[redis]` (the Redis client, needed when Redis is on), `djapi-guard[geo]` (`maxminddb` and the downloader of the built-in GeoIP manager, needed for country rules) and `djapi-guard[cloud]` (`aiohttp` and `requests`, needed for cloud-provider blocking). A config that needs a package you did not install is refused when `SecurityConfig` is built, with a message that names the adapter's extra, and the Redis, cloud, geo and rate-limit names the package re-exports load lazily, so the import works without them. Add the extra your config uses, for example `pip install "djapi-guard[redis,geo]"`.

- **Added** - **The route gate: the middleware records the matched route template and answers `static_file_exists`.** `_populate_guard_state` records the resolved route's template (`ResolverMatch.route`) as `request.guard_route_template` next to `guard_route_unresolved`, which guard-core's route gate reads: a script path such as `/shop/cart.php` is clean only when the route literally contains its extension, and a `<path:name>` converter does not. A `.ts` or `.map` path whose URL pattern is `django.views.static.serve` (also behind a decorator) is clean when `safe_join` keeps it inside `document_root` and the file exists, and `django.contrib.staticfiles` `serve` is answered through the staticfiles finders; a traversal, a missing file and any other view keep the path flagged as in 5.0.0, and nothing is cached. The middleware also lists its static route prefixes (`static_route_prefixes()`) so guard-core can warn once about an `exclude_paths` entry that matches no route.

- **Changed (behavior)** - **`endpoint_rate_limits` keys follow the Django resolver, and every routed view has a handler identity.** Each key is resolved through the URLconf at startup and when a dynamic rule is applied, so a key counts the requests that reach the same view with the same path parameters, and a key that matches no route falls back to a normalized match (`//` collapsed, dot segments resolved, one trailing slash stripped, case kept). The middleware sets the handler identity for every routed view, decorated or not, so `rate_limit` buckets key by the route. Two paths pointing at one view share one budget (`path("login/", sign_in)` and `path("signin/", sign_in)` count against one limit, so a stacked path cannot get a fresh budget), and a generic view routed on many paths shares one too, so give each limited path its own view.

- **Added** - **Request bodies are read with an idle deadline from the server's socket.** `DjangoGuardRequest.read_body_prefix_until_idle(max_bytes, idle_timeout)` reads at most `max_bytes` from the request's stream in chunks and maps a socket timeout to `BodyReadStalledError`. Where the server exposes its socket in `META` (`gunicorn.socket`, `werkzeug.socket`) the read sets the idle timeout on it and restores the old one; on any other server (`runserver` and `wsgiref`, where the handler timeout is the deadline) the server's own socket timeout reaches the engine as the same error. The consumed bytes go back, because the request's stream is replaced by one that replays them, so form parsing and the view still read the whole body. A client that sends headers and no body gets `408` under `fail_secure` (a log line and a `suspicious_request` event, no strike) and a slow client that keeps sending gets through.

- **Changed (behavior)** - **Throttle rules answer `429`, route and global, unrouted paths included.** The adapter called `process_usage_rules` as a bare statement and dropped the refusal it returned, so a usage `throttle` rule recorded its trips and never refused. It now answers the engine's `429 Too many requests` with `Retry-After` for route and global throttle rules on routed and unrouted paths, and passes itself to the behavioral processor so `correlate_with_detection` sees the detection hits. guard-core 5.0.0 also enforces the rules in its own pipeline and each request records its hit once, so the adapter's call and the engine's never count a request twice. If your clients began to receive `429` after the upgrade, a throttle rule you configured is now doing what it says: raise its threshold or window.

- **Changed (behavior)** - **`security_headers` settings are applied by guard-core's `apply_security_headers_settings`, and the startup call of the global manager no longer overrides other apps.** The adapter's own reader is gone: a partial block merges over the engine defaults (a block that leaves `xss_protection` out sends `X-XSS-Protection: 0`, where the adapter's reader sent `1; mode=block`), and `hsts: None` configures the manager instead of raising. The middleware's own call to the global `security_headers_manager.configure(...)` passes `override_apps=False`, so it fills the manager's own state as before and no longer sets the cross-app override to this app's config: two apps with different CSPs each keep their own. A call you make yourself with `override_apps=True` still reaches every guarded app, and one without it reaches none.

- **Changed (behavior)** - **`Origin` is merged into the view's `Vary`.** The CORS pass replaced the response's `Vary` with the engine's, dropping a `Vary` the view had set (`Accept-Encoding`, for one). It now merges `Origin` through `django.utils.cache.patch_vary_headers`, which keeps a value that already lists `Origin` and collapses to `*` when the view sent `*`. Django resolves a route without regard to the method, so `route_resolution_strict` never produces a `405` here and no `Allow` lookup is needed.

- **Changed (behavior)** - **`passive_mode` admits a request when Redis is down at initialization.** A `GuardRedisError` from the first initialization answered `503`. Under `passive_mode` it now passes the request through unguarded with a sampled log line. Without `passive_mode` the answer stays `503` with `Retry-After`.

- **Fixed** - **A ban made inside a view goes through its own app.** The adapter holds the app's scope across the view and releases it in a `finally`, so a ban, an event or a Redis write made from a handler of one app goes through that app's own handlers, trusted proxies and Redis prefix when two apps share a process.

- **Fixed** - **`agent_stats` answers with the agent on.** Once the engine swapped in its `CompositeAgentHandler`, `agent_stats` raised `AttributeError` because the composite had no `get_stats`. The adapter now calls `get_stats` on the handler without a cast, and guard-core returns the stats of the handlers that have one.

- **Added** - **The response wrapper declares `body_is_materialized`.** The wrapper reports `isinstance HttpResponse and not streaming`, so the engine hands a body-reading `custom_response_modifier` the real response for a plain response and takes its bounded path for a streamed one. `StreamingHttpResponse` and `FileResponse` are teed through `streaming_content` (an async stream is never consumed): a declared `Content-Length` within the cap is read to its end, any other stream stops at the first chunk, and every byte still reaches the client. `DjangoGuardResponse` is typed `HttpResponseBase` like Django's `get_response`. A streamed body now reaches `return_pattern` scans, and a refused modifier read raises the engine's `ResponseBodyUnavailableError`.

- **Changed** - **The config is a `SecurityConfig[SyncGuardRequest]`, and the middleware has no `cast` and no explicit `Any`.** guard-core 5.0.0's `SecurityConfig` is generic in the request type, and a WSGI adopter who runs `mypy` writes `SecurityConfig[SyncGuardRequest](...)` out (mypy does not always infer it from a sync check); a plain `SecurityConfig(...)` is the async form. The event bus, route resolver and geo handler are built at construction so the engine's middleware protocol types them non-optional, the agent handler is typed `SyncAgentHandlerProtocol`, and `mypy` runs with `disallow_any_explicit` on `djangoapi_guard` behind a ratchet. `_finalize_response` now calls `_process_response` for the shared work and attaches CORS afterwards: both names and signatures stay and the response is unchanged.

- **Added** - **Python 3.15 is supported.** `requires-python` is now `>=3.10,<3.16` and 3.15 joins the test matrix as a required version.

- **Fixed** - **Decorator routes, `exclude_paths` and the route gate see the path without the script prefix.** The middleware resolved `request.path`, which carries `SCRIPT_NAME` (a sub-path mount or `FORCE_SCRIPT_NAME`), where Django resolves `request.path_info`. Under a prefix no route resolved, so a decorator such as `require_ip(whitelist=...)` was not enforced and `route_resolution_strict=True` answered `404` for every path. `DjangoGuardRequest.url_path` and the route resolution now use `request.path_info`, so `exclude_paths` and path rules match the path the URLconf matches, without the prefix.

- **Fixed** - **The first request initializes the handlers once.** Concurrent first requests each ran the lazy initialization and rebuilt the event bus, bypass handler and behavioral processor while others were served. The initialization now takes a lock, and the requests that waited for it find it done.

- **Fixed** - **Routes are resolved in the urlconf the request was given.** The middleware resolved with the thread-local urlconf, not `request.urlconf` set by an earlier middleware (django-hosts and similar), so a route decorated in the per-request urlconf was seen as unresolved and its decorators were not applied: `require_headers` answered `200` without the header. Route resolution, the route gate and the endpoint identity now use `request.urlconf` when it is set.

- **Fixed** - **Route decorators on class-based views are enforced however they are applied.** Only a decorator applied to the class itself was enforced; one applied to `Class.as_view()`, through `method_decorator` on a method or through `method_decorator(name="dispatch")` was silently not (`200`, no warning), because the middleware replaced the resolved function by its class before it looked for the decorator mark. It now looks at the resolved function, the class, `dispatch` and the method of the request's HTTP verb (`head` falls back to `get`), so a method decorator guards its own method only. Decorators applied in more than one place of one view are not merged: the first place is enforced and one warning per view names them.

- **Fixed** - **The agent is flushed and stopped at process exit.** The adapter started the agent (a loop thread) and never stopped it, so the events and metrics it still buffered were lost when the process ended. An `atexit` hook, registered once per handler, now calls the agent's `stop()` (which flushes the buffer) and waits at most 5 seconds for it: the agent's own `stop()` retries a refused endpoint for about 14 seconds and a black-holed one for over a minute, and exit no longer waits for that. Events still unsent after the bound are dropped, with one warning.

- **Fixed (docs)** - **The README states how a dynamic rule's `endpoint_rate_limits` combine with the config.** A dynamic rule's `endpoint_rate_limits` merge per endpoint: the rule's value wins for the endpoints it names and your static limits stay for the rest.

- **Fixed** - **A response a custom hook returns without a `Content-Type` is served as `text/plain; charset=utf-8`.** `unwrap_response` handed the framework default type (`text/html`, or a sniffed one) to a foreign `GuardResponse` that named none, so a `custom_request_check` response that echoes request text was a reflected XSS. The unwrapped response now carries `text/plain; charset=utf-8` when no header named `Content-Type` in any case is present; a `Content-Type` the hook sets, in any case, is kept as it is. Behavior change for a hook that returned HTML or JSON without naming the type: it now has to set `Content-Type` itself.

___

v5.0.0 (2026-10-15)
-------------------

Engine routing parity with fastapi-guard, required GUARD_SECURITY_CONFIG (v5.0.0)
---------------------------------------------------------------------------------

- **Breaking changes** - **A missing `settings.GUARD_SECURITY_CONFIG` now raises `ImproperlyConfigured`** (#39, closes #38). `DjangoAPIGuard` used to fall back silently to `SecurityConfig()` defaults when the setting was absent or `None`, which ran the guard with a configuration you never chose. It now fails at startup with a message naming the setting.
- **Breaking changes** - **Upgrade action** - Define `GUARD_SECURITY_CONFIG = SecurityConfig(...)` in your Django settings before upgrading. If you relied on the defaults, set `GUARD_SECURITY_CONFIG = SecurityConfig()` explicitly.

- **Fixed** - **Global behavioral return rules now run.** `global_behavior_rules` are passed to the engine response pass at both response-pass call sites, as fastapi-guard does.

- **Documentation and tests** - The README examples now build a real `SecurityConfig` instead of relying on the fallback, and the advanced example uses the engine request and response protocols and the `status:404` return pattern syntax.
- **Documentation and tests** - `tests/test_engine_parity.py` drives the middleware over Django's real URL resolution and views with the real engine bypass handler and response factory. The test that asserted the fallback now asserts the error.

- **Compatibility** - The `guard-core` floor rises from `>=4.1.0` to `>=4.4.0`, so upgrading djapi-guard also brings the guard-core 4.4.0 detection and dynamic rule fixes (Cookie header scanned per pair, the per-request scan budget, the semantic-only header opt-out and dynamic rule versions applied over the base config).

- **Chore** - The sponsor button points at the maintainer's Sponsors page, the mkdocs `site_url` drops `/latest/` so canonical URLs resolve, the README markdown lint errors that blocked the docs deploy are fixed and the README was brought to content parity, a CODEOWNERS file was added, the family Discord relay workflow was added, and the `upload-sarif` action was bumped (#29, #30, #31, #32, #34, #36, #37).

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

- **Added** - `_populate_guard_state()` swallowed `Resolver404` and left `request.state` untouched, which is indistinguishable from a view that simply carries no decorators. guard-core reads both as "nothing to enforce", so a resolution failure silently skips every per-route check - the fail-open half of [GHSA-f2vm-w8gq-h378](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378), reported against the Starlette adapter. Django resolves URLs itself, so this adapter has no equivalent matching bug, but it now reports the failure by setting `request.state.guard_route_unresolved`. With guard-core >= 3.7.0 and `SecurityConfig.route_resolution_strict=True`, those requests are logged, emit a `route_unresolved` event, and are blocked with `500`. Behaviour is unchanged by default and on older guard-core, which ignores the attribute.
- **Fixed (tests)** - The IPv6 and mixed IPv4/IPv6 allow-list tests still encoded pre-3.2.0 guard-core semantics, where the blacklist was evaluated before the whitelist. Since guard-core 3.2.0 an explicit whitelist match overrides the blacklist, so an address inside both a whitelist CIDR and a blacklist entry is now served rather than blocked. CI floats guard-core to the latest release and had not run here since 2026-05-28, so these only surfaced now; the adapter itself was correct throughout.
- **Fixed (CI)** - The greetings workflow passed `issue-message`/`pr-message` to `actions/first-interaction@v3`, which expects `issue_message`/`pr_message`, so the job failed on every first-time issue and pull request.

___

v4.0.1 (2026-05-27)
-------------------

guard-core 3.1.0 compatibility + PEP 639 license metadata (v4.0.1)
------------------------------------------------------------------

- **Fixed** - guard-core 3.1.0 narrowed `block_cloud_providers` to `set[Literal["AWS", "GCP", "Azure"]]`; `refresh_cloud_ip_ranges()` now normalizes it to `set[str]` before calling `cloud_handler.refresh_async`, resolving a `set`-invariance mypy error. Runtime behavior is unchanged.
- **Packaging** - Migrated license metadata to PEP 639: `license = "MIT"` (SPDX expression) plus `license-files = ["LICENSE"]`, and dropped the deprecated MIT license classifier.
- **Build** - Removed the unused `setup.py`; the release workflow now builds via `python -m build` (hatchling backend) instead of `python setup.py sdist bdist_wheel`.

___

v4.0.0 (2026-04-29)
-------------------

Fail-secure by default (upstream), agent-stats surface, version reporting (v4.0.0)
----------------------------------------------------------------------------------

- **Breaking (upstream)** - `SecurityConfig.fail_secure` now defaults to `True` (inherited from `guard-core >= 3.0.0`). When any security check raises an unhandled exception, the request is now blocked with HTTP 500 instead of logging and falling through. Bugs in checks that previously slipped past as silent fail-open responses now surface immediately. Restore the old behavior on deployments that depend on it via `SecurityConfig(fail_secure=False)`. Recommended migration: keep the new default, surface any check exceptions in your monitoring, and fix them - the previous default could mask serious bugs. The djapi-guard major bump tracks this upstream change so deployments see a clear signal.
- **Added** - `DjangoAPIGuard.agent_stats` read-only `@property` returning the agent's telemetry buffer state. Returns `{"enabled": False}` when no agent is wired; otherwise returns `{"enabled": True, **agent_handler.get_stats()}` exposing `events_dropped`, `metrics_dropped`, `circuit_breaker_state`, and other agent counters. No caching - fresh on each call. Lets app teams build health endpoints that surface agent-side drops and circuit-breaker trips without scraping the agent directly.
- **Added** - `from djangoapi_guard import __version__` - package version is now exported via `importlib.metadata.version("djapi-guard")` with a `"0.0.0+unknown"` fallback if the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` so application code can wire the djapi-guard version through to the agent for SaaS-side telemetry attribution: `SecurityConfig(agent_guard_version=__version__)`.
- **Compatibility** - `DjangoAPIGuard.agent_stats` is purely additive; no existing API was changed. `__version__` was previously absent; reading it before this release returned `None` via missing-attribute fallback in some integrations.

___

v3.0.0 (2026-04-26)
-------------------

Pipeline-first CORS via guard_core.cors_handler (v3.0.0)
--------------------------------------------------------

- **Breaking** - Preflight `OPTIONS` requests are now subject to the security pipeline. Previously the middleware short-circuited preflights ahead of `_execute_security_pipeline` (the `if config.enable_cors and request.method == "OPTIONS"` block at line 227), allowing banned IPs and rate-limited clients to preflight freely.
- **Fixed** - Cross-origin preflight requests to passthrough paths (e.g. `exclude_paths=["/health"]`) now receive a valid CORS response. Preflight handling runs ahead of the passthrough/bypass short-circuit so the browser permission check works for excluded paths.
- **Fixed** - Cross-origin GETs to passthrough/bypass paths now carry CORS headers on their responses.
- **Fixed (latent)** - `middleware.py` was importing `BaseSecurityDecorator` and `RouteConfig` from `guard_core.decorators.base` (the async path) when it should have been using `guard_core.sync.decorators.base`. Sync/async protocol mismatches cascaded from there. Surfaced after removing the `[[tool.mypy.overrides]] follow_imports = "skip"` block.
- **Fixed (latent)** - `cloud_handler.refresh(ttl=...)` was being called with a `ttl` kwarg the method does not accept; correct call is `refresh_async()`.
- **Fixed (latent)** - 4 tests passed `agent_model="..."` to `SecurityConfig`; that field does not exist on the model.
- **Internal** - CORS preflight handling moved to the shared `guard_core.sync.handlers.cors_handler.CorsHandler` module. Removed all six `[[tool.mypy.overrides]]` suppression blocks (`redis.*`, `guard_agent.*`, `guard_core.*`, `django.*`, `examples.*`, `example_app.*`/`advanced_app.*`). Installed `django-stubs` as dev dep; `redis` 7.x, `guard-core` 2.2.0, `guard-agent` 2.2.0 all ship `py.typed`. Stripped `[tool.uv.sources] guard-core` local-path block from committed pyproject.toml. Added `reset_ratelimit_singleton` autouse fixture to `tests/conftest.py` so test runs no longer accumulate rate-limit state across tests.
- **Requires** - `guard-core>=2.2.0` (declared as unconstrained `guard-core` in pyproject; documented here for upgrade guidance).

___

v2.2.0 (2026-04-25)
-------------------

guard-core 2.0.0 compatibility (v2.2.0)
---------------------------------------

- **Compat** - Requires guard-core 2.0.0 or newer. Adapter middleware updated to match the new `suspicious_request_counts: dict[str, dict[str, int]]` protocol shape and `DetectionResult` return type. User code that didn't reach into those internals is unaffected.
- **Changed** - `DjangoAPIGuard.suspicious_request_counts` is now `dict[str, dict[str, int]]` to mirror the per-IP, per-category counters introduced by guard-core 2.0.0.
- **Tests** - `tests/test_middleware.py` mocks for `detect_penetration_patterns` and `detect_penetration_attempt` now return `DetectionResult(is_threat=..., trigger_info=...)` instead of the legacy `(bool, str)` tuple.

___

v2.1.1 (2026-04-25)
-------------------

Integration fixes for OTel + enrichment pipeline (v2.1.1)
---------------------------------------------------------

- **Fixed** - After composite construction, `self.agent_handler` is rebound from the bare `guard-agent` client to the composite. Downstream callers that receive `middleware.agent_handler` (most notably `guard_core.utils.extract_client_ip → send_agent_event`) now route through the composite, so enrichment and OTel see every event.
- **Fixed** - `BehavioralContext` now receives `handler_initializer.behavior_tracker`, matching the guard-core 1.2.1 wiring. This closes the architectural gap so `guard.behavior.recent_event_count` populates end-to-end when `enable_enrichment=True`.
- **Added** - `tests/test_middleware_lifecycle.py` - regression tests pinning the agent_handler rebind and behavior_tracker threading, plus coverage for unbuilt-pipeline and early-decorator-handler paths.
- **Requires** - `guard-core>=1.2.1` for the matching OTLP endpoint normalization and `BehaviorTracker` wiring fixes. Install the latest with `uv add djapi-guard guard-core` or `pip install -U djapi-guard guard-core`.
- **User-visible impact** - Users with `enable_otel=True`, `enable_logfire=True`, or `enable_enrichment=True` previously saw silent drops on a portion of events because callers using `middleware.agent_handler` directly bypassed the composite handler. After this release every downstream caller routes through the composite, so all events flow through telemetry and enrichment as configured.

___

v2.1.0 (2026-04-24)
-------------------

Telemetry pipeline wiring fix (v2.1.0)
--------------------------------------

Adopts guard-core 1.1.0 and fixes a middleware wiring bug that prevented OpenTelemetry, Logfire, and event/metric/check-log muting from seeing anything emitted by the request-path security pipeline.

- **Fixed** - `DjangoAPIGuard.__init__` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` in `_init_core_components()` using the bare `guard_agent` handler (or `None`). `_initialize_handlers()` then called `HandlerInitializer.initialize_agent_integrations()` which built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were already frozen on the bare handler. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release splits construction into `_init_core_components()` (handler_initializer only), `_init_route_resolver()`, and `_build_event_bus_and_contexts()` - the last of which consults `handler_initializer.composite_handler` and uses `build_event_bus()` / `build_metrics_collector()` when the composite is available. `_initialize_handlers()` now re-invokes `_build_event_bus_and_contexts()` after `initialize_agent_integrations()` so the dependent contexts (`ResponseContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`) bind to the post-init event bus.
- **Added** - `tests/test_middleware_wiring.py` - four regression tests that pin `mw.event_bus.agent_handler` and `mw.metrics_collector.agent_handler` to `CompositeAgentHandler` after instantiation when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** - `guard-core>=1.1.0,<2.0.0`.
- **User-visible impact** - Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) - but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.
- **Tests** - `tests/test_middleware.py` - the two coverage tests that pinned the old `_init_routing_and_validation` guards (`test_init_routing_event_bus_none`, `test_init_routing_response_factory_none`) are replaced with `test_build_event_bus_handler_initializer_none` and `test_build_event_bus_route_resolver_none` covering the new guards in `_build_event_bus_and_contexts`.

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
