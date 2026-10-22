---

title: Security Headers Manager - DjangoAPI Guard
description: Comprehensive HTTP security header management following OWASP best practices
keywords: security headers, CSP, HSTS, X-Frame-Options, OWASP headers
---

Security Headers Manager
========================

The Security Headers Manager provides comprehensive HTTP security header management following OWASP best practices.

___

Class Reference
---------------

```python
from djangoapi_guard import SecurityHeadersManager

security_headers_manager = SecurityHeadersManager()
```

Methods: `configure()`, `get_headers()`, `get_cors_headers()`, `validate_csp_report()`, `reset()`

Global `configure()` and the override
-------------------------------------

`configure()` on the global manager sets exactly what you pass. **Without `override_apps=True` it changes only the manager's own headers and does not reach any guarded app.** The middleware itself calls it at startup with every key from its config, and that call changes nothing for the apps.

- **The manager's own headers** keep the full replace: what the call does not pass is absent on the manager.
- **Every guarded app** (only with `override_apps=True`): the keys you pass override the `security_headers` config of every guarded app in the process from the next response on, for paths already served and for paths never served. Keys you do not pass are not overridden, each app keeps its own value for them. `None` switches that header off for every app, `hsts_max_age`, `hsts_include_subdomains` and `hsts_preload` merge over each app's `hsts` one by one, and a passed `enabled` wins in both directions (`enabled=True` switches on an app whose own `security_headers` is off, `enabled=False` switches every app off).
- **Clearing**: `configure(override_apps=True)` with nothing else clears the override. `security_headers_manager.reset()` clears the manager and the override, in the process and in Redis. Writing `security_headers_manager.enabled` is never an override.
- **CORS keys** (only with `override_apps=True`): `enable_cors`, `cors_origins`, `cors_allow_credentials`, `cors_allow_methods`, `cors_allow_headers`, `cors_max_age` and `cors_expose_headers` join the override and follow the same rule: a call sets exactly what it passes, and a call that passes only CORS keys is recorded. The values are validated in `configure()` (lists of strings, bools, a non-negative integer for `cors_max_age`) and a bad value raises `ValueError`. A merge that would give wildcard origins together with credentials is refused: the app keeps its own CORS and the engine logs a WARNING and sends an event. An app built with `enable_cors=False` gets CORS only when the call passes `enable_cors=True` (a WARNING per app), and the engine then answers its preflight requests in the pipeline, after the ban and IP checks and before rate limiting. A passed `enable_cors=False` stops the CORS answers of every app. The headers `enabled` flag never governs CORS. A merge that widens the app's CORS logs a WARNING once per app and override version, a merge that narrows it logs INFO. With Redis, the CORS keys travel with the rest of the override to the other workers with the same startup config.
- **Never silent**: every call with the flag that changes the override logs one line and sends the security headers event. A call that drops keys from an active override (a clearing call included) logs a WARNING that names the dropped keys, and the event lists them. Header values in the log line and the event are redacted (a custom `X-Auth-Token` value never appears).

```python
from djangoapi_guard import SecurityHeadersManager

security_headers_manager = SecurityHeadersManager()

security_headers_manager.configure(
    csp={"default-src": ["'self'", "https://cdn.example"]},
    override_apps=True,
)  # every app: this CSP
security_headers_manager.configure(
    frame_options="DENY", override_apps=True
)  # drops csp from the override: WARNING, apps use their own CSP again
security_headers_manager.configure(
    csp={"default-src": ["'none'"]}
)  # no flag: the manager only, no app changes
security_headers_manager.reset()  # clears the override
```

With Redis on, each app saves the override with no TTL under `{redis_prefix}security_headers:override:{hash}`, where `hash` is the hash of the startup config the app runs, and each worker pulls it at most once every 5 seconds, so a call in one worker reaches the others within about 5 seconds. A worker started with another config ignores it, and a Redis error keeps the last applied override (retried after 5 seconds, whatever `redis_fail_open` says). Two services that share a `redis_prefix` and run an identical config share the override: give each service its own prefix.

___

Default Headers
---------------

| Header | Default Value |
|--------|--------------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

___

Example Usage
-------------

```python
# settings.py
GUARD_SECURITY_CONFIG = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {"max_age": 31536000, "include_subdomains": True},
        "frame_options": "DENY",
    }
)
```

___

See Also
--------

- [HTTP Security Headers Tutorial](../tutorial/security/http-security-headers.md)
- [Security Configuration](../tutorial/configuration/security-config.md)
