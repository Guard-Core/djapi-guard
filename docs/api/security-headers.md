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

`configure()` on the global manager sets exactly what you pass.

- **The manager's own headers** keep the full replace: what the call does not pass is absent on the manager.
- **Every guarded app**: the keys you pass override the `security_headers` config of every guarded app in the process from the next response on, for paths already served and for paths never served. Keys you do not pass are not overridden, each app keeps its own value for them. `None` switches that header off for every app, `enabled=False` switches every app off, `hsts_max_age`, `hsts_include_subdomains` and `hsts_preload` merge over each app's `hsts` one by one, and an app whose own `security_headers` is off stays off.
- **A bare `configure()`** clears the manager and the override. `security_headers_manager.reset()` clears them too, in the process and in Redis.
- **Never silent**: every call that changes the override logs one line and sends the security headers event. A call that drops keys from an active override (a bare call included) logs a WARNING that names the dropped keys, and the event lists them. Header values in the log line and the event are redacted (a custom `X-Auth-Token` value never appears).
- **Opt-in**: without a call there is no override, and the guarded apps of a process behave as before.

```python
from djangoapi_guard import SecurityHeadersManager

security_headers_manager = SecurityHeadersManager()

security_headers_manager.configure(csp={"default-src": ["'self'", "https://cdn.example"]})  # every app: this CSP
security_headers_manager.configure(frame_options="DENY")  # drops csp from the override: WARNING, apps use their own CSP again
security_headers_manager.reset()  # clears the override
```

With Redis on, each app saves the override with no TTL under `{redis_prefix}security_headers:override:{hash}`, where `hash` is the hash of the startup config the app runs, and each worker pulls it at most once every 5 seconds, so a call in one worker reaches the others within about 5 seconds. A worker started with another config ignores it, and a Redis error keeps the last applied override. Two services that share a `redis_prefix` and run an identical config share the override: give each service its own prefix.

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
