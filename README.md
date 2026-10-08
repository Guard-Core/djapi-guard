<p align="center">
    <a href="https://guard-core.github.io/djapi-guard/latest/">
        <img src="https://guard-core.github.io/djapi-guard/latest/assets/djapi_guard_legend.svg" alt="DjangoAPI Guard">
    </a>
</p>

---

<p align="center">
    <strong>djapi-guard is a security library for Django that provides middleware to control IPs, log requests, detect penetration attempts and more. It integrates seamlessly with Django to offer robust protection against various security threats. Powered by <a href="https://github.com/Guard-Core/guard-core">guard-core</a>.</strong>
</p>

<p align="center">
    <a href="https://badge.fury.io/py/djapi-guard">
        <img src="https://badge.fury.io/py/djapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4" alt="PyPiVersion">
    </a>
    <a href="https://github.com/Guard-Core/djapi-guard/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/djapi-guard/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/djapi-guard/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/djapi-guard/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/djapi-guard/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/djapi-guard/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/djapi-guard/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/djapi-guard/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/djapi-guard/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/djapi-guard/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/djapi-guard?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&amp;logo=Python&amp;logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Django-092E20.svg?style=flat&amp;logo=Django&amp;logoColor=white" alt="Django">
    <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&amp;logo=Redis&amp;logoColor=white" alt="Redis">
    <a href="https://pepy.tech/project/djapi-guard">
        <img src="https://pepy.tech/badge/djapi-guard" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/djapi-guard/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

# Documentation

**[Documentation](https://guard-core.github.io/djapi-guard)** - Full technical documentation and deep dive into its inner workings.

___

## Ecosystem

DjangoAPI Guard is the Django adapter for the Guard security ecosystem. Powered by `guard-core` and compatible with the shared telemetry agent. Parallel implementations exist for TypeScript (on npm) and Rust (on crates.io).

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter (this package) | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope. Source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |

### Rust

Published on crates.io. **🚧 Placeholder crates — implementation in progress.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core-rs) | Core engine | [![crates.io](https://img.shields.io/crates/v/guard-core)](https://crates.io/crates/guard-core) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |

___

## Features

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP.
- **Automatic IP Banning**: Automatically ban IPs after a certain number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts.
- **HTTP Security Headers**: Comprehensive security headers management (CSP, HSTS, X-Frame-Options, etc.)
- **Custom Logging**: Log security events to a custom file.
- **CORS Configuration**: Configure CORS settings for your Django application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use a service like IPInfo.io API to determine the country of an IP address.
- **Distributed State Management**: (Optional) Redis integration for shared security state across instances.
- **Flexible Storage**: Redis-enabled distributed storage or in-memory storage for single instance deployments.
- **Route-Level Security Decorators**: Fine-grained security controls per route.
- **Behavioral Analysis**: Endpoint usage tracking and anomaly detection.
- **Time-Based Access Control**: Restrict endpoint access to specific time windows.
- **Emergency Mode**: Block all traffic except whitelisted IPs.

___

## Installation

To install `djapi-guard`, use pip:

```bash
pip install djapi-guard
```

___

## Migrating to v4.0.0

`djapi-guard` 4.0.0 tracks `guard-core >= 3.0.0`'s fail-secure default flip and adds two adapter-side surfaces.

### Fail-secure default flip (upstream)

`SecurityConfig.fail_secure` now defaults to `True`. If any security check raises an unhandled exception, the request is blocked with HTTP 500 instead of falling through. Restore the previous behavior on deployments that depend on it:

```python
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    fail_secure=False,
)
```

The recommended migration is to keep the new default, surface check exceptions in your monitoring, and fix them at the root.

### Reading agent buffer state

`DjangoAPIGuard.agent_stats` exposes the agent's live buffer drop counters and circuit-breaker state without reaching into the agent directly. Build it into a health-check view:

```python
from django.http import JsonResponse
from djangoapi_guard.middleware import DjangoAPIGuard


def agent_health(request):
    middleware: DjangoAPIGuard = request._guard_middleware
    return JsonResponse(middleware.agent_stats)
# {"enabled": True,
#  "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0, ...},
#  "transport_stats": {"circuit_breaker_state": "CLOSED", ...}}
```

When the agent is disabled or failed to initialize, the property returns `{"enabled": False}`. Read it on each scrape — it reflects live counters and is not cached.

### Wiring the package version through to the agent

```python
from djangoapi_guard import SecurityConfig, __version__

GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_agent=True,
    agent_api_key="...",
    agent_guard_version=__version__,
)
```

`__version__` resolves via `importlib.metadata.version("djapi-guard")` and falls back to `"0.0.0+unknown"` when the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` for SaaS-side telemetry attribution.

___

## Usage

## Basic Setup

To use `djapi-guard`, you need to add the middleware to your Django project and configure the security settings. Here's a basic example:

### settings.py

```python
MIDDLEWARE = [
    # Add DjangoAPI Guard middleware early in the stack
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # ... other middleware
]

# Define your security configuration
GUARD_SECURITY_CONFIG = {
    "ipinfo_token": "your_ipinfo_token_here",  # Optional: IPInfo token required for IP geolocation
    "ipinfo_db_path": "custom/ipinfo.db",  # Optional custom database path
    "whitelist": ["192.168.1.1", "2001:db8::1"],
    "blacklist": ["10.0.0.1", "2001:db8::2"],
    "blocked_countries": ["AR", "IT"],
    "blocked_user_agents": ["curl", "wget"],
    "auto_ban_threshold": 5,
    "auto_ban_duration": 86400,
    "custom_log_file": "security.log",
    "rate_limit": 100,
    "enforce_https": True,
    "enable_cors": True,
    "cors_allow_origins": ["*"],
    "cors_allow_methods": ["GET", "POST"],
    "cors_allow_headers": ["*"],
    "cors_allow_credentials": True,
    "cors_expose_headers": ["X-Custom-Header"],
    "cors_max_age": 600,
    "block_cloud_providers": {"AWS", "GCP", "Azure"},
}
```

### views.py

```python
from django.http import JsonResponse

def read_root(request):
    return JsonResponse({"message": "Hello, World!"})
```

## IP Whitelisting and Blacklisting

You can control access based on IP addresses using the `whitelist` and `blacklist` options in the `SecurityConfig`.

```python
GUARD_SECURITY_CONFIG = {
    "whitelist": ["192.168.1.1", "2001:db8::1"],
    "blacklist": ["10.0.0.1", "2001:db8::2"],
}
```

## User Agent Filtering

Block requests from specific user agents by adding patterns to the `blocked_user_agents` list.

```python
GUARD_SECURITY_CONFIG = {
    "blocked_user_agents": ["curl", "wget"],
}
```

## Rate Limiting

Limit the number of requests from a single IP using the `rate_limit` option.

```python
GUARD_SECURITY_CONFIG = {
    "rate_limit": 100,  # Maximum 100 requests per minute
}
```

## Automatic IP Banning

Automatically ban IPs after a certain number of suspicious requests using the `auto_ban_threshold` and `auto_ban_duration` options.

```python
GUARD_SECURITY_CONFIG = {
    "auto_ban_threshold": 5,  # Ban IP after 5 suspicious requests
    "auto_ban_duration": 86400,  # Ban duration in seconds (1 day)
}
```

## Penetration Attempt Detection

Enable penetration attempt detection using the `enable_penetration_detection` option.

```python
GUARD_SECURITY_CONFIG = {
    "enable_penetration_detection": True,  # True by default
}
```

Optional: Enable `passive mode` to log suspicious activity without blocking requests.

```python
GUARD_SECURITY_CONFIG = {
    "passive_mode": True,  # False by default
}
```

## Custom Penetration Detection

Detect and log potential penetration attempts using the `detect_penetration_attempt` function.

```python
from django.http import JsonResponse
from djangoapi_guard.utils import detect_penetration_attempt

def submit_data(request):
    is_suspicious, trigger_info = detect_penetration_attempt(request)
    if is_suspicious:
        return JsonResponse(
            {"error": f"Suspicious activity detected: {trigger_info}"},
            status=400,
        )
    return JsonResponse({"message": "Data submitted successfully"})
```

## Custom Logging

Log security events with console output (always enabled) and optional file logging:

```python
GUARD_SECURITY_CONFIG = {
    "custom_log_file": "security.log",  # Optional: adds file logging
    # "custom_log_file": None,  # Default: console output only
}
```

**Note:** Console output is always enabled for visibility. File logging is only activated when `custom_log_file` is provided.

## HTTP Security Headers

Configure comprehensive security headers following OWASP best practices:

```python
GUARD_SECURITY_CONFIG = {
    "security_headers": {
        "enabled": True,
        "hsts": {
            "max_age": 31536000,  # 1 year
            "include_subdomains": True,
            "preload": False,
        },
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://trusted.cdn.com"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'", "https://api.example.com"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
        },
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "1; mode=block",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": "geolocation=(), microphone=(), camera=()",
        "custom": {
            "X-Custom-Header": "CustomValue",
        },
    },
}
```

Key security headers supported:

- **Content Security Policy (CSP)**: Prevent XSS attacks by controlling resource loading
- **HTTP Strict Transport Security (HSTS)**: Force HTTPS connections
- **X-Frame-Options**: Prevent clickjacking attacks
- **X-Content-Type-Options**: Prevent MIME type sniffing
- **X-XSS-Protection**: Enable browser XSS filtering
- **Referrer-Policy**: Control referrer information
- **Permissions-Policy**: Restrict browser features
- **Cross-Origin Policies**: Control cross-origin resource access and embedding
- **Header Injection Prevention**: Automatic validation against injection attacks
- **CORS Security**: Secure wildcard and credentials handling

## CORS Configuration

Configure CORS settings for your Django application using the `enable_cors` and related options.

```python
GUARD_SECURITY_CONFIG = {
    "enable_cors": True,
    "cors_allow_origins": ["*"],
    "cors_allow_methods": ["GET", "POST"],
    "cors_allow_headers": ["*"],
    "cors_allow_credentials": True,
    "cors_expose_headers": ["X-Custom-Header"],
    "cors_max_age": 600,
}
```

## Cloud Provider IP Blocking

Block requests from cloud provider IPs (AWS, GCP, Azure) using the `block_cloud_providers` option.

```python
GUARD_SECURITY_CONFIG = {
    "block_cloud_providers": {"AWS", "GCP", "Azure"},
}
```

## IP Geolocation and Country Blocking

If you want to use `djapi-guard`'s built-in country filtering features, you'll need to obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account
2. After signing up, you'll receive an API token
3. The free tier includes:
   - Up to 50,000 requests per month
   - Access to IP to Country database
   - Daily database updates
   - IPv4 & IPv6 support

Note: This is only required if you use country filtering (`blocked_countries`, `whitelist_countries`). You can also provide your own handler that uses any other service.

___

## Route-Level Security with Decorators

DjangoAPI Guard provides powerful decorators that allow you to apply security controls to individual views, giving you fine-grained control over your API endpoints.

### Basic Decorator Usage

```python
from djangoapi_guard import DjangoAPIGuard, SecurityConfig, SecurityDecorator
from django.http import JsonResponse

# In your settings.py, configure the middleware and security config as shown above.

# Create decorator instance
from django.conf import settings
from djangoapi_guard.models import SecurityConfig as SecurityConfigModel

config = SecurityConfigModel(**settings.GUARD_SECURITY_CONFIG)
guard_deco = SecurityDecorator(config)

# Apply decorators to specific views
def public_endpoint(request):
    return JsonResponse({"data": "public"})

@guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
def limited_endpoint(request):
    return JsonResponse({"data": "limited"})

@guard_deco.require_ip(whitelist=["192.168.1.0/24"])
@guard_deco.block_countries(["CN", "RU"])
def restricted_endpoint(request):
    return JsonResponse({"data": "restricted"})
```

### Available Decorators

Access Control

- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(["CN", "RU"])` - Block specific countries
- `@guard_deco.allow_countries(["US", "CA"])` - Allow only specific countries
- `@guard_deco.block_clouds(["AWS", "GCP"])` - Block cloud provider IPs

Rate Limiting

- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={"US": 100, "default": 50})` - Geographic rate limiting

Authentication & Headers

- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer")` - Require authentication
- `@guard_deco.api_key_auth(header_name="X-API-Key")` - API key authentication
- `@guard_deco.require_headers({"X-Custom": "required"})` - Require specific headers

Content Filtering

- `@guard_deco.block_user_agents(["curl", "wget"])` - Block user agent patterns
- `@guard_deco.content_type_filter(["application/json"])` - Filter content types
- `@guard_deco.max_request_size(1048576)` - Limit request size (1MB)
- `@guard_deco.require_referrer(["myapp.com"])` - Require specific referrers

Behavioral Analysis

- `@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")` - Monitor endpoint usage
- `@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="alert")` - Monitor return patterns
- `@guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="log")` - Detect suspicious frequency

Advanced Controls

- `@guard_deco.time_window("09:00", "17:00", "UTC")` - Time-based access control
- `@guard_deco.honeypot_detection(trap_fields=["hidden_field"])` - Detect bots using honeypot fields
- `@guard_deco.bypass(checks=["rate_limit"])` - Bypass specific security checks

### Complex Route Protection

Combine multiple decorators for comprehensive protection:

```python
from django.http import JsonResponse

@guard_deco.require_https()                        # Security requirement
@guard_deco.require_auth(type="bearer")            # Authentication
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])   # Access control
@guard_deco.rate_limit(requests=5, window=3600)    # Rate limiting
@guard_deco.suspicious_detection(enabled=True)     # Monitoring
def admin_endpoint(request):
    return JsonResponse({"status": "admin action"})

@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
@guard_deco.block_countries(["CN", "RU", "KP"])
def rewards_endpoint(request):
    # This endpoint is protected against:
    # - Excessive usage (>50 calls/hour results in ban)
    # - Suspicious return patterns (>3 rare items/day results in ban)
    # - Geographic restrictions
    return JsonResponse({"reward": "rare_item", "value": 1000})
```

### Decorator Configuration Priority

Security settings are applied in the following priority order:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows views to override global settings while maintaining sensible defaults.

___

## Advanced Usage

### Secure Proxy Configuration

Configure trusted proxies to securely handle X-Forwarded-For headers:

```python
GUARD_SECURITY_CONFIG = {
    "trusted_proxies": ["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs or CIDR ranges
    "trusted_proxy_depth": 1,                           # How many proxies to expect in chain
    "trust_x_forwarded_proto": True,                    # Whether to trust X-Forwarded-Proto for HTTPS detection (default: True)
}
```

When `trusted_proxies` is configured, DjangoAPI Guard will:

1. Only trust X-Forwarded-For headers from these IPs
2. Extract the appropriate client IP based on proxy depth
3. Prevent IP spoofing attacks through header manipulation

### Custom Geolocation Handler

The library implements a handler that uses IPInfo's [IP to Country database](https://ipinfo.io/products/free-ip-database), which provides:

- Full accuracy IP to country mapping
- Daily updates
- Support for both IPv4 and IPv6
- Country and continent information
- ASN details

To use the geolocation feature with this handler:

```python
from djangoapi_guard.protocols.geo_ip_protocol import GeoIPHandler

GUARD_SECURITY_CONFIG = {
    "geo_ip_handler": GeoIPHandler,
    "blocked_countries": ["AR", "IT"],   # Block specific countries using ISO 3166-1 alpha-2 codes
    "whitelist_countries": ["US", "CA"],  # Optional: Only allow specific countries
}
```

The database is automatically downloaded and cached locally when the middleware starts, if required, and it's updated daily to ensure accuracy.

You can also use a service other than IPInfo, as long as you implement the same protocol:

```python
# Implement the required methods of djangoapi_guard.protocols.geo_ip_protocol.GeoIPHandler protocol

class GeoIPHandler:
    """
    Your custom class.
    """

    @property
    def is_initialized(self) -> bool:
        # your implementation
        ...

    def initialize(self) -> None:
        # your implementation
        ...

    def initialize_redis(self, redis_handler: "RedisManager") -> None:
        # your implementation
        ...

    def get_country(self, ip: str) -> str | None:
        # your implementation
        ...


GUARD_SECURITY_CONFIG = {
    "geo_ip_handler": GeoIPHandler,
    "blocked_countries": ["AR", "IT"],  # Block specific countries using ISO 3166-1 alpha-2 codes
    "whitelist_countries": ["US", "CA"],  # Optional: Only allow specific countries
}
```

### Custom Request Check

You can define a custom function to perform additional checks on the request using the `custom_request_check` option.

```python
from django.http import HttpResponse
from typing import Optional

def custom_check(req) -> Optional[HttpResponse]:
    if "X-Custom-Header" not in req.headers:
        return HttpResponse("Missing custom header", status=400)
    return None

GUARD_SECURITY_CONFIG = {
    "custom_request_check": custom_check,
}
```

### Custom Response Modifier

You can define a custom function to modify the response before it's sent using the `custom_response_modifier` option.

```python
from django.http import HttpResponse, JsonResponse

def custom_modifier(response: HttpResponse) -> HttpResponse:
    # Add custom headers
    response["X-Custom-Header"] = "CustomValue"

    # Convert text responses to JSON responses
    if response.status_code >= 400 and response.get("Content-Type") != "application/json":
        try:
            content = response.content.decode("utf-8")
            json_response = JsonResponse({"detail": content})
            json_response.status_code = response.status_code
            return json_response
        except Exception:
            pass

    return response

GUARD_SECURITY_CONFIG = {
    "custom_response_modifier": custom_modifier,
}
```

The example above shows how to:

1. Add custom headers to all responses
2. Convert plain text error responses to JSON format with a "detail" field

___

## Redis Configuration

Enable distributed state management across multiple instances:

```python
GUARD_SECURITY_CONFIG = {
    "enable_redis": True,
    "redis_url": "redis://prod-redis:6379/1",
    "redis_prefix": "myapp:security:",
}
```

The Redis integration provides:

- Atomic increment operations for rate limiting
- Distributed IP ban tracking
- Cloud provider IP range caching
- Pattern storage for penetration detection

___

## Emergency Mode

Block all incoming traffic except from explicitly whitelisted IPs. Useful during active attacks or maintenance windows:

```python
GUARD_SECURITY_CONFIG = {
    "emergency_mode": True,
    "emergency_whitelist": ["10.0.0.1", "192.168.1.0/24"],
}
```

___

## Behavioral Analysis

DjangoAPI Guard includes a behavioral analysis engine for detecting anomalous usage patterns. This works both at the global level and per-view via decorators:

```python
from djangoapi_guard import SecurityConfig, BehaviorRule
from django.http import JsonResponse

# Global behavioral rules can be defined in config

# Per-view behavioral monitoring via decorators
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
def rewards_endpoint(request):
    return JsonResponse({"reward": "rare_item", "value": 1000})
```

Behavioral actions include:

- `"log"` - Log the anomaly
- `"alert"` - Generate an alert event
- `"ban"` - Automatically ban the offending IP

___

## Detailed Configuration Options

### SecurityConfig

The `SecurityConfig` class defines the structure for security configuration, including IP whitelists and blacklists, blocked countries, blocked user agents, rate limiting, automatic IP banning, HTTPS enforcement, custom hooks, CORS settings, and blocking of cloud provider IPs.

### Attributes

- **geo_ip_handler**: ```GeoIPHandler``` - Protocol that allows for IP geolocation functionality.
- **enable_redis**: ```bool``` - Enable Redis for distributed state (default: True). When disabled, uses in-memory storage.
- **redis_url**: ```str | None``` - Redis connection URL (default: "redis://localhost:6379").
- **redis_prefix**: ```str``` - Prefix for Redis keys (default: "djangoapi_guard:").
- **trusted_proxies**: ```list[str] | None``` - List of trusted proxy IPs or CIDR ranges.
- **trusted_proxy_depth**: ```int``` - How many proxies to expect in chain.
- **trust_x_forwarded_proto**: ```bool``` - Whether to trust X-Forwarded-Proto for HTTPS detection.
- **whitelist**: ```list[str] | None``` - A list of IP addresses or ranges that are always allowed. If set to None, no whitelist is applied.
- **blacklist**: ```list[str]``` - A list of IP addresses or ranges that are always blocked.
- **blocked_countries**: ```list[str]``` - A list of country codes whose IP addresses should be blocked.
- **blocked_user_agents**: ```list[str]``` - A list of user agent strings or patterns that should be blocked.
- **auto_ban_threshold**: ```int``` - The threshold for auto-banning an IP address after a certain number of requests.
- **auto_ban_duration**: ```int``` - The duration in seconds for which an IP address should be banned after reaching the auto-ban threshold.
- **custom_log_file**: ```str | None``` - Optional path to a log file. When provided, enables file logging in addition to console output (which is always enabled). Default: `None` (console only).
- **custom_error_responses**: ```dict[int, str]``` - A dictionary of custom error responses for specific HTTP status codes.
- **rate_limit**: ```int``` - The maximum number of requests allowed per minute from a single IP.
- **rate_limit_window**: ```int``` - The time window in seconds for rate limiting (default: 60).
- **enforce_https**: ```bool``` - Whether to enforce HTTPS connections. If True, all HTTP requests will be redirected to HTTPS.
- **custom_request_check**: ```Callable[[HttpRequest], HttpResponse | None] | None``` - A custom synchronous function to perform additional checks on the request. If it returns an HttpResponse, that response will be sent instead of continuing the middleware chain.
- **custom_response_modifier**: ```Callable[[HttpResponse], HttpResponse] | None``` - A custom synchronous function to modify the response before it's sent.
- **enable_cors**: ```bool``` - Whether to enable CORS.
- **cors_allow_origins**: ```list[str]``` - A list of origins that are allowed to access the API.
- **cors_allow_methods**: ```list[str]``` - A list of methods that are allowed to access the API.
- **cors_allow_headers**: ```list[str]``` - A list of headers that are allowed in CORS requests.
- **cors_allow_credentials**: ```bool``` - Whether to allow credentials in CORS requests.
- **cors_expose_headers**: ```list[str]``` - A list of headers that are exposed in CORS responses.
- **cors_max_age**: ```int``` - The maximum age in seconds that the results of a preflight request can be cached.
- **block_cloud_providers**: ```set[str]``` - Case-sensitive cloud provider names to block. Valid values: 'AWS', 'GCP', 'Azure'. Invalid entries are silently ignored.
- **passive_mode**: ```bool``` - When enabled, logs suspicious activity without blocking requests (default: False).
- **enable_ip_banning**: ```bool``` - Enable or disable IP banning functionality (default: True).
- **enable_rate_limiting**: ```bool``` - Enable or disable rate limiting (default: True).
- **enable_penetration_detection**: ```bool``` - Enable or disable penetration attempt detection (default: True).
- **emergency_mode**: ```bool``` - Block all traffic except whitelisted IPs (default: False).
- **emergency_whitelist**: ```list[str]``` - IPs allowed during emergency mode.
- **exclude_paths**: ```list[str]``` - Paths excluded from security checks (default: ["/admin", "/static", "/favicon.ico"]).
- **security_headers**: ```dict[str, Any] | None``` - Security headers configuration following OWASP best practices.
- **endpoint_rate_limits**: ```dict[str, tuple[int, int]]``` - Per-endpoint rate limits as {endpoint: (limit, window)}.
- **log_suspicious_level**: ```Literal["INFO","DEBUG","WARNING","ERROR","CRITICAL"] | None``` - Log level for suspicious activity (default: "WARNING").
- **log_request_level**: ```Literal["INFO","DEBUG","WARNING","ERROR","CRITICAL"] | None``` - Log level for request logging (default: None).

___

## Detection Engine

DjangoAPI Guard includes a comprehensive detection engine for identifying penetration attempts. It uses pattern matching, semantic analysis, and anomaly detection to catch a wide range of attack vectors.

### Attack Categories Detected

| Category | Examples |
|----------|----------|
| **XSS** | Script tags, event handlers, JavaScript protocol, cookie manipulation |
| **SQL Injection** | UNION queries, logic-based (OR/AND), time-based (SLEEP/BENCHMARK), file ops |
| **Command Injection** | Shell commands, command substitution/chaining, PHP functions |
| **Path Traversal** | `../` sequences, `/etc/passwd`, `/proc/self/environ`, Windows system files |
| **File Inclusion** | `php://`, `data://`, `file://`, `zip://`, `expect://` protocols |
| **LDAP Injection** | Wildcard patterns, attribute matching, logic ops |
| **XML Injection** | XXE, CDATA sections, XML declarations |
| **SSRF** | localhost, `127.0.0.1`, `169.254.*`, private ranges |
| **Code Injection** | Python `eval`/`exec`/`__import__`, obfuscation, high-entropy payloads |

### Detection Configuration

| Config Field | Default | Range | Purpose |
|-------------|---------|-------|---------|
| `detection_compiler_timeout` | `2.0` | 0.1-10.0 | Pattern compilation timeout (seconds) |
| `detection_max_content_length` | `10000` | 1000-100000 | Max content length to analyze |
| `detection_preserve_attack_patterns` | `True` | - | Preserve attack signatures during preprocessing |
| `detection_semantic_threshold` | `0.7` | 0.0-1.0 | Semantic analysis confidence threshold |
| `detection_anomaly_threshold` | `3.0` | 1.0-10.0 | Anomaly detection threshold (std devs) |
| `detection_slow_pattern_threshold` | `0.1` | 0.01-1.0 | Slow pattern detection threshold (seconds) |
| `detection_monitor_history_size` | `1000` | 100-10000 | Performance monitor history size |
| `detection_max_tracked_patterns` | `1000` | 100-5000 | Max tracked patterns |

___

## Key Differences from FlaskAPI Guard

DjangoAPI Guard is a direct port of [FlaskAPI Guard](https://github.com/Guard-Core/flaskapi-guard) to the Django ecosystem. The security logic is identical, but adapted for Django's middleware model:

| Aspect | FlaskAPI Guard | DjangoAPI Guard |
|--------|--------------|----------------|
| **Entry point** | `FlaskAPIGuard` (Flask extension) | `DjangoAPIGuard` (Django middleware) |
| **Hook mechanism** | `before_request` / `after_request` | `__call__` / `process_request` / `process_response` |
| **Configuration** | `FlaskAPIGuard(app, config=config)` | `MIDDLEWARE` setting + `GUARD_SECURITY_CONFIG` |
| **Server model** | WSGI (gunicorn, waitress) | WSGI (gunicorn, uwsgi, daphne) |
| **Package name** | `flaskapi_guard` | `djangoapi_guard` |
| **Request state** | `flask.g` | `request` attributes |
| **Request object** | `flask.request` (Werkzeug) | `django.http.HttpRequest` |
| **Response object** | `flask.Response` (Werkzeug) | `django.http.HttpResponse` |
| **IP extraction** | `request.remote_addr` / `request.access_route` | `request.META["REMOTE_ADDR"]` / `X-Forwarded-For` |
| **Custom callables** | `def check(request) -> Response \| None` | `def check(request) -> HttpResponse \| None` |

___

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

___

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

___

## Author

Renzo Franceschini - [contact@guard-core.com](mailto:contact@guard-core.com) .

___

## Acknowledgements

- [Django](https://www.djangoproject.com/)
- [FlaskAPI Guard](https://github.com/Guard-Core/flaskapi-guard)
- [FastAPI Guard](https://github.com/Guard-Core/fastapi-guard)
- [IPInfo](https://ipinfo.io/)
- [cachetools](https://cachetools.readthedocs.io/)
- [Redis](https://redis.io/)
- [gunicorn](https://gunicorn.org/)
- [Pydantic](https://docs.pydantic.dev/)
