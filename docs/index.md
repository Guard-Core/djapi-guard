---

title: DjangoAPI Guard - Security Middleware for Django
description: Comprehensive security library for Django applications providing IP control, rate limiting, request logging, and penetration detection
keywords: django, security, middleware, python, ip control, rate limiting, penetration detection, cybersecurity

---

# DjangoAPI Guard

![DjangoAPI Guard](assets/djapi_guard_legend.svg)

[![PyPI version](https://badge.fury.io/py/djapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4)](https://badge.fury.io/py/djapi-guard)
[![Release](https://github.com/Guard-Core/djapi-guard/actions/workflows/release.yml/badge.svg)](https://github.com/Guard-Core/djapi-guard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Guard-Core/djapi-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Guard-Core/djapi-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Guard-Core/djapi-guard/actions/workflows/code-ql.yml/badge.svg)](https://github.com/Guard-Core/djapi-guard/actions/workflows/code-ql.yml)

`djapi-guard` is a comprehensive security library for Django applications, providing middleware to control IPs, log requests, and detect penetration attempts. It integrates seamlessly with Django to offer robust protection against various security threats, ensuring your application remains secure and reliable. DjangoAPI Guard is a direct port of [FastAPI Guard](https://github.com/Guard-Core/fastapi-guard) to the Django ecosystem.

___

## Quick Start

### Installation

=== "uv"

    ```bash
    uv add djapi-guard
    ```

=== "poetry"

    ```bash
    poetry add djapi-guard
    ```

=== "pip"

    ```bash
    pip install djapi-guard
    ```

### Basic Usage

```python
# settings.py
from djangoapi_guard import SecurityConfig, IPInfoManager

GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_token_here"),
    enable_redis=False,
    rate_limit=100,
    auto_ban_threshold=5,
)

MIDDLEWARE = [
    # Add DjangoAPIGuard middleware
    "djangoapi_guard.middleware.DjangoAPIGuard",
    # ... other middleware
    "django.middleware.common.CommonMiddleware",
]
```

### Django Settings Pattern

DjangoAPI Guard reads its configuration from `settings.GUARD_SECURITY_CONFIG`:

```python
# settings.py
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    enable_penetration_detection=True,
)

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
    # ... other middleware
]
```

```python
# views.py
from django.http import JsonResponse

def hello(request):
    return JsonResponse({"message": "Hello, World!"})
```

___

## Example App

Inside [examples](https://github.com/Guard-Core/djapi-guard/tree/master/examples), you can find a simple example app that demonstrates how to use DjangoAPI Guard.

___

## Docker Container

You can also download the example app as a Docker container from [GitHub Container Registry](https://github.com/orgs/Guard-Core/packages/container/djapi-guard-example).

```bash
# Pull the latest version
docker pull ghcr.io/guard-core/djapi-guard-example:latest

# Or pull a specific version (matches library releases)
docker pull ghcr.io/guard-core/djapi-guard-example:v4.3.2
```

___

## Running the Example App

### Using Docker Compose (Recommended)

The easiest way to run the example app is with Docker Compose, which automatically sets up Redis:

```bash
# Clone the repository
git clone https://github.com/Guard-Core/djapi-guard.git
cd djapi-guard/examples

# Start the app with Redis
docker compose up
```

This will start both the DjangoAPI Guard example app and Redis service. The app will be available at <http://0.0.0.0:8000>.

### Using Docker Container Only

Alternatively, you can run just the container:

```bash
# Run with default settings
docker run -p 8000:8000 ghcr.io/guard-core/djapi-guard-example:latest

# Run with custom Redis connection
docker run -p 8000:8000 \
  -e REDIS_URL=redis://your-redis-host:your-redis-port \
  -e REDIS_PREFIX=your-redis-prefix \
  -e IPINFO_TOKEN=your-ipinfo-token \
  ghcr.io/guard-core/djapi-guard-example:latest
```

### Running Locally

You can also run the example app locally with gunicorn. Install the dependencies:

=== "uv"

    ```bash
    uv add djapi-guard gunicorn
    ```

=== "poetry"

    ```bash
    poetry add djapi-guard gunicorn
    ```

=== "pip"

    ```bash
    pip install djapi-guard gunicorn
    ```

Then run:

```bash
# Run with gunicorn
gunicorn examples.wsgi:application --bind 0.0.0.0:8000 --reload

# Or with Django's built-in server
python manage.py runserver
```

___

## Features

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses with CIDR support.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP, with per-endpoint and geo-based rate limits.
- **Automatic IP Banning**: Automatically ban IPs after a configurable number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts (XSS, SQL injection, command injection, path traversal, and more).
- **Custom Logging**: Log security events to a custom file with configurable log levels.
- **CORS Configuration**: Configure CORS settings for your Django application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use IPInfo.io API to determine the country of an IP address.
- **Security Headers**: OWASP-recommended security headers (HSTS, CSP, X-Frame-Options, etc.).
- **Route-Level Security**: Per-route security configuration via decorators.
- **Behavioral Analysis**: Endpoint usage tracking, anomaly detection, and return pattern monitoring.
- **Time-Based Access Control**: Restrict access to specific time windows.
- **Authentication Enforcement**: Require API keys, Bearer tokens, or session-based auth per route.
- **Content Filtering**: Validate content types and enforce request size limits.
- **Emergency Mode**: Block all traffic except whitelisted IPs during incidents.
- **Flexible Storage**: Choose between Redis-backed distributed state or in-memory storage.
- **Automatic Fallback**: Seamless operation with or without a Redis connection.
- **Secure Proxy Handling**: Protection against X-Forwarded-For header injection attacks.
- **Honeypot Detection**: Bot detection via hidden form fields.

___

## Architecture Overview

DjangoAPI Guard uses the standard Django middleware pattern with the `__call__` method for request/response processing. This provides full access to route-specific configuration, decorator metadata, and URL resolution.

### Middleware Execution Flow

**Request processing (security pipeline):**

1. Handle passthrough/bypass cases
2. Get route config and client IP
3. Execute security check pipeline (17 checks)
4. Process behavioral usage rules
5. If any check fails, return an error response (short-circuits the request)

**Response processing:**

1. Apply security headers
2. Apply CORS headers
3. Collect metrics
4. Process behavioral return rules
5. Execute custom response modifier

### Security Check Pipeline

The pipeline uses a Chain of Responsibility pattern with 17 checks executed in order:

| Order | Check | Purpose |
|-------|-------|---------|
| 1 | Route config extraction | Resolve per-route decorator config |
| 2 | Emergency mode | Block all traffic except whitelisted IPs |
| 3 | HTTPS enforcement | Redirect or reject non-HTTPS requests |
| 4 | Request logging | Log incoming requests |
| 5 | Size/content validation | Max request size, allowed content types |
| 6 | Required headers | Verify presence of required headers |
| 7 | Authentication | Verify auth requirements (API key, session) |
| 8 | Referrer validation | Validate request referrer against allowlist |
| 9 | Custom validators | Execute user-defined validator functions |
| 10 | Time windows | Enforce time-based access restrictions |
| 11 | Cloud IP refresh | Periodically refresh cloud provider IP ranges |
| 12 | IP security | Whitelist/blacklist, country-based filtering |
| 13 | Cloud provider blocking | Block requests from AWS/GCP/Azure IPs |
| 14 | User agent filtering | Block specific user agents |
| 15 | Rate limiting | Sliding window rate limits (per-IP, per-endpoint) |
| 16 | Suspicious activity | Penetration attempt detection |
| 17 | Custom request checks | Execute user-defined request check function |

___

## Route-Level Security

DjangoAPI Guard provides a decorator system for per-route security overrides:

```python
# settings.py
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(rate_limit=100, rate_limit_window=60)

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    # ...
]
```

```python
# views.py
from django.http import JsonResponse
from djangoapi_guard import SecurityDecorator, SecurityConfig

config = SecurityConfig(rate_limit=100, rate_limit_window=60)
security = SecurityDecorator(config)

@security.rate_limit(requests=5, window=60)
def rate_limited(request):
    return JsonResponse({"message": "This endpoint is rate limited", "limit": "5/minute"})

@security.require_auth(type="bearer")
def protected(request):
    return JsonResponse({"message": "Authenticated!"})

@security.content_type_filter(["application/json"])
def json_only(request):
    return JsonResponse({"message": "JSON accepted"})

@security.time_window("09:00", "17:00", "UTC")
def business_hours(request):
    return JsonResponse({"message": "Available during business hours only"})

@security.require_ip(whitelist=["127.0.0.1", "::1", "10.0.0.0/8"])
def local_only(request):
    return JsonResponse({"message": "Local access granted"})

@security.bypass(["all"])
def unprotected(request):
    return JsonResponse({"message": "No security checks applied"})
```

___

## Detection Engine

DjangoAPI Guard includes a detection engine for identifying penetration attempts via pattern matching, semantic analysis, and anomaly detection. Attack categories detected include:

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

___

## Configuration

DjangoAPI Guard uses a Pydantic model (`SecurityConfig`) for validated configuration. Key configuration areas include:

- **Proxy and trust settings**: Trusted proxies, proxy depth, X-Forwarded-Proto trust
- **Core security**: Passive mode, Redis integration, Redis prefix
- **IP management**: Whitelists, blacklists, country-based filtering
- **Rate limiting**: Global limits, per-endpoint limits, sliding window
- **Security headers**: OWASP defaults (HSTS, CSP, X-Frame-Options, etc.)
- **CORS**: Origins, methods, headers, credentials, max age
- **Cloud provider blocking**: AWS, GCP, Azure IP range blocking
- **Logging**: Custom log files, configurable log levels
- **Emergency mode**: Block all traffic except whitelisted IPs
- **Detection engine**: Compiler timeout, content length limits, semantic threshold, anomaly threshold
- **Custom functions**: Synchronous request checks and response modifiers
- **Path exclusions**: Skip security checks for specific paths

```python
# settings.py
from django.http import HttpRequest, HttpResponse
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    # Rate limiting
    rate_limit=100,
    rate_limit_window=60,

    # IP management
    whitelist=["127.0.0.1", "::1"],
    blacklist=[],

    # Auto-banning
    auto_ban_threshold=10,
    auto_ban_duration=3600,

    # Redis
    enable_redis=True,
    redis_url="redis://localhost:6379",
    redis_prefix="djangoapi_guard:",

    # Penetration detection
    enable_penetration_detection=True,

    # CORS
    enable_cors=True,
    cors_allow_origins=["https://example.com"],

    # Security headers
    security_headers={
        "enabled": True,
        "csp": "default-src 'self'; script-src 'self'",
        "hsts": {"max_age": 31536000, "include_subdomains": True},
        "frame_options": "DENY",
        "content_type_options": "nosniff",
    },

    # Custom request check (sync)
    custom_request_check=lambda request: None,

    # Custom response modifier (sync)
    custom_response_modifier=lambda response: response,

    # Path exclusions
    exclude_paths=["/health", "/static", "/favicon.ico"],
)

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
    # ...
]
```

___

## Key Differences from FastAPI Guard

DjangoAPI Guard is a direct port of [FastAPI Guard](https://github.com/Guard-Core/fastapi-guard) adapted for Django's synchronous model:

| Aspect | FastAPI Guard | DjangoAPI Guard |
|--------|--------------|----------------|
| **Entry point** | `SecurityMiddleware` (ASGI) | `DjangoAPIGuard` (Django middleware) |
| **Hook mechanism** | ASGI `dispatch(request, call_next)` | Django `__call__(request)` |
| **Execution model** | `async`/`await` | Fully synchronous |
| **Server model** | ASGI (uvicorn) | WSGI (gunicorn, waitress) |
| **Request object** | `starlette.requests.Request` | `django.http.HttpRequest` |
| **Response object** | `starlette.responses.Response` | `django.http.HttpResponse` |
| **Request state** | `request.state` | `request._guard_*` attributes |
| **Redis client** | `redis.asyncio.Redis` | `redis.Redis` (sync) |
| **HTTP client** | `httpx.AsyncClient` | `httpx.Client` (sync) |
| **Custom callables** | `async def check(request)` | `def check(request)` |
| **Configuration** | Passed to middleware constructor | `settings.GUARD_SECURITY_CONFIG` |

___

## Documentation

- [Release Notes](release-notes.md)
- [GitHub Repository](https://github.com/Guard-Core/djapi-guard)
- [PyPI Package](https://pypi.org/project/djapi-guard/)
- [FastAPI Guard (upstream)](https://github.com/Guard-Core/fastapi-guard)
