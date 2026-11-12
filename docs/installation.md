---

title: Installation - DjangoAPI Guard
description: Learn how to install and set up DjangoAPI Guard, a comprehensive security middleware for Django applications
keywords: djangoapi guard installation, python security middleware, django security setup
---

Installation
============

Install `djapi-guard` with **uv** (recommended), **poetry**, or **pip**:

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

**Note**: Ensure you have Python 3.10 or higher installed.

Optional extras. The base install carries `djapi-guard`'s own dependencies and guard-core (`cachetools`, `pydantic` and `typing-extensions`); it does not carry the Redis client, the GeoIP reader or the downloaders. A config that needs a package you did not install is refused when `SecurityConfig` is built, with a message that names the extra:

| Extra | Adds | Needed for |
|---|---|---|
| `djapi-guard[redis]` | the Redis client | `enable_redis=True`: Redis-backed rate limits, bans, caches and shared state |
| `djapi-guard[geo]` | `maxminddb` and the downloader of the built-in GeoIP manager | country rules (`blocked_countries`, `whitelist_countries`, `@block_countries`, `@allow_countries`, `@geo_rate_limit`) and `ipinfo_token` |
| `djapi-guard[cloud]` | `aiohttp` and `requests` | `block_cloud_providers` |

Combine them as needed, for example `pip install "djapi-guard[redis,geo]"`.

___

Prerequisites
-------------

Before using `djapi-guard`'s country filtering features, obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account.
2. After signing up, you'll receive an API token.
3. The free tier includes:
   - Up to 50,000 requests per month.
   - Access to IP to Country database.
   - Daily database updates.
   - IPv4 & IPv6 support.

Note: The IPInfo token is only required when using the country filtering features (`blocked_countries`, `whitelist_countries` and/or `block_cloud_providers`).

**Usage Example**:

```python
# settings.py
from djangoapi_guard import SecurityConfig
from djangoapi_guard import IPInfoManager

GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=IPInfoManager(
        "your_ipinfo_token_here"
    ),  # NOTE: Required when using country blocking
    enable_redis=True,  # Off unless a Redis field is set, enable to use Redis (without it state is in-memory)
    redis_url="redis://localhost:6379/0",
    redis_prefix="prod:security:",
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
)

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
    # ...
]
```

**Note**: Add `"djangoapi_guard"` to `INSTALLED_APPS` so `manage.py check` and `runserver` report a `detection_exclusion(path_params=...)` name its route does not have (an Error, or a Warning with `fail_on_misconfiguration=False`). Without it the first request logs the same problem once as a WARNING.

**Note**: When Redis is disabled:

- Rate limiting and IP bans become instance-local
- Cloud provider IP ranges refresh every hour
- Penetration patterns reset on app restart

___

Secure Proxy Configuration
---------------------------

If your application is behind a proxy or load balancer, configure trusted proxies:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    # Security configuration for proxies
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # Only trust specific IPs/ranges
    trusted_proxy_depth=1,  # Default proxy depth
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto from trusted proxies
    # Other config options...
)
```

This prevents IP spoofing attacks via X-Forwarded-For header manipulation.
