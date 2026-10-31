---

title: Security Configuration - DjangoAPI Guard
description: Complete guide to DjangoAPI Guard's SecurityConfig model and configuration options
keywords: security config, configuration, settings, django settings
---

Security Configuration
=====================

DjangoAPI Guard uses Pydantic models for configuration and data structures.

___

SecurityConfig
--------------

The main configuration model for DjangoAPI Guard middleware.

```python
class SecurityConfig(BaseModel):
    """
    Main configuration model for DjangoAPI Guard.
    Configured via settings.GUARD_SECURITY_CONFIG in your Django settings.
    """
```

Core Security Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `passive_mode` | bool | False | If True, only log without blocking |
| `enable_penetration_detection` | bool | True | Enable penetration attempt detection |
| `auto_ban_threshold` | int | 10 | Number of suspicious requests before auto-ban |
| `auto_ban_duration` | int | 3600 | Auto-ban duration in seconds |
| `route_resolution_strict` | bool | False | Block with 500 when Django could not resolve the request path to a view, instead of running the pipeline with no per-route config. Also turns unresolvable paths into 500s rather than 404s. Requires guard-core >= 3.7.0 |

Detection Engine Settings
-------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detection_compiler_timeout` | float | 2.0 | Timeout for pattern compilation and execution (seconds) |
| `detection_max_content_length` | int | 10000 | Maximum content length to analyze |
| `detection_preserve_attack_patterns` | bool | True | Preserve attack patterns during content truncation |
| `detection_semantic_threshold` | float | 0.7 | Minimum threat score for semantic detection (0.0-1.0) |
| `detection_anomaly_threshold` | float | 3.0 | Standard deviations to consider performance anomaly |
| `detection_slow_pattern_threshold` | float | 0.1 | Execution time to consider pattern slow (seconds) |
| `detection_monitor_history_size` | int | 1000 | Number of performance metrics to keep in history |
| `detection_max_tracked_patterns` | int | 1000 | Maximum patterns to track for performance |

IP Management Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `whitelist` | list[str] \| None | None | List of always-allowed IP addresses or CIDR ranges |
| `blacklist` | list[str] | [] | List of always-blocked IP addresses or CIDR ranges |
| `blocked_countries` | list[str] | [] | List of blocked country codes |
| `whitelist_countries` | list[str] | [] | List of allowed country codes |
| `blocked_user_agents` | list[str] | [] | List of blocked user agent patterns |

Redis Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_redis` | bool | False | Enable Redis integration. Left unset, Redis is on exactly when a Redis connection field (`redis_url`, `redis_prefix` and the other `redis_*` settings) is set explicitly; an explicit `enable_redis` always wins |
| `redis_url` | str \| None | "redis://localhost:6379" | Redis server URL |
| `redis_prefix` | str | "guard_core:" | Prefix for Redis keys |

Agent Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_agent` | bool | False | Enable Guard Agent integration |
| `agent_api_key` | str \| None | None | API key for agent authentication |
| `agent_endpoint` | str | "https://api.guard-core.com" | Agent API endpoint |
| `agent_enable_events` | bool | True | Send events to agent |
| `agent_enable_metrics` | bool | True | Send metrics to agent |

Cloud Provider Settings
-----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_cloud_providers` | set[str] \| None | None | Cloud providers to block (AWS, GCP, Azure) |
| `cloud_ip_refresh_interval` | int | 3600 | Interval in seconds between cloud IP range refreshes (60-86400) |

Security Headers Settings
------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `security_headers` | dict[str, Any] \| None | See below | Security headers configuration |

Default security_headers configuration:

```python
{
    "enabled": True,
    "hsts": {
        "max_age": 31536000,  # 1 year
        "include_subdomains": True,
        "preload": False,
    },
    "csp": None,  # Content Security Policy directives
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "0",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": None,  # Additional custom headers
}
```

`xss_protection` defaults to `"0"` since the 5.0.0 engine; set `"1; mode=block"` to restore the earlier default.

CORS Settings
-------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_cors` | bool | False | Enable CORS handling |
| `cors_allow_origins` | list[str] | ["*"] | Allowed origins |
| `cors_allow_methods` | list[str] | ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] | Allowed methods |
| `cors_allow_headers` | list[str] | ["*"] | Allowed headers |
| `cors_allow_credentials` | bool | False | Allow credentials |
| `cors_max_age` | int | 600 | Preflight cache duration |

Logging Settings
----------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `custom_log_file` | str \| None | None | Custom log file path |
| `log_request_level` | str \| None | None | Log level for requests |
| `log_suspicious_level` | str \| None | "WARNING" | Log level for suspicious activity |
| `log_format` | Literal["text", "json"] | "text" | Log output format |

Usage Example
-------------

```python
# settings.py
from djangoapi_guard import SecurityConfig

# Basic configuration
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=5,
    detection_semantic_threshold=0.7,
)

# Full configuration
GUARD_SECURITY_CONFIG = SecurityConfig(
    # Core settings
    passive_mode=False,
    # Detection engine
    enable_penetration_detection=True,
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
    detection_anomaly_threshold=3.0,
    detection_slow_pattern_threshold=0.1,
    detection_monitor_history_size=1000,
    detection_max_tracked_patterns=1000,
    # Security headers
    security_headers={
        "enabled": True,
        "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False},
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
        },
        "frame_options": "DENY",
    },
    # Redis
    enable_redis=True,
    redis_url="redis://localhost:6379",
    # Agent
    enable_agent=True,
    agent_api_key="your-api-key",
    # Logging
    custom_log_file="security.log",
    log_suspicious_level="WARNING",
    log_format="json",
    # Cloud IP refresh
    cloud_ip_refresh_interval=1800,
)

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    # ...
]
```

___

Configuration Validation
------------------------

The SecurityConfig model validates settings on initialization:

```python
# Validation examples
try:
    config = SecurityConfig(
        detection_compiler_timeout=0.05  # Too low
    )
except ValidationError as e:
    print(f"Configuration error: {e}")

# Valid ranges
config = SecurityConfig(
    detection_compiler_timeout=2.0,  # 0.1 - 10.0
    detection_semantic_threshold=0.7,  # 0.0 - 1.0
    detection_anomaly_threshold=3.0,  # 1.0 - 10.0
)
```

___

See Also
--------

- [Security Middleware](../../api/security-middleware.md) - Using SecurityConfig with the middleware
- [Detection Engine Configuration](../security/detection-engine/configuration.md) - Detailed configuration guide
- [Logging Configuration](logging.md) - Logging configuration
- [CORS Configuration](cors.md) - CORS configuration
