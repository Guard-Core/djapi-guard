---

title: Security Decorators API - DjangoAPI Guard
description: API reference for managing security decorators in DjangoAPI Guard
keywords: security decorators, djangoapi guard, security middleware, python api reference
---

Security Decorators
======================

The decorators module provides route-level security controls for individual Django views.

___

Main Decorator Class
---------------

. SecurityDecorator
----------------------------

::: guard_core.decorators.SecurityDecorator

```python
from djangoapi_guard import SecurityConfig
from djangoapi_guard import SecurityDecorator

config = SecurityConfig(
    # geo source for block_countries, allow_countries and geo_rate_limit; response body scanning for return_monitor
    ipinfo_token="your_ipinfo_token_here",
    behavior_scan_response_body=True,
)
guard_deco = SecurityDecorator(config)


@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
def sensitive_endpoint(request):
    return JsonResponse({"data": "sensitive"})
```

___

Mixin Classes
-------------

. AccessControlMixin
---------------------

::: guard_core.decorators.access_control.AccessControlMixin

- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(countries=[])` - Block specific countries
- `@guard_deco.allow_countries(countries=[])` - Allow only specific countries
- `@guard_deco.block_clouds(providers=[])` - Block cloud provider IPs
- `@guard_deco.bypass(checks=[])` - Bypass specific security checks

. AuthenticationMixin
---------------------

::: guard_core.decorators.authentication.AuthenticationMixin

- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer")` - Require authentication
- `@guard_deco.api_key_auth(header_name="X-API-Key")` - API key authentication
- `@guard_deco.require_headers(headers={})` - Require specific headers

. RateLimitingMixin
---------------------

::: guard_core.decorators.rate_limiting.RateLimitingMixin

- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={})` - Geographic rate limiting

. BehavioralMixin
---------------------

::: guard_core.decorators.behavioral.BehavioralMixin

- `@guard_deco.usage_monitor(max_calls, window, action)` - Monitor endpoint usage
- `@guard_deco.return_monitor(pattern, max_occurrences, window, action)` - Monitor return patterns
- `@guard_deco.behavior_analysis(rules=[])` - Apply multiple behavioral rules

. ContentFilteringMixin
---------------------

::: guard_core.decorators.content_filtering.ContentFilteringMixin

- `@guard_deco.block_user_agents(patterns=[])` - Block user agent patterns
- `@guard_deco.content_type_filter(allowed_types=[])` - Filter content types
- `@guard_deco.max_request_size(size_bytes)` - Limit request size
- `@guard_deco.require_referrer(allowed_domains=[])` - Require specific referrers
- `@guard_deco.custom_validation(validator)` - Add custom validation logic

. AdvancedMixin
-------------

::: guard_core.decorators.advanced.AdvancedMixin

- `@guard_deco.time_window(start_time, end_time, timezone)` - Time-based access control
- `@guard_deco.suspicious_detection(enabled=True)` - Toggle suspicious pattern detection
- `@guard_deco.honeypot_detection(trap_fields=[])` - Detect bots using honeypot fields

___

Configuration Priority
--------------

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)
