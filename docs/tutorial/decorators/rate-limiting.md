---

title: Rate Limiting Decorators - DjangoAPI Guard
description: Learn how to use rate limiting decorators for custom request rate controls and geographic rate limiting
keywords: rate limiting, request throttling, geographic limits, api rate control, security decorators
---

Rate Limiting Decorators
=========================

Rate limiting decorators allow you to apply custom rate limits to specific endpoints, overriding global settings.

___

Basic Rate Limiting
-------------------

```python
from djangoapi_guard import SecurityDecorator
from django.http import JsonResponse

guard_deco = SecurityDecorator(config)


@guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
def limited_endpoint(request):
    return JsonResponse({"data": "rate limited"})
```

___

Endpoint-Specific Rate Limits
-------------------

```python
@guard_deco.rate_limit(requests=5, window=300)  # 5 attempts per 5 minutes
def login(request):
    return JsonResponse({"token": "jwt_token"})


@guard_deco.rate_limit(requests=3, window=3600)  # 3 registrations per hour
def register(request):
    return JsonResponse({"status": "user created"})
```

___

Geographic Rate Limiting
-------------------------

```python
@guard_deco.geo_rate_limit(
    {
        "US": (100, 3600),  # 100 requests/hour for US
        "CA": (100, 3600),  # 100 requests/hour for Canada
        "CN": (10, 3600),  # 10 requests/hour for China
        "*": (50, 3600),  # 50 requests/hour for others
    }
)
def geo_limited_content(request):
    return JsonResponse({"data": "geographic rate limited"})
```

___

Combining with Other Decorators
-------------------------------

```python
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
@guard_deco.rate_limit(requests=20, window=3600)  # 20 actions per hour
def admin_action(request):
    return JsonResponse({"status": "admin action completed"})
```

___

Error Handling
--------------

- **429 Too Many Requests**: Rate limit exceeded

___

Next Steps
----------

- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Rate Limiting API Documentation](../../api/decorators.md#ratelimitingmixin).
