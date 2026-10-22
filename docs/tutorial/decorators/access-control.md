---

title: Access Control Decorators - DjangoAPI Guard
description: Learn how to use access control decorators for IP filtering, geographic restrictions, and cloud provider blocking
keywords: access control, ip filtering, geographic restrictions, cloud blocking, security decorators
---

Access Control Decorators
==========================

Access control decorators allow you to restrict access to specific endpoints based on IP addresses, geographic location, and cloud providers.

___

IP Address Filtering
--------------------

Control access based on specific IP addresses or CIDR ranges:

. IP Whitelist
------------

```python
from djangoapi_guard import SecurityDecorator
from django.http import JsonResponse

guard_deco = SecurityDecorator(config)


@guard_deco.require_ip(whitelist=["192.168.1.0/24", "10.0.0.1"])
def internal_endpoint(request):
    return JsonResponse({"message": "Internal network access only"})
```

. IP Blacklist
------------

```python
@guard_deco.require_ip(blacklist=["203.0.113.0/24", "198.51.100.1"])
def public_endpoint(request):
    return JsonResponse({"message": "Public access except blocked IPs"})
```

___

Geographic Restrictions
-----------------------

. Block Specific Countries
------------------------

```python
@guard_deco.block_countries(["CN", "RU", "IR", "KP"])
def compliance_endpoint(request):
    return JsonResponse({"data": "Compliance-restricted content"})
```

. Allow Only Specific Countries
-----------------------------

```python
@guard_deco.allow_countries(["US"])
def us_only_endpoint(request):
    return JsonResponse({"data": "US-only content"})
```

___

Cloud Provider Blocking
------------------------

```python
@guard_deco.block_clouds(["AWS", "GCP"])
def no_clouds_endpoint(request):
    return JsonResponse({"data": "No cloud provider access"})
```

___

Bypassing Security Checks
-------------------------

. Valid Bypass Tokens
-------------------

| Token | Skips |
|---|---|
| `all` | The entire security pipeline for the route |
| `ip_ban` | The standing banned-IP check |
| `ip` | Global IP whitelist/blacklist, blocked countries and blocked clouds |
| `clouds` | The cloud provider check |
| `rate_limit` | Global, endpoint, route and geo rate limiting |
| `penetration` | Detection engine / suspicious activity |

An unknown token is ignored and logged as a warning naming it, so a typo leaves the check fully enforced rather than raising. There is no country-only token: country blocking is bypassed by `ip`, which also lifts the global IP whitelist and blacklist for that route.

```python
@guard_deco.bypass(["rate_limit", "ip"])  # Bypass rate limiting and IP checks
def health_check(request):
    return JsonResponse({"status": "healthy"})


@guard_deco.bypass(["all"])  # Bypass all security checks
def public_health_check(request):
    return JsonResponse({"status": "public health endpoint"})
```

___

Combining Access Controls
-------------------------

```python
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
@guard_deco.allow_countries(["US", "CA"])  # North America only
@guard_deco.block_clouds(["AWS", "GCP"])  # No cloud providers
def ultra_secure_endpoint(request):
    return JsonResponse({"data": "Maximum security endpoint"})
```

___

Error Handling
--------------

- **403 Forbidden**: IP not in whitelist, IP in blacklist, country blocked, cloud provider detected

___

Next Steps
----------

- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements
- **[Rate Limiting Decorators](rate-limiting.md)** - Custom rate controls
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Access Control API Documentation](../../api/decorators.md#accesscontrolmixin).
