---

title: Authentication Decorators - DjangoAPI Guard
description: Learn how to use authentication decorators for HTTPS enforcement, auth requirements, and API key validation
keywords: authentication, https, api keys, security headers, authorization decorators
---

Authentication Decorators
=========================

Authentication decorators provide route-level authentication and authorization controls.

___

HTTPS Enforcement
-----------------

```python
from djangoapi_guard import SecurityDecorator
from django.http import JsonResponse

guard_deco = SecurityDecorator(config)


@guard_deco.require_https()
def login(request):
    return JsonResponse({"token": "secure_jwt_token"})
```

___

Authentication Requirements
---------------------------

```python
@guard_deco.require_auth(type="bearer")
def user_profile(request):
    return JsonResponse({"profile": "user data"})
```

___

API Key Authentication
----------------------

```python
@guard_deco.api_key_auth(header_name="X-API-Key")
def api_key_endpoint(request):
    return JsonResponse({"data": "api key required"})
```

___

Required Headers
----------------

```python
@guard_deco.require_headers(
    {"X-Requested-With": "XMLHttpRequest", "X-CSRF-Token": "required"}
)
def secure_endpoint(request):
    return JsonResponse({"data": "csrf protected"})
```

___

Combined Authentication Patterns
--------------------------------

```python
@guard_deco.require_https()  # Secure connection
@guard_deco.require_auth(type="bearer")  # Bearer token
@guard_deco.api_key_auth(header_name="X-Admin-Key")  # Admin API key
@guard_deco.require_headers({"X-CSRF-Token": "required", "X-Request-ID": "required"})
def critical_admin_endpoint(request):
    return JsonResponse({"status": "critical operation completed"})
```

___

Error Handling
--------------

- **400 Bad Request**: Missing required headers
- **401 Unauthorized**: Invalid or missing authentication
- **403 Forbidden**: Valid auth but insufficient permissions
- **301/302 Redirect**: HTTP to HTTPS redirect

___

Next Steps
----------

- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Rate Limiting Decorators](rate-limiting.md)** - Request rate controls
- **[Behavioral Analysis](behavioral.md)** - Monitor authentication patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Authentication API Documentation](../../api/decorators.md#authenticationmixin).
