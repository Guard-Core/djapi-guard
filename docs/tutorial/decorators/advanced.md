---

title: Advanced Security Decorators - DjangoAPI Guard
description: Learn how to use advanced security decorators for time-based access, honeypot detection, and suspicious pattern control
keywords: advanced security, time window, honeypot, suspicious patterns, security decorators
---

Advanced Security Decorators
============================

Advanced security decorators offer sophisticated controls including time-based access rules, honeypots, and suspicious pattern detection control.

___

Time-Based Access Control
-------------------------

```python
from djangoapi_guard import SecurityDecorator
from django.http import JsonResponse

guard_deco = SecurityDecorator(config)


@guard_deco.time_window("09:00", "17:00", "EST")
def generate_reports(request):
    return JsonResponse({"message": "Reports are only available during business hours"})
```

___

Honeypot Protection
-------------------

```python
@guard_deco.honeypot_detection(trap_fields=["website_url"])
def register_user(request):
    return JsonResponse({"message": "User registered successfully"})
```

___

Suspicious Pattern Detection Control
------------------------------------

```python
@guard_deco.suspicious_detection(enabled=False)
def submit_code(request):
    return JsonResponse({"status": "Code submitted for review"})
```

___

Error Handling
--------------

- **403 Forbidden**: Outside allowed time window, honeypot field filled

___

Next Steps
----------

- **[Behavioral Analysis Decorators](behavioral.md)** - Monitor usage patterns and detect anomalies
- **[Content Filtering](content-filtering.md)** - Validate and sanitize request data
- **[Rate Limiting Decorators](rate-limiting.md)** - Protect against brute-force attacks

For complete API reference, see the [Advanced Decorators API Documentation](../../api/decorators.md#advancedmixin).
