---

title: Content Filtering Decorators - DjangoAPI Guard
description: Learn how to use content filtering decorators for request validation, content type filtering, and size limits
keywords: content filtering, request validation, content types, size limits, user agent blocking
---

Content Filtering Decorators
============================

Content filtering decorators allow you to control and validate incoming requests based on content type, size, user agents, referrers, and custom validation logic.

___

Content Type Filtering
----------------------

```python
from djangoapi_guard import SecurityDecorator
from django.http import JsonResponse

guard_deco = SecurityDecorator(config)


@guard_deco.content_type_filter(["application/json"])
def json_only_endpoint(request):
    return JsonResponse({"message": "JSON only"})
```

___

Request Size Limits
-------------------

```python
@guard_deco.max_request_size(1024 * 1024)  # 1MB limit
def small_upload(request):
    return JsonResponse({"status": "Small file upload"})
```

___

User Agent Blocking
-------------------

```python
@guard_deco.block_user_agents(
    [
        r"bot",
        r"crawler",
        r"spider",
    ]
)
def human_only_endpoint(request):
    return JsonResponse({"message": "Human users only"})
```

___

Referrer Requirements
--------------------

```python
@guard_deco.require_referrer(["myapp.com", "app.mycompany.com"])
def internal_api(request):
    return JsonResponse({"message": "Internal API access"})
```

___

Custom Validation
-----------------

```python
from django.http import HttpResponse


def validate_api_version(req) -> HttpResponse | None:
    version = req.META.get("HTTP_API_VERSION")
    if not version:
        return HttpResponse("Missing API-Version header", status=400)
    if version not in ["1.0", "2.0", "2.1"]:
        return HttpResponse("Unsupported API version", status=400)
    return None


@guard_deco.custom_validation(validate_api_version)
def versioned_endpoint(request):
    return JsonResponse({"message": "Version validated"})
```

___

Error Handling
--------------

- **400 Bad Request**: Missing required headers, invalid content
- **413 Payload Too Large**: Request size exceeds limit
- **415 Unsupported Media Type**: Content type not allowed
- **403 Forbidden**: User agent blocked, referrer not allowed

___

Next Steps
----------

- **[Advanced Decorators](advanced.md)** - Time windows and detection controls
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions

For complete API reference, see the [Content Filtering API Documentation](../../api/decorators.md#contentfilteringmixin).
