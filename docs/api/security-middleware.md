---

title: DjangoAPIGuard API - DjangoAPI Guard
description: Complete API reference for DjangoAPI Guard's DjangoAPIGuard middleware class
keywords: security middleware, django middleware, api security, middleware configuration
---

DjangoAPIGuard
==================

The `DjangoAPIGuard` class is the core component that handles all security features.

!!! info "Architecture"
    DjangoAPIGuard uses a modular architecture with specialized core modules. See [Core Architecture](core-architecture.md) for internal details.

___

Class Definition
----------------

```python
class DjangoAPIGuard:
    def __init__(
        self,
        get_response: Callable[[HttpRequest], HttpResponse],
    ) -> None:
        """
        Initialize the DjangoAPIGuard middleware.

        Args:
            get_response: The next middleware or view in the chain

        Note:
            Configuration is read from settings.GUARD_SECURITY_CONFIG.
            If not set, defaults are used.
        """
```

___

Request Processing Flow
-----------------------

```text
Request -> __call__
    |
1. Handle CORS preflight
2. BypassHandler.handle_passthrough()
3. Extract client IP and route config
4. BypassHandler.handle_security_bypass()
5. SecurityCheckPipeline.execute() (17 checks)
6. BehavioralProcessor.process_usage_rules()
7. get_response(request) -> view function
8. ErrorResponseFactory.process_response()
    |
Response
```

___

Public Methods
--------------

set_decorator_handler
---------------------

```python
def set_decorator_handler(
    self, decorator_handler: BaseSecurityDecorator | None
) -> None:
    """Set the SecurityDecorator instance for decorator support."""
```

create_error_response
---------------------

```python
def create_error_response(self, status_code: int, default_message: str) -> HttpResponse:
    """Create standardized error responses."""
```

reset
-----

```python
def reset(self) -> None:
    """Reset rate limit handler state."""
```

___

Usage Examples
--------------

Basic Setup
-----------

```python
# settings.py
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    rate_limit=100, enforce_https=True, enable_cors=True
)

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    # ...
]
```

With Decorators
---------------

```python
from djangoapi_guard import SecurityDecorator
from djangoapi_guard import SecurityConfig

config = SecurityConfig(rate_limit=100)
guard_deco = SecurityDecorator(config)


@guard_deco.rate_limit(requests=10, window=300)
def limited_endpoint(request):
    return JsonResponse({"data": "limited"})
```

___

See Also
--------

- [Core Architecture](core-architecture.md) - Detailed internal architecture
- [SecurityConfig](../tutorial/configuration/security-config.md) - Configuration options
- [Decorators](decorators.md) - Route-level security
