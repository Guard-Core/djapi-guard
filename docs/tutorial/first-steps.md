---

title: Getting Started with DjangoAPI Guard
description: First steps guide for implementing DjangoAPI Guard security features in your Django application
keywords: django security tutorial, djangoapi guard setup, python security middleware
---

First Steps
===========

Let's start with a simple example that shows how to add DjangoAPI Guard to your application.

Create a Django application
----------------------------

First, create a new Django project:

```python
# settings.py
from djangoapi_guard import SecurityConfig
from djangoapi_guard import IPInfoManager
```

___

Configure Security Settings
----------------------------

Create a `SecurityConfig` instance in your Django settings:

```python
# settings.py
GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=IPInfoManager(
        "your_ipinfo_token_here"
    ),  # NOTE: Required for geolocation
    enable_redis=True,  # Enable Redis integration
    redis_url="redis://localhost:6379",  # Redis URL
    rate_limit=100,  # Max requests per minute
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    custom_log_file="security.log",  # Custom log file
)
```

Note: DjangoAPI Guard only loads resources as needed. The IPInfo database is only downloaded when country filtering is configured, and cloud IP ranges are only fetched when cloud provider blocking is enabled.

___

Add the Middleware
------------------

Add the security middleware to your Django `MIDDLEWARE` setting:

```python
# settings.py
MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
    # ... other middleware
]
```

___

Complete Example
----------------

Here's a complete example showing basic usage:

```python
# settings.py
from djangoapi_guard import SecurityConfig
from djangoapi_guard import IPInfoManager

GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    enable_redis=True,  # Redis enabled
    redis_url="redis://localhost:6379",
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    rate_limit=100,
    custom_log_file="security.log",
)

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
    # ...
]
```

```python
# views.py
from django.http import JsonResponse


def root(request):
    return JsonResponse({"message": "Hello World"})
```

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("", views.root),
]
```

___

Run the Application
-------------------

Run your application using gunicorn:

```bash
gunicorn myproject.wsgi:application --reload
```

Your API is now protected by DjangoAPI Guard!

___

Releasing an app
----------------

Django has no app-shutdown event (`request_finished` fires after every request), so `DjangoAPIGuard` never releases its app on its own: serving requests leaves the module-level default managers bound to the first app that took them. When a host stops a worker, or a test suite builds several middleware instances in one process, release the config explicitly:

```python
from django.conf import settings
from djangoapi_guard import release_app

release_app(settings.GUARD_SECURITY_CONFIG)
```

The host calls it once, at process shutdown, for example in gunicorn's `worker_exit` hook or an `atexit` handler. The default managers then go to the next app at that moment. An app that is never released keeps the garbage-collector-timed handoff of guard-core 5.0.0: the next app gets the defaults only once the collector has freed the earlier one, so which managers a later app gets can differ between runs. Calling it twice is harmless.

In a test suite, release the config in a fixture after each test:

```python
import pytest
from django.conf import settings
from djangoapi_guard import release_app


@pytest.fixture(autouse=True)
def release_guard_app():
    yield
    release_app(settings.GUARD_SECURITY_CONFIG)
```

Never call `release_app` from a per-request signal such as `request_finished`, or from any other per-request hook. Those run after every request, so each request would release the live app: its handlers are forgotten and the default managers go to the next app while this one is still serving. Release only at process shutdown, or at the end of a test.

___

What's Next
-----------

- Learn about [IP Management](ip-management/banning.md)
- Configure [Rate Limiting](ip-management/rate-limiter.md)
- Set up [Penetration Detection](security/penetration-detection.md)
- Learn about [Redis Integration](redis-integration/caching.md)
