---

title: Rate Limiting - DjangoAPI Guard
description: Learn how to implement rate limiting in your Django application using DjangoAPI Guard
keywords: rate limiting, api security, ddos protection, request throttling, django
---

Rate Limiting
=============

Rate limiting protects your API from abuse, DoS attacks, and excessive usage.

___

Basic Configuration
-------------------

```python
# settings.py
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    rate_limit=100,  # Maximum number of requests allowed
    rate_limit_window=60,  # Time window in seconds
)
```

___

How It Works
------------

DjangoAPI Guard implements a sliding window rate limiting algorithm:

1. Each client request is tracked using a timestamp
2. Only requests within the current time window are counted
3. When count exceeds `rate_limit`, the request is rejected with 429 status

___

In-Memory vs. Redis Rate Limiting
---------------------------------

**In-Memory** (default when Redis disabled):

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    enable_redis=False,
)
```

**Redis-Based** (for distributed environments):

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    redis_url="redis://localhost:6379/0",
    redis_prefix="myapp:",
)
```

___

Custom Response Messages
------------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    custom_error_responses={429: "Rate limit exceeded. Please try again later."},
)
```

___

Best Practices
--------------

1. **Set reasonable limits**: Consider your API's typical usage patterns
2. **Use Redis in production**: For reliability in distributed environments
3. **Implement graduated limits**: Consider different limits for different API endpoints
4. **Monitor usage patterns**: Keep an eye on rate limit hits to adjust as needed

___

See Also
--------

- [RateLimitManager API Reference](../../api/ratelimit-manager.md)
- [Redis Integration](../redis-integration/caching.md)
