---

title: RateLimitManager - DjangoAPI Guard
description: API reference for the RateLimitManager class
keywords: rate limiting, api security, django, rate limit handler
---

RateLimitManager
================

The `RateLimitManager` manages rate limiting with sliding window algorithm, supporting both in-memory and Redis-based storage.

___

Example Usage
-------------

```python
# settings.py
GUARD_SECURITY_CONFIG = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    enable_rate_limiting=True,
    enable_redis=True,
    redis_url="redis://localhost:6379/0",
)
```

___

See Also
--------

- [Rate Limiting Tutorial](../tutorial/ip-management/rate-limiter.md)
- [Redis Integration](../tutorial/redis-integration/caching.md)
