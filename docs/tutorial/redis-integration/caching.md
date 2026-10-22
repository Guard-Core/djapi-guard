---

title: Redis Integration - DjangoAPI Guard
description: Guide to using Redis for distributed state management in DjangoAPI Guard
keywords: redis configuration, distributed rate limiting, atomic operations
---

Redis Integration
=================

DjangoAPI Guard uses Redis for distributed state management across multiple instances.

___

Basic Configuration
-------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod-redis:6379/1",
    redis_prefix="myapp:security:",
)
```

___

Key Features
------------

- Distributed Rate Limiting
- Shared IP Ban List
- Cloud IP Range Caching
- Pattern Storage for Penetration Detection

___

Fallback Behavior
-----------------

When Redis is disabled (`enable_redis=False`):

- Uses in-memory storage (TTLCache)
- Rate limits are instance-local
- IP bans only affect current instance
- Cloud IP ranges refresh hourly

___

Connection Management
---------------------

```python
# Access RedisManager from middleware instance
# Manual connection handling example
with redis.get_connection() as conn:
    conn.set("key", "value")

# Automatic operation retry
redis.safe_operation(lambda conn: conn.get("my_key"), namespace="data", key="my_key")
```

___

Key Namespacing
---------------

Keys are automatically prefixed using: `{redis_prefix}{namespace}:{key}`

Example: `djangoapi_guard:cloud_ranges:AWS`

___

Best Practices
--------------

1. Use separate Redis databases for different environments
2. Set appropriate TTLs for transient data
3. Monitor connection pool size in high-traffic deployments
4. Use `safe_operation` for all Redis interactions
