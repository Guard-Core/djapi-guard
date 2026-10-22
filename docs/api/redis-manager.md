---

title: RedisManager API - DjangoAPI Guard
description: API reference for Redis-based distributed state management
keywords: redis integration, distributed state, connection pooling, atomic operations
---

RedisManager
============

The `RedisManager` class handles Redis connections and atomic operations with automatic retries.

___

Key Methods
-----------

```python
def initialize(self):
    """Initialize Redis connection with retry logic"""


@contextmanager
def get_connection(self):
    """Context manager for safe Redis operations"""


def get_key(self, namespace: str, key: str) -> Any:
    """Get namespaced key with prefix"""


def set_key(self, namespace: str, key: str, value: Any, ttl: int | None = None) -> bool:
    """Set namespaced key with optional TTL"""


def incr(self, namespace: str, key: str, ttl: int | None = None) -> int:
    """Atomic increment with expiration"""
```

___

Usage Example
-------------

```python
from djangoapi_guard import RedisManager
from djangoapi_guard import SecurityConfig

config = SecurityConfig(redis_url="redis://localhost:6379")
redis = RedisManager(config)

redis.initialize()
redis.set_key("namespace", "key", "value", ttl=3600)
```
