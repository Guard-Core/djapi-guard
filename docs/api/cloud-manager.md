---

title: CloudManager API - DjangoAPI Guard
description: API reference for managing and detecting IP addresses from major cloud providers
keywords: cloud ip detection, aws ip ranges, gcp ip ranges, azure ip ranges
---

CloudManager
============

The `CloudManager` class manages detection of IP addresses from major cloud providers (AWS, GCP, Azure) with singleton pattern.

___

Methods
-------

```python
def refresh(self, providers=_ALL_PROVIDERS):
    """Refresh IP ranges."""


def is_cloud_ip(self, ip: str, providers: set[str]) -> bool:
    """Check if IP belongs to cloud providers."""


def initialize_redis(self, redis_handler, providers=_ALL_PROVIDERS, ttl=3600):
    """Initialize Redis integration."""
```

___

Usage Example
-------------

```python
from djangoapi_guard import cloud_handler

is_cloud = cloud_handler.is_cloud_ip("35.186.224.25", {"AWS", "GCP", "Azure"})
cloud_handler.refresh()

aws_updated = cloud_handler.last_updated["AWS"]
```
