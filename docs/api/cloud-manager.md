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

!!! note "Per-app accessor: `cloud_handler_for`"
    `cloud_handler` is the module-level singleton. It serves the first app built in the process, and any later app that shares its Redis prefix or has no Redis. An app on its own Redis prefix gets a separate cloud manager, and the engine resolves the manager of the app in flight with `cloud_handler_for(config)` on every request. Use the singleton for a single-app process, or to read the shared provider ranges. When a process builds more than one config (an app factory, a reload, tests), call `cloud_handler_for(config)` with the config of the app you mean, so you never talk to another app's manager. It is public, is not re-exported by this package, and is imported from `guard_core.sync.handlers.cloud_handler`: `from guard_core.sync.handlers.cloud_handler import cloud_handler_for`.
