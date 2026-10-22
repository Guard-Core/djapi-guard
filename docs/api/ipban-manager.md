---

title: IPBanManager API - DjangoAPI Guard
description: API reference for DjangoAPI Guard's IP banning system
keywords: ip ban api, ban management, ip blocking api, security api
---

IPBanManager
============

The `IPBanManager` class handles temporary IP bans.

___

Methods
-------

```python
def ban_ip(ip: str, duration: int) -> None:
    """Ban an IP address for a specified duration."""


def is_ip_banned(ip: str) -> bool:
    """Check if an IP address is currently banned."""


def reset() -> None:
    """Reset all banned IPs and every auto-ban strike (memory and Redis)."""


def unban_ip(ip: str) -> None:
    """Unban an IP address and clear its auto-ban strikes."""
```

___

Usage with DjangoAPIGuard
-----------------------------

```python
# settings.py
GUARD_SECURITY_CONFIG = SecurityConfig(auto_ban_threshold=5, auto_ban_duration=3600)
```
