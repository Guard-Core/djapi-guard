---

title: IP Banning - DjangoAPI Guard
description: Implement automatic and manual IP banning in Django applications using DjangoAPI Guard's IPBanManager
keywords: ip banning, ip blocking, security middleware, django security
---

IP Banning
==========

DjangoAPI Guard provides powerful IP banning capabilities through the `IPBanManager`.

___

Automatic IP Banning
---------------------

Configure automatic IP banning based on suspicious activity:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds (1 hour)
)
```

___

Manual IP Banning
------------------

You can also manually ban IPs using the `IPBanManager`:

```python
from djangoapi_guard import ip_ban_manager
from django.http import JsonResponse


def ban_ip(request, ip):
    duration = int(request.GET.get("duration", 3600))
    ip_ban_manager.ban_ip(ip, duration)
    return JsonResponse({"message": f"IP {ip} banned for {duration} seconds"})
```

___

Checking Ban Status
-------------------

```python
def check_ban(request, ip):
    is_banned = ip_ban_manager.is_ip_banned(ip)
    return JsonResponse({"ip": ip, "banned": is_banned})
```

___

Reset All Bans
--------------

```python
def reset_bans(request):
    ip_ban_manager.reset()
    return JsonResponse({"message": "All IP bans cleared"})
```
