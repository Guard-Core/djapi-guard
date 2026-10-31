---

title: IP Geolocation - DjangoAPI Guard
description: Configure country-based IP filtering and geolocation features using IPInfo's database in DjangoAPI Guard
keywords: ip geolocation, country blocking, ipinfo integration, location filtering
---

IP Geolocation
==============

DjangoAPI Guard accepts an arbitrary class that implements geolocation and country-based filtering. All it needs is to implement the following protocol:

```python
class GeoIPHandler(Protocol):
    @property
    def is_initialized(self) -> bool: ...
    def initialize(self) -> None: ...
    def initialize_redis(self, redis_handler: "RedisManager") -> None: ...
    def initialize_agent(self, agent_handler: "SyncAgentHandlerProtocol") -> None: ...
    def get_country(self, ip: str) -> str | None: ...
    def refresh(self) -> None: ...
    def close(self) -> None: ...
```

It provides an implementation that uses the [ipinfo.io](https://ipinfo.io/signup) service:

```python
from djangoapi_guard import IPInfoManager
```

___

Setup
-----

Option 1: Using the built-in IPInfoHandler
-------------------------------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    blocked_countries=["CN", "RU"],
    block_cloud_providers={"AWS", "GCP"},
)
```

Use `whitelist_countries=["US", "CA"]` instead of `blocked_countries` to allow only those countries. A non-empty `whitelist_countries` is restrictive, so `blocked_countries` has no effect while it is set and guard-core warns about the combination.

Option 2: Providing a custom geographical IP handler
----------------------------------------------------

```python
class CustomGeoIPHandler:
    @property
    def is_initialized(self) -> bool: ...
    def initialize(self) -> None: ...
    def initialize_redis(self, redis_handler: "RedisManager") -> None: ...
    def initialize_agent(self, agent_handler: "SyncAgentHandlerProtocol") -> None: ...
    def get_country(self, ip: str) -> str | None: ...
    def refresh(self) -> None: ...
    def close(self) -> None: ...


GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=CustomGeoIPHandler(),
    blocked_countries=["CN", "RU"],
)
```

___

Country Blocking
----------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    blocked_countries=["CN", "RU", "IR", "KP"],
)
```

___

Country Whitelisting
--------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    whitelist_countries=["US", "CA", "GB", "AU"],
)
```

___

Custom Geolocation Logic
------------------------

```python
from djangoapi_guard import IPInfoManager
from django.http import JsonResponse

ipinfo_db = IPInfoManager(token="your_ipinfo_token_here")
ipinfo_db.initialize()


def get_ip_country(request, ip):
    country = ipinfo_db.get_country(ip)
    return JsonResponse({"ip": ip, "country": country})
```
