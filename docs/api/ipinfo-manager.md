---

title: IPInfoManager API - DjangoAPI Guard
description: API documentation for IP geolocation and country-based filtering using IPInfo's database
keywords: ip geolocation, country filtering, ipinfo integration, location detection
---

IPInfoManager
=============

The `IPInfoManager` class handles IP geolocation using IPInfo's database with a singleton pattern.

___

Methods
-------

```python
def initialize(self):
    """Initialize and download the database if needed."""


def get_country(self, ip: str) -> str | None:
    """Get country code for an IP address."""


def close(self):
    """Close the database connection."""
```

___

Usage Example
-------------

```python
from djangoapi_guard import IPInfoManager

ipinfo_db = IPInfoManager(token="your_token")
ipinfo_db.initialize()

country = ipinfo_db.get_country("8.8.8.8")
print(f"Country: {country}")  # Output: "US"
```
