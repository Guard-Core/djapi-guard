---

title: Cloud Provider IP Blocking - DjangoAPI Guard
description: Block requests from major cloud providers like AWS, GCP, and Azure using DjangoAPI Guard's IP management
keywords: cloud ip blocking, aws blocking, gcp blocking, azure blocking, cloud security
---

Cloud Provider IP Blocking
===========================

DjangoAPI Guard can automatically detect and block requests from major cloud providers.

___

Supported Providers
-------------------

- Amazon Web Services (AWS)
- Google Cloud Platform (GCP)
- Microsoft Azure

___

Basic Configuration
-------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(block_cloud_providers={"AWS", "GCP", "Azure"})
```

___

IP Range Updates
----------------

Cloud IP ranges are refreshed automatically at a configurable interval (default: 1 hour):

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    block_cloud_providers={"AWS", "GCP", "Azure"},
    cloud_ip_refresh_interval=1800,  # Refresh every 30 minutes
)
```

You can also manually trigger a refresh:

```python
from guard_core.sync.handlers.cloud_handler import cloud_handler_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
clouds = cloud_handler_for(config)

clouds.refresh()
```

___

Provider Status
---------------

```python
from guard_core.sync.handlers.cloud_handler import cloud_handler_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
clouds = cloud_handler_for(config)

for provider in ("AWS", "GCP", "Azure"):
    updated = clouds.last_updated[provider]
    if updated:
        print(f"{provider}: last updated {updated.isoformat()}")
```

___

Custom IP Checking
-------------------

```python
from guard_core.sync.handlers.cloud_handler import cloud_handler_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
clouds = cloud_handler_for(config)
from django.http import JsonResponse


def check_cloud_ip(request, ip):
    is_cloud = clouds.is_cloud_ip(ip, providers={"AWS", "GCP", "Azure"})
    return JsonResponse({"ip": ip, "is_cloud": is_cloud})
```
