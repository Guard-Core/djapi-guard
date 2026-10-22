---

title: CORS Configuration - DjangoAPI Guard
description: Learn how to configure Cross-Origin Resource Sharing (CORS) settings in DjangoAPI Guard for secure API access
keywords: django cors, cors configuration, api security, cross origin resource sharing
---

CORS Configuration
==================

DjangoAPI Guard provides comprehensive CORS (Cross-Origin Resource Sharing) configuration options.

___

Basic CORS Setup
-----------------

Enable CORS with default settings:

```python
# settings.py
GUARD_SECURITY_CONFIG = SecurityConfig(enable_cors=True, cors_allow_origins=["*"])
```

___

Advanced Configuration
----------------------

Configure specific CORS settings:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["https://example.com", "https://api.example.com"],
    cors_allow_methods=["GET", "POST", "PUT", "DELETE"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
)
```

___

Origin Patterns
---------------

Use patterns to match multiple origins:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["https://*.example.com", "https://*.api.example.com"],
)
```

___

Credentials Support
-------------------

Enable credentials support for authenticated requests:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_cors=True,
    cors_allow_credentials=True,
    cors_allow_origins=[
        "https://app.example.com"  # Must be specific origin when using credentials
    ],
)
```

___

Custom Headers
--------------

Configure custom headers for CORS:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_cors=True,
    cors_allow_headers=["Authorization", "Content-Type", "X-Custom-Header"],
    cors_expose_headers=["X-Custom-Response-Header"],
)
```
