---

title: Security Monitoring - DjangoAPI Guard
description: Guide to monitoring and analyzing security events in DjangoAPI Guard
keywords: security monitoring, logging, analytics, djangoapi guard
---

Security Monitoring
==================

DjangoAPI Guard provides robust security logging capabilities for monitoring and analytics.

___

Basic Logging
-------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(custom_log_file="/path/to/security.log")
```

___

Passive Mode for Penetration Detection
---------------------------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    passive_mode=True,  # Log but don't block
)
```

___

Configurable Log Levels
------------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    log_request_level="INFO", log_suspicious_level="WARNING"
)
```

___

Log Analysis
------------

DjangoAPI Guard logs contain valuable security intelligence, including:

- IP addresses attempting suspicious actions
- Pattern matches indicating attack vectors
- Geographic origins of traffic
- Rate limiting violations
- Cloud provider origins
