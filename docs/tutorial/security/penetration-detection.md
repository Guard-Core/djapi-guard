---

title: Penetration Detection - DjangoAPI Guard
description: Detect and prevent common attack patterns including SQL injection, XSS, and other security threats
keywords: penetration detection, attack prevention, security patterns, threat detection
---

Penetration Detection
=====================

DjangoAPI Guard includes sophisticated penetration attempt detection to identify and block malicious requests.

___

Basic Configuration
-------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=5,
    auto_ban_duration=3600,
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
)
```

___

Detection Patterns
------------------

The system checks for: SQL Injection, XSS, Command Injection, Path Traversal, Template Injection, HTTP Response Splitting, LDAP Injection, XML Injection, NoSQL Injection, and File Upload attacks.

___

Custom Detection Logic
----------------------

```python
from guard_core.sync.utils import detect_penetration_attempt
from django.http import JsonResponse


def submit_data(request):
    is_suspicious, trigger_info = detect_penetration_attempt(request)
    if is_suspicious:
        return JsonResponse(
            {"error": f"Suspicious activity detected: {trigger_info}"}, status=400
        )
    return JsonResponse({"status": "success"})
```

___

Passive Mode
------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    passive_mode=True,  # Don't block, just log
)
```

___

Further Reading

- [Detection Engine Overview](detection-engine/overview.md)
- [Detection Engine Architecture](detection-engine/architecture.md)
- [Detection Engine Components](detection-engine/components.md)
- [Performance Tuning Guide](detection-engine/performance-tuning.md)
