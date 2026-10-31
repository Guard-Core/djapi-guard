---

title: Custom Security Patterns - DjangoAPI Guard
description: Create and manage custom security patterns for detecting specific threats in your Django application
keywords: security patterns, custom detection, threat patterns, security rules
---

Custom Patterns
===============

DjangoAPI Guard allows you to add custom patterns for detecting suspicious activity.

___

Adding Custom Patterns
-----------------------

```python
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


def setup_patterns():
    SusPatternsManager.add_pattern(r"malicious_pattern.*", custom=True)
```

___

Pattern Types
-------------

```python
# Custom XSS pattern
SusPatternsManager.add_pattern(r"<script\s+src=[^>]*>", custom=True)

# Custom SQL injection pattern
SusPatternsManager.add_pattern(r";\s*DROP\s+TABLE", custom=True)

# Custom file path pattern
SusPatternsManager.add_pattern(r"\.\./[^/]{1,64}/etc/passwd", custom=True)
```

___

Managing Patterns
-----------------

```python
# Remove a custom pattern
success = SusPatternsManager.remove_pattern(r"malicious_pattern.*", custom=True)

# Get all patterns
all_patterns = SusPatternsManager.get_all_patterns()

# Get only custom patterns
custom_patterns = SusPatternsManager.get_custom_patterns()
```

___

Pattern Testing
---------------

```python
from guard_core.sync.utils import detect_penetration_attempt
from django.http import JsonResponse


def test_patterns(request):
    is_suspicious, trigger_info = detect_penetration_attempt(request)
    return JsonResponse(
        {
            "suspicious": is_suspicious,
            "trigger_info": trigger_info,
        }
    )
```
