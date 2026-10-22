---

title: Behavioral Analysis Decorators - DjangoAPI Guard
description: Learn how to use behavioral analysis decorators for usage monitoring, return pattern detection, and anomaly analysis
keywords: behavioral analysis, usage monitoring, pattern detection, anomaly detection, security decorators
---

Behavioral Analysis Decorators
==============================

Behavioral analysis decorators provide advanced monitoring capabilities to detect suspicious usage patterns and potential abuse.

___

Usage Monitoring
----------------

```python
from djangoapi_guard import SecurityDecorator
from django.http import JsonResponse

guard_deco = SecurityDecorator(config)


@guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")
def sensitive_endpoint(request):
    return JsonResponse({"data": "sensitive information"})
```

___

Return Pattern Monitoring
-------------------------

```python
@guard_deco.return_monitor("win", max_occurrences=2, window=86400, action="ban")
def lottery_endpoint(request):
    import random

    result = random.choice(["win", "lose", "lose", "lose"])
    return JsonResponse({"result": result})
```

Pattern formats supported:

- **Simple string**: `"win"`, `"success"`, `"rare_item"`
- **JSON path**: `"json:result.status==win"`
- **Regex**: `"regex:win|victory|success"`
- **Status code**: `"status:200"`

___

Action Types
------------

- **ban**: Ban the IP address
- **alert**: Send an alert notification
- **throttle**: Apply rate limiting
- **log**: Only log incidents for analysis

___

Complex Behavioral Analysis
---------------------------

```python
from djangoapi_guard import BehaviorRule

rules = [
    BehaviorRule("usage", threshold=20, window=3600, action="alert"),
    BehaviorRule(
        "return_pattern", threshold=5, pattern="win", window=86400, action="ban"
    ),
    BehaviorRule("frequency", threshold=60, window=300, action="throttle"),
]


@guard_deco.behavior_analysis(rules)
def casino_game(request):
    return JsonResponse({"result": "win", "amount": 500})
```

___

Next Steps
----------

- **[Advanced Decorators](advanced.md)** - Time windows and detection controls
- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Content Filtering](content-filtering.md)** - Request validation and filtering

For complete API reference, see the [Behavioral Analysis API Documentation](../../api/decorators.md#behavioralmixin).
