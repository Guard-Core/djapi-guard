---

title: Behavior Manager API - DjangoAPI Guard
description: API reference for managing behavioral analysis and monitoring
keywords: behavior manager, djangoapi guard, behavioral analysis, monitoring
---

Behavior Manager
=================

::: guard_core.handlers.behavior_handler.BehaviorTracker

The Behavior Manager handles behavioral analysis for detecting suspicious usage patterns.

___

BehaviorRule
------------

::: guard_core.handlers.behavior_handler.BehaviorRule

Rule types: `usage`, `return_pattern`, `frequency`

Pattern formats: Simple string, JSON path (`json:result.status==win`), Regex (`regex:win|victory`), Status code (`status:200`)

Actions: `ban`, `log`, `alert`, `throttle`

___

Integration with Decorators
----------------------------

```python
guard_deco = SecurityDecorator(config)


@guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="alert")
def rewards_endpoint(request):
    return JsonResponse({"reward": "rare_item"})
```

___

See Also
--------

- [Behavioral Decorators Tutorial](../tutorial/decorators/behavioral.md)
- [Redis Integration](../tutorial/redis-integration/caching.md)
