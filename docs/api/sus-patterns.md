---

title: SusPatternsManager API - DjangoAPI Guard
description: API documentation for suspicious pattern detection and management
keywords: security patterns, threat detection, pattern management, security rules api
---

SusPatternsManager
==================

The `SusPatternsManager` class manages suspicious patterns for security threat detection using a singleton pattern with enhanced detection capabilities.

___

Pattern Management Methods
--------------------------

```python
@classmethod
def add_pattern(cls, pattern: str, custom: bool = False) -> None:
    """Add a new pattern."""


@classmethod
def remove_pattern(cls, pattern: str, custom: bool = False) -> bool:
    """Remove a pattern."""


@classmethod
def get_all_patterns(cls) -> list[str]:
    """Get all registered patterns."""
```

___

Detection Methods
-----------------

```python
def detect(
    self,
    content: str,
    ip_address: str,
    context: str = "unknown",
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Perform comprehensive threat detection."""
```

___

Context-Aware Filtering
------------------------

Patterns are tagged with applicable input contexts: `query_param`, `url_path`, `header`, `request_body`, `unknown`.

___

Performance and Monitoring
--------------------------

```python
@classmethod
def get_performance_stats(cls) -> dict[str, Any] | None:
    """Get performance statistics."""


@classmethod
def get_component_status(cls) -> dict[str, bool]:
    """Check active components."""


def configure_semantic_threshold(self, threshold: float) -> None:
    """Adjust semantic threshold."""
```
