---

title: Utilities API - DjangoAPI Guard
description: Helper functions and utilities for logging, security checks, and request handling
keywords: security utilities, logging functions, security checks, request handling
---

Utilities
=========

The `utils` module provides helper functions for security operations.

___

Logging Functions
-----------------

```python
def setup_custom_logging(
    log_file: str | None = None, log_format: str = "text"
) -> logging.Logger:
    """Setup custom logging for DjangoAPI Guard."""


def log_activity(
    request,
    logger,
    log_type="request",
    reason="",
    passive_mode=False,
    trigger_info="",
    level="WARNING",
):
    """Universal logging function for all types of requests and activities."""
```

___

Security Check Functions
------------------------

```python
def is_user_agent_allowed(user_agent: str, config: SecurityConfig) -> bool:
    """Check if user agent is allowed."""


def is_ip_allowed(ip: str, config: SecurityConfig, ipinfo_db=None) -> bool:
    """Check if IP address is allowed."""


def detect_penetration_attempt(
    request: HttpRequest,
    config: SecurityConfig | None = None,
    route_config: RouteConfig | None = None,
) -> DetectionResult:
    """Detect potential penetration attempts using the Detection Engine."""


def extract_client_ip(
    request: HttpRequest, config: SecurityConfig, agent_handler=None
) -> str:
    """Securely extract the client IP address from the request."""
```

___

Detection Result
----------------

`detect_penetration_attempt` returns a `DetectionResult` dataclass with the following fields:

- `is_threat: bool` - Whether a threat was detected.
- `trigger_info: str` - Human-readable description of the matched component and pattern.
- `threat_categories: list[str]` - Categories raised by the detection engine (e.g. `sql_injection`, `xss`).
- `threat_scores: dict[str, float]` - Per-category confidence scores produced by the detection engine.

___

Usage Examples
--------------

```python
from guard_core.sync.utils import setup_custom_logging, detect_penetration_attempt

logger = setup_custom_logging("security.log")

# Check for penetration attempts
result = detect_penetration_attempt(request)
if result.is_threat:
    logger.warning(
        "Suspicious request from %s: %s (categories=%s)",
        request.META.get("REMOTE_ADDR"),
        result.trigger_info,
        result.threat_categories,
    )
```
