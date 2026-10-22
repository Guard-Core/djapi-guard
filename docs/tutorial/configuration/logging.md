---

title: Logging Configuration - DjangoAPI Guard
description: Configure security event logging and monitoring in DjangoAPI Guard with custom log formats and levels
keywords: django logging, security logging, event monitoring, log configuration
---

Logging Configuration
=====================

DjangoAPI Guard includes powerful logging capabilities to help you monitor and track security-related events in your application.

___

Basic Logging Setup
-------------------

DjangoAPI Guard uses a hierarchical logging namespace (`djangoapi_guard`) with automatic console output and optional file logging:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    # Optional: Enable file logging by providing a path
    custom_log_file="security.log"  # Creates file + console output
    # OR
    # custom_log_file=None  # Console output only (default)
)
```

**Key Features:**

- Console output is **always enabled** for visibility
- File logging is **optional** and only enabled when `custom_log_file` is set
- All DjangoAPI Guard components use the `djangoapi_guard.*` namespace

___

Configurable Log Levels
------------------------

DjangoAPI Guard supports different log levels for normal and suspicious requests:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    # Log normal requests as INFO (or set to None to disable)
    log_request_level="INFO",
    # Log suspicious activity as WARNING
    log_suspicious_level="WARNING",
)
```

Available log levels:

- `"INFO"`: Informational messages
- `"DEBUG"`: Detailed debug information
- `"WARNING"`: Warning messages (default for suspicious activity)
- `"ERROR"`: Error conditions
- `"CRITICAL"`: Critical errors
- `None`: Disable logging completely

___

Structured JSON Logging
------------------------

DjangoAPI Guard supports structured JSON log output for integration with log aggregation systems like ELK, Datadog, or CloudWatch:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    log_format="json", custom_log_file="security.log"
)
```

When `log_format="json"` is set, all log output (both console and file) uses structured JSON:

```json
{"timestamp": "2026-03-14 08:30:00,123", "level": "INFO", "logger": "djangoapi_guard", "message": "Request from 192.168.1.1"}
{"timestamp": "2026-03-14 08:30:01,456", "level": "WARNING", "logger": "djangoapi_guard", "message": "Suspicious activity detected from 10.0.0.5"}
```

The default `log_format="text"` preserves the human-readable format:

```text
[djangoapi_guard] 2026-03-14 08:30:00 - INFO - Request from 192.168.1.1
```

___

Performance Optimization
-------------------------

For high-traffic production environments, consider disabling normal request logging:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    # Disable normal request logging (default)
    log_request_level=None,
    # Keep security event logging enabled
    log_suspicious_level="WARNING",
)
```

___

Custom Logger
-------------

The `setup_custom_logging` function is automatically called by the middleware during initialization:

```python
from guard_core.sync.utils import setup_custom_logging

# Manual setup (if needed outside of middleware)
# Console only (no file)
logger = setup_custom_logging(None)

# Console + file logging
logger = setup_custom_logging("security.log")

# The logger uses the "djangoapi_guard" namespace
# All handlers automatically use sub-namespaces like:
# - "djangoapi_guard.handlers.redis"
# - "djangoapi_guard.handlers.cloud"
# - "djangoapi_guard.handlers.ipban"
```

**Note:** The function is synchronous and handles directory creation automatically.

___

Logger Namespace Hierarchy
---------------------------

DjangoAPI Guard uses a hierarchical namespace structure for organized logging:

```diagram
djangoapi_guard                    # Root logger for all DjangoAPI Guard components
├── djangoapi_guard.handlers       # Handler components
│   ├── djangoapi_guard.handlers.redis
│   ├── djangoapi_guard.handlers.cloud
│   ├── djangoapi_guard.handlers.ipinfo
│   ├── djangoapi_guard.handlers.ipban
│   ├── djangoapi_guard.handlers.ratelimit
│   ├── djangoapi_guard.handlers.behavior
│   ├── djangoapi_guard.handlers.suspatterns
│   └── djangoapi_guard.handlers.dynamic_rule
├── djangoapi_guard.decorators     # Decorator components
│   └── djangoapi_guard.decorators.base
└── djangoapi_guard.detection_engine  # Detection engine components
```

___

Complete Examples
-----------------

Example 1: Production Setup with File Logging
----------------------------------------------

```python
# settings.py
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    # File + console logging for audit trail
    custom_log_file="/var/log/djapi-guard/security.log",
    # Disable normal request logging to reduce noise
    log_request_level=None,
    # Keep security events at WARNING level
    log_suspicious_level="WARNING",
    # Other security settings...
    enable_redis=True,
    enable_penetration_detection=True,
)
```

Example 2: Development Setup with Console Only
-----------------------------------------------

```python
# settings.py
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    # Console-only output for development
    custom_log_file=None,  # No file logging
    # Enable all logging for debugging
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    # Other settings...
    passive_mode=True,  # Log-only mode for testing
)
```

Example 3: Custom Component-Level Configuration
------------------------------------------------

```python
import logging
from djangoapi_guard import SecurityConfig

# Configure specific component log levels
logging.getLogger("djangoapi_guard.handlers.redis").setLevel(logging.DEBUG)
logging.getLogger("djangoapi_guard.handlers.ipban").setLevel(logging.INFO)
logging.getLogger("djangoapi_guard.detection_engine").setLevel(logging.WARNING)

GUARD_SECURITY_CONFIG = SecurityConfig(
    custom_log_file="security.log",
    # ... other settings
)
```

Example 4: Integration with Django Logging
------------------------------------------------

```python
import logging

# Configure your application logging
app_logger = logging.getLogger("myapp")
app_logger.setLevel(logging.INFO)

# DjangoAPI Guard logs are isolated under "djangoapi_guard" namespace
# No interference with your app logs

# settings.py
GUARD_SECURITY_CONFIG = SecurityConfig(
    custom_log_file="security.log",  # Separate security log file
)

# Your app logs and DjangoAPI Guard logs remain separate
app_logger.info("Application started")  # Goes to "myapp" logger
# Security events go to "djangoapi_guard" logger
```
