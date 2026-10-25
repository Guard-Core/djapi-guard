# Detection Engine Configuration Guide

## Configuration Profiles

### High Security Profile

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=3,
    auto_ban_duration=7200,
    detection_compiler_timeout=1.0,
    detection_max_content_length=5000,
    detection_semantic_threshold=0.5,
    detection_anomaly_threshold=2.0,
)
```

### Performance Optimized Profile

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=10,
    auto_ban_duration=1800,
    detection_compiler_timeout=3.0,
    detection_max_content_length=2000,
    detection_semantic_threshold=0.8,
    detection_anomaly_threshold=4.0,
    detection_monitor_history_size=500,
)
```

### Development Profile

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    passive_mode=True,
    detection_compiler_timeout=5.0,
    detection_max_content_length=50000,
    detection_monitor_history_size=5000,
    custom_log_file="security-debug.log",
)
```

## Dynamic Configuration

```python
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
patterns = sus_patterns_manager_for(config)

# Adjust semantic threshold dynamically
patterns.configure_semantic_threshold(0.8)

# Add custom patterns
patterns.add_pattern(r"(?i)custom_threat_pattern", custom=True)

# Check component status
status = patterns.get_component_status()
```

## Next Steps

- Review [Performance Tuning Guide](performance-tuning.md)
- Explore [Custom Pattern Development](../custom-patterns.md)
