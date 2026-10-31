---

title: Core Architecture - DjangoAPI Guard
description: Internal architecture documentation for DjangoAPI Guard's modular core system
keywords: core architecture, modular design, security checks, middleware internals
---

Core Architecture (Internal)
=============================

!!! warning "Internal Implementation Details"
    The `djangoapi_guard/core/` modules documented here are **internal implementation details** and should NOT be imported directly. Always use the public API.

___

Overview
--------

DjangoAPI Guard uses a modular core architecture that separates security concerns into specialized, independently testable modules.

Module Overview
----------------

```text
djangoapi_guard/core/
├── checks/              # Security check pipeline (Chain of Responsibility)
├── events/              # Event bus and metrics collection
├── initialization/      # Handler initialization logic
├── responses/           # Response creation and processing
├── routing/             # Route configuration resolution
├── validation/          # Request validation utilities
├── bypass/              # Security bypass handling
└── behavioral/          # Behavioral rule processing
```

___

Security Check Pipeline
-----------------------

Up to 18 checks execute in this order (guard-core's `DEFAULT_CHECK_CLASSES`, `guard_core/sync/core/checks/factory.py`; a check that the configuration can never trigger is not built):

1. **RouteConfigCheck** - Extract route config and client IP
2. **EmergencyModeCheck** - Emergency mode (highest priority)
3. **HttpsEnforcementCheck** - HTTPS enforcement (can redirect)
4. **RequestLoggingCheck** - Log request
5. **RequestSizeContentCheck** - Validate size/content
6. **CloudIpRefreshCheck** - Periodic maintenance
7. **IpSecurityCheck** - IP whitelist/blacklist
8. **CloudProviderCheck** - Cloud provider blocking
9. **UserAgentCheck** - User agent filtering
10. **CorsPreflightCheck** - CORS preflight answers
11. **RateLimitCheck** - Rate limiting
12. **RequiredHeadersCheck** - Check required headers
13. **AuthenticationCheck** - Verify authentication
14. **ReferrerCheck** - Check referrer
15. **CustomValidatorsCheck** - Custom validators
16. **TimeWindowCheck** - Time-based access
17. **SuspiciousActivityCheck** - Threat detection
18. **CustomRequestCheck** - Custom checks

___

See Also
--------

- [DjangoAPIGuard](security-middleware.md) - Main middleware documentation
- [API Overview](overview.md) - Complete API reference
- [Decorators](decorators.md) - Route-level security decorators
