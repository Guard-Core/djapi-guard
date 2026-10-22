---

title: HTTP Security Headers - DjangoAPI Guard Tutorial
description: Configure and use security headers following OWASP best practices with DjangoAPI Guard
keywords: security headers tutorial, CSP configuration, HSTS setup, X-Frame-Options
---

HTTP Security Headers
=====================

DjangoAPI Guard provides comprehensive HTTP security header management following OWASP best practices.

___

Quick Start
-----------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    security_headers={
        "enabled": True  # Uses secure defaults
    }
)
```

This automatically adds: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, and additional cross-origin policies.

___

Content Security Policy (CSP)
------------------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    security_headers={
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'"],
        }
    }
)
```

___

HTTP Strict Transport Security (HSTS)
---------------------------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    security_headers={
        "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False}
    }
)
```

___

Tools and Resources
-------------------

- [Security Headers Scanner](https://securityheaders.com)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com)
- [Mozilla Observatory](https://observatory.mozilla.org)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

___

Next Steps
----------

- [API Reference](../../api/security-headers.md) - Detailed API documentation
- [Configuration](../configuration/security-config.md) - Complete configuration options
