---

title: Proxy Security - DjangoAPI Guard
description: Secure handling of X-Forwarded-For headers and proxy configurations in DjangoAPI Guard
keywords: proxy security, X-Forwarded-For, header security, IP spoofing prevention
---

Proxy Security
==============

When your application is behind a proxy, load balancer, or CDN, properly handling the `X-Forwarded-For` header is critical for security.

___

Secure Configuration
--------------------

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],
    trusted_proxy_depth=1,
    trust_x_forwarded_proto=True,
)
```

___

How It Works
------------

1. When a request arrives, DjangoAPI Guard checks if it's from a trusted proxy
2. If not from a trusted proxy, the direct connecting IP is always used
3. If from a trusted proxy, the X-Forwarded-For header is parsed
4. The extracted IP is then used for all security checks

___

Real-World Examples
-------------------

Single Reverse Proxy:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    trusted_proxies=["10.0.0.1"], trusted_proxy_depth=1, trust_x_forwarded_proto=True
)
```

Load Balancer + Proxy:

```python
GUARD_SECURITY_CONFIG = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],
    trusted_proxy_depth=2,
    trust_x_forwarded_proto=True,
)
```

___

Best Practices
--------------

1. **Be specific**: Only include the exact IPs or ranges of your known proxies
2. **Use correct depth**: Configure based on your actual proxy chain
3. **Regular audits**: Periodically review your trusted proxy list
4. **Test configuration**: Verify correct IP extraction in your environment
