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

___

Prerequisite: ASGI Servers Must Not Pre-Resolve the Client
----------------------------------------------------------

DjangoAPI Guard reads the connecting IP from `request.META["REMOTE_ADDR"]`. Django itself never rewrites it from `X-Forwarded-For`, and neither does Gunicorn, so a WSGI deployment needs no change. Under ASGI, Django fills `REMOTE_ADDR` from `scope["client"]`, and uvicorn's `ProxyHeadersMiddleware` rewrites `scope["client"]` from `X-Forwarded-For` before Django runs, for every peer that matches `--forwarded-allow-ips` (default `127.0.0.1,::1`).

!!! warning "`--forwarded-allow-ips='*'` lets a client choose its own identity"
    With `--forwarded-allow-ips='*'` (or `FORWARDED_ALLOW_IPS=*`) under uvicorn, a client that reaches the server directly sends a different `X-Forwarded-For` on each request and DjangoAPI Guard sees a new connecting IP every time, so rate limits and bans stop working. Pass `--no-proxy-headers` and let `trusted_proxies` resolve the client, or list in `--forwarded-allow-ips` exactly the addresses you list in `trusted_proxies` and never `*`.
