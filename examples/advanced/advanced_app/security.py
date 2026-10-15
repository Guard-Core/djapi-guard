import logging
import os

from django.http import JsonResponse
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest as GuardRequest

from djangoapi_guard import SecurityConfig, SecurityDecorator
from djangoapi_guard.adapters import DjangoGuardResponse

logger = logging.getLogger(__name__)


def custom_request_check(request: GuardRequest) -> GuardResponse | None:
    if request.query_params.get("debug") == "true":
        return DjangoGuardResponse(
            JsonResponse({"detail": "Debug mode not allowed"}, status=403)
        )
    return None


def custom_response_modifier(response: GuardResponse) -> GuardResponse:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


security_config = SecurityConfig(
    whitelist=[],
    blacklist=["192.168.100.0/24"],
    trusted_proxies=["172.16.0.0/12", "10.0.0.0/8"],
    trusted_proxy_depth=1,
    trust_x_forwarded_proto=True,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    blocked_user_agents=["badbot", "evil-crawler", "sqlmap"],
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=300,
    enable_penetration_detection=True,
    enable_redis=True,
    redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
    redis_prefix=os.environ.get("REDIS_PREFIX", "djangoapi_guard:"),
    enforce_https=False,
    custom_request_check=custom_request_check,
    custom_response_modifier=custom_response_modifier,
    cloud_ip_refresh_interval=1800,
    log_format="json",
    security_headers={
        "enabled": True,
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'strict-dynamic'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": [
                "'self'",
                "https://fonts.gstatic.com",
            ],
            "connect-src": ["'self'"],
        },
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False,
        },
        "frame_options": "SAMEORIGIN",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        ),
        "custom": {
            "X-App-Name": "DjangoAPI-Guard-Advanced-Example",
            "X-Security-Contact": "security@example.com",
        },
    },
    enable_cors=True,
    cors_allow_origins=[
        "http://localhost:3000",
        "https://example.com",
    ],
    cors_allow_methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
    ],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Total-Count"],
    cors_max_age=3600,
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    custom_log_file="security.log",
    exclude_paths=[
        "/favicon.ico",
        "/static",
        "/health",
        "/ready",
    ],
    passive_mode=False,
)

guard = SecurityDecorator(security_config)
