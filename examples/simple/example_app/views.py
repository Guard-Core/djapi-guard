import json
import logging
import time
from datetime import datetime, timezone
from ipaddress import ip_address

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from example_project.settings import GUARD_SECURITY_CONFIG
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.handlers.cloud_handler import cloud_handler_for
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import (
    BehaviorRule,
    SecurityConfig,
    SecurityDecorator,
)
from djangoapi_guard.adapters import DjangoGuardResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

config: SecurityConfig[SyncGuardRequest] = GUARD_SECURITY_CONFIG
DYNAMIC_RULES_OWN_EMERGENCY_MODE = (
    "this app takes emergency mode from the dashboard's dynamic rules; a local "
    "switch would be reverted at the next rule update"
)
guard = SecurityDecorator(config)


def root(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "DjangoAPI Guard Example Application",
            "details": {
                "version": "1.0.0",
                "endpoints": {
                    "/basic": "Basic features",
                    "/access": "Access control",
                    "/auth": "Authentication",
                    "/rate": "Rate limiting",
                    "/behavior": "Behavioral analysis",
                    "/headers": "Security headers",
                    "/content": "Content filtering",
                    "/advanced": "Advanced features",
                    "/admin": "Administration",
                    "/test": "Security testing",
                },
            },
        }
    )


@require_GET
def health(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@require_GET
def basic_root(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "Basic features endpoint"})


@require_GET
def basic_ip(request: HttpRequest) -> JsonResponse:
    client_ip = request.META.get("REMOTE_ADDR", "unknown")
    try:
        ip_obj = ip_address(client_ip)
        ip_info = {
            "ip": str(ip_obj),
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
        }
    except ValueError:
        ip_info = {"ip": client_ip, "error": "Invalid IP"}
    return JsonResponse(
        {
            "message": "Client IP information",
            "details": ip_info,
        }
    )


@require_GET
def basic_health(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@csrf_exempt
@require_POST
def basic_echo(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "Echo response",
            "details": {
                "received_data": data,
                "headers": dict(request.headers),
                "method": request.method,
                "url": request.build_absolute_uri(),
            },
        }
    )


@require_GET
@guard.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
def access_ip_whitelist(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "IP whitelist access granted",
            "details": {
                "allowed_ranges": [
                    "127.0.0.1",
                    "10.0.0.0/8",
                ]
            },
        }
    )


@require_GET
@guard.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
def access_ip_blacklist(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "IP blacklist check passed",
            "details": {
                "blocked_ranges": [
                    "192.168.1.0/24",
                    "172.16.0.0/12",
                ]
            },
        }
    )


@require_GET
@guard.block_countries(["CN", "RU", "KP"])
def access_country_block(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Country block check passed",
            "details": {"blocked_countries": ["CN", "RU", "KP"]},
        }
    )


@require_GET
@guard.allow_countries(["US", "CA", "GB", "AU"])
def access_country_allow(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Country allow check passed",
            "details": {"allowed_countries": ["US", "CA", "GB", "AU"]},
        }
    )


@require_GET
@guard.block_clouds()
def access_no_cloud(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Cloud provider check passed",
            "details": {"all_cloud_providers_blocked": True},
        }
    )


@require_GET
@guard.block_clouds(["AWS"])
def access_no_aws(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "AWS cloud check passed",
            "details": {"blocked_providers": ["AWS"]},
        }
    )


@require_GET
@guard.bypass(["rate_limit", "ip"])
def access_bypass_demo(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Security bypass demo",
            "details": {
                "bypassed_checks": [
                    "rate_limit",
                    "ip",
                ]
            },
        }
    )


@require_GET
@guard.require_https()
def auth_https_only(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "HTTPS verification passed",
            "details": {"protocol": "https"},
        }
    )


@require_GET
@guard.require_auth(type="bearer")
def auth_bearer(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Bearer authentication verified",
            "details": {"auth_type": "bearer"},
        }
    )


@require_GET
@guard.api_key_auth(header_name="X-API-Key")
def auth_api_key(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "API key authentication verified",
            "details": {"auth_type": "api_key"},
        }
    )


@require_GET
@guard.require_headers(
    {
        "X-Custom-Header": "required-value",
        "X-Client-ID": "required-value",
    }
)
def auth_custom_headers(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Custom headers verified",
            "details": {
                "required_headers": [
                    "X-Custom-Header",
                    "X-Client-ID",
                ]
            },
        }
    )


@require_GET
@guard.rate_limit(requests=5, window=60)
def rate_custom_limit(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Custom rate limit endpoint",
            "details": {
                "limit": 5,
                "window": "60 seconds",
            },
        }
    )


@require_GET
@guard.rate_limit(requests=1, window=10)
def rate_strict_limit(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Strict rate limit endpoint",
            "details": {
                "limit": 1,
                "window": "10 seconds",
            },
        }
    )


@require_GET
@guard.geo_rate_limit(
    {
        "US": (100, 60),
        "CN": (10, 60),
        "RU": (20, 60),
        "*": (50, 60),
    }
)
def rate_geo_limit(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Geo-based rate limit endpoint",
            "details": {
                "rates": {
                    "US": "100/60s",
                    "CN": "10/60s",
                    "RU": "20/60s",
                    "default": "50/60s",
                }
            },
        }
    )


@require_GET
@guard.usage_monitor(max_calls=10, window=300, action="log")
def behavior_usage_monitor(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Usage monitored endpoint",
            "details": {
                "max_calls": 10,
                "window": "300 seconds",
                "action": "log",
            },
        }
    )


@require_GET
@guard.return_monitor(
    pattern="404",
    max_occurrences=3,
    window=60,
    action="ban",
)
def behavior_return_monitor(request: HttpRequest, status_code: int) -> JsonResponse:
    if status_code == 404:
        return JsonResponse({"detail": "Not found"}, status=404)
    return JsonResponse(
        {
            "message": "Return monitor endpoint",
            "details": {
                "status_code": status_code,
                "monitored_pattern": "404",
            },
        }
    )


@require_GET
@guard.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
def behavior_suspicious_frequency(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Suspicious frequency endpoint",
            "details": {
                "max_frequency": 0.5,
                "window": "10 seconds",
                "action": "throttle",
            },
        }
    )


@csrf_exempt
@require_POST
@guard.behavior_analysis(
    [
        BehaviorRule(
            rule_type="frequency",
            threshold=10,
            window=60,
            action="throttle",
        ),
        BehaviorRule(
            rule_type="return_pattern",
            pattern="404",
            threshold=5,
            window=60,
            action="ban",
        ),
    ]
)
def behavior_rules(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "Behavior analysis endpoint",
            "details": {
                "received_data": data,
                "rules": [
                    {
                        "type": "frequency",
                        "threshold": 10,
                        "action": "throttle",
                    },
                    {
                        "type": "return_pattern",
                        "pattern": "404",
                        "action": "ban",
                    },
                ],
            },
        }
    )


@require_GET
def headers_root(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Security headers information",
            "details": {
                "headers": [
                    "Content-Security-Policy",
                    "Strict-Transport-Security",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                    "Permissions-Policy",
                ],
                "description": (
                    "Security headers are automatically applied to all responses"
                ),
            },
        }
    )


@require_GET
def headers_test_page(request: HttpRequest) -> HttpResponse:
    html = """<!DOCTYPE html>
<html>
<head>
    <title>DjangoAPI Guard Security Headers Demo</title>
    <style>
        body { font-family: Arial, sans-serif;
               max-width: 800px; margin: 0 auto;
               padding: 20px; }
        .header-info { background: #f0f0f0;
                       padding: 10px; margin: 5px 0;
                       border-radius: 5px; }
    </style>
</head>
<body>
    <h1>DjangoAPI Guard Security Headers Demo</h1>
    <p>Check browser DevTools to see security headers.</p>
    <div id="headers"></div>
    <script>
        document.getElementById('headers').textContent =
            'Headers loaded via CSP-compliant script.';
    </script>
</body>
</html>"""
    return HttpResponse(html, content_type="text/html")


@csrf_exempt
@require_POST
def headers_csp_report(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    logger.warning(f"CSP Violation Report: {data}")
    return JsonResponse(
        {
            "message": "CSP violation report received",
            "details": data,
        }
    )


@require_GET
def headers_frame_test(request: HttpRequest) -> HttpResponse:
    html = """<!DOCTYPE html>
<html>
<head><title>Frame Test</title></head>
<body>
    <h1>Frame Test Page</h1>
    <p>This page tests X-Frame-Options header.</p>
    <iframe src="/headers/" width="100%"
            height="300"></iframe>
</body>
</html>"""
    return HttpResponse(html, content_type="text/html")


@require_GET
def headers_hsts_info(request: HttpRequest) -> JsonResponse:
    hsts = (config.security_headers or {}).get("hsts")
    hsts_config = hsts if isinstance(hsts, dict) else {}
    return JsonResponse(
        {
            "message": "HSTS configuration",
            "details": {
                "max_age": hsts_config.get("max_age", 31536000),
                "include_subdomains": hsts_config.get("include_subdomains", True),
                "preload": hsts_config.get("preload", False),
            },
        }
    )


@require_GET
def headers_security_analysis(request: HttpRequest) -> JsonResponse:
    req_headers = dict(request.headers)
    analysis = {
        "has_authorization": "Authorization" in req_headers,
        "has_user_agent": "User-Agent" in req_headers,
        "has_accept": "Accept" in req_headers,
        "has_content_type": "Content-Type" in req_headers,
        "has_origin": "Origin" in req_headers,
        "has_referer": "Referer" in req_headers,
        "total_headers": len(req_headers),
    }
    return JsonResponse(
        {
            "message": "Request header analysis",
            "details": {
                "analysis": analysis,
                "headers_received": req_headers,
            },
        }
    )


@require_GET
@guard.block_user_agents(["bot", "crawler", "spider", "scraper"])
def content_no_bots(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Bot-free zone",
            "details": {
                "blocked_agents": [
                    "bot",
                    "crawler",
                    "spider",
                    "scraper",
                ]
            },
        }
    )


@csrf_exempt
@require_POST
@guard.content_type_filter(["application/json"])
def content_json_only(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "JSON content accepted",
            "details": {"received_data": data},
        }
    )


@csrf_exempt
@require_POST
@guard.max_request_size(1024 * 100)
def content_size_limit(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "Request within size limit",
            "details": {
                "max_size": "100KB",
                "received_data": data,
            },
        }
    )


@require_GET
@guard.require_referrer(["https://example.com", "https://app.example.com"])
def content_referrer_check(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Referrer check passed",
            "details": {
                "allowed_referrers": [
                    "https://example.com",
                    "https://app.example.com",
                ]
            },
        }
    )


def _custom_validator(req: SyncGuardRequest) -> GuardResponse | None:
    user_agent = req.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return DjangoGuardResponse(
            JsonResponse({"detail": "Suspicious user agent detected"}, status=403)
        )
    return None


@require_GET
@guard.custom_validation(_custom_validator)
def content_custom_validation(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Custom validation passed",
            "details": {"validator": "user_agent_check"},
        }
    )


@require_GET
@guard.time_window(
    start_time="09:00",
    end_time="17:00",
    timezone="UTC",
)
def advanced_business_hours(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Business hours access granted",
            "details": {
                "window": "09:00-17:00 UTC",
                "current_time": datetime.now(timezone.utc).strftime("%H:%M UTC"),
            },
        }
    )


@require_GET
@guard.time_window(
    start_time="00:00",
    end_time="23:59",
    timezone="UTC",
)
def advanced_weekend_only(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Weekend access granted",
            "details": {
                "window": "00:00-23:59 UTC",
                "current_time": datetime.now(timezone.utc).strftime("%H:%M UTC"),
            },
        }
    )


@csrf_exempt
@require_POST
@guard.honeypot_detection(["honeypot_field", "trap_input", "hidden_field"])
def advanced_honeypot(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "Honeypot check passed",
            "details": {
                "received_data": data,
                "honeypot_fields": [
                    "honeypot_field",
                    "trap_input",
                    "hidden_field",
                ],
            },
        }
    )


@require_GET
@guard.suspicious_detection(enabled=True)
def advanced_suspicious_patterns(request: HttpRequest) -> JsonResponse:
    query = request.GET.get("q", "")
    return JsonResponse(
        {
            "message": "Suspicious pattern check passed",
            "details": {"query": query},
        }
    )


@csrf_exempt
@require_POST
@guard.require_ip(whitelist=["127.0.0.1"])
def admin_unban_ip(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    try:
        ip_to_unban = str(ip_address(str(data.get("ip", "")).strip()))
    except (ValueError, AttributeError):
        return JsonResponse({"detail": "Not an IP address"}, status=400)
    # `ip_ban_manager` is the default app's; this app's own manager:
    ip_ban_manager_for(config).unban_ip(ip_to_unban)
    return JsonResponse(
        {
            "message": f"IP {ip_to_unban} has been unbanned",
            "details": {"action": "unban", "ip": ip_to_unban},
        }
    )


@require_GET
@guard.require_ip(whitelist=["127.0.0.1"])
def admin_stats(request: HttpRequest) -> JsonResponse:
    """Reads this process's ban table (IPBanManager.banned_ips), its rate limit
    windows (RateLimitManager.request_timestamps) and the SecurityConfig rules.
    The engine keeps no request counters, so none are reported."""
    now = time.time()
    windows = RateLimitManager(config).request_timestamps
    banned_ips = sorted(
        ip
        for ip, expiry in ip_ban_manager_for(config).banned_ips.items()
        if expiry > now
    )
    rate_limit_windows = {key: len(window) for key, window in windows.items() if window}
    active_rules = {
        "rate_limit": config.rate_limit,
        "rate_limit_window": config.rate_limit_window,
        "auto_ban_threshold": config.auto_ban_threshold,
        "blocked_countries": list(config.blocked_countries),
        "block_cloud_providers": sorted(config.block_cloud_providers or ()),
    }
    return JsonResponse(
        {
            "message": "Security statistics",
            "details": {
                "banned_ips": banned_ips,
                "rate_limit_windows": rate_limit_windows,
                "active_rules": active_rules,
            },
        }
    )


@csrf_exempt
@require_POST
@guard.require_ip(whitelist=["127.0.0.1"])
def admin_clear_cache(request: HttpRequest) -> JsonResponse:
    """Clears all bans and rate limit windows for this app's Redis prefix."""
    ip_ban_manager_for(config).reset()
    RateLimitManager(config).reset()
    return JsonResponse(
        {
            "message": "Security caches cleared",
            "details": {
                "cleared": ["ip_bans", "rate_limit_windows"],
                "cleared_at": datetime.now(timezone.utc).isoformat(),
            },
        }
    )


@csrf_exempt
@require_http_methods(["PUT"])
@guard.require_ip(whitelist=["127.0.0.1"])
def admin_emergency_mode(request: HttpRequest) -> JsonResponse:
    """Switches emergency mode on this process through SecurityConfig.

    Emergency mode has two sources: SecurityConfig.emergency_mode set at startup,
    or a dynamic rule from the dashboard at runtime. This is the local switch: it
    changes this process only, so a multi-worker deployment uses the dashboard's
    dynamic rule. While emergency mode is on only emergency_whitelist is admitted,
    so enabling adds 127.0.0.1 to keep this admin route reachable.
    """
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    enable = data.get("enable") if isinstance(data, dict) else None
    if not isinstance(enable, bool):
        return JsonResponse(
            {"detail": 'The body must be {"enable": true|false}'}, status=400
        )
    if config.enable_dynamic_rules:
        return JsonResponse({"detail": DYNAMIC_RULES_OWN_EMERGENCY_MODE}, status=409)
    if enable and "127.0.0.1" not in config.emergency_whitelist:
        config.emergency_whitelist = [*config.emergency_whitelist, "127.0.0.1"]
    config.emergency_mode = enable
    state = "enabled" if config.emergency_mode else "disabled"
    return JsonResponse(
        {
            "message": f"Emergency mode {state}",
            "details": {
                "emergency_mode": config.emergency_mode,
                "emergency_whitelist": list(config.emergency_whitelist),
            },
        }
    )


@require_GET
@guard.require_ip(whitelist=["127.0.0.1"])
def admin_cloud_status(request: HttpRequest) -> JsonResponse:
    last_updated = {}
    # `cloud_handler` is the default app's; this app's own manager:
    for provider, dt in cloud_handler_for(config).last_updated.items():
        last_updated[provider] = dt.isoformat() if dt else None
    return JsonResponse(
        {
            "message": "Cloud provider IP range status",
            "details": {
                "refresh_interval": config.cloud_ip_refresh_interval,
                "providers": last_updated,
            },
        }
    )


@csrf_exempt
@require_POST
def test_xss(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "XSS test endpoint",
            "details": {"received_data": data},
        }
    )


@require_GET
def test_sql_injection(request: HttpRequest) -> JsonResponse:
    query = request.GET.get("query", "")
    return JsonResponse(
        {
            "message": "SQL injection test endpoint",
            "details": {"query_received": query},
        }
    )


@require_GET
def test_path_traversal(request: HttpRequest, file_path: str) -> JsonResponse:
    return JsonResponse(
        {
            "message": "Path traversal test endpoint",
            "details": {"path_received": file_path},
        }
    )


@csrf_exempt
@require_POST
def test_command_injection(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "Command injection test endpoint",
            "details": {"received_data": data},
        }
    )


@csrf_exempt
@require_POST
def test_mixed_attack(request: HttpRequest) -> JsonResponse:
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse(
        {
            "message": "Mixed attack test endpoint",
            "details": {
                "received_fields": list(data.keys()),
                "field_count": len(data),
            },
        }
    )
