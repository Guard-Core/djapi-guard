import json
import logging
from datetime import datetime, timezone

from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from guard_core.sync.handlers.cloud_handler import cloud_handler_for

from advanced_app.models import message_response, stats_response
from advanced_app.security import guard

logger = logging.getLogger(__name__)


@csrf_exempt
@require_POST
@guard.require_ip(whitelist=["127.0.0.1"])
def unban_ip_address(request: HttpRequest) -> JsonResponse:
    data = {}
    if request.body:
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            data = {}
    ip = data.get("ip", "")
    logger.info("Unbanning IP: %s", ip)
    return JsonResponse(
        message_response(
            f"IP {ip} has been unbanned",
            details={"action": "unban", "ip": ip},
        )
    )


@require_GET
@guard.require_ip(whitelist=["127.0.0.1"])
def get_security_stats(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        stats_response(
            total_requests=1500,
            blocked_requests=75,
            banned_ips=["192.168.1.100", "10.0.0.50"],
            rate_limited_ips={
                "192.168.1.200": 5,
                "172.16.0.10": 3,
            },
            suspicious_activities=[
                {
                    "ip": "192.168.1.100",
                    "reason": "SQL injection attempt",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "ip": "10.0.0.50",
                    "reason": "Rapid requests",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            ],
            active_rules={
                "rate_limit": 30,
                "rate_window": 60,
                "auto_ban_threshold": 5,
                "blocked_countries": ["XX"],
                "blocked_clouds": ["AWS", "GCP", "Azure"],
            },
        )
    )


@csrf_exempt
@require_POST
@guard.require_ip(whitelist=["127.0.0.1"])
def clear_security_cache(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        message_response(
            "Security caches cleared",
            details={
                "cleared": [
                    "rate_limit_cache",
                    "ip_ban_cache",
                    "geo_cache",
                ],
            },
        )
    )


@csrf_exempt
@require_http_methods(["PUT"])
@guard.require_ip(whitelist=["127.0.0.1"])
def toggle_emergency_mode(request: HttpRequest) -> JsonResponse:
    data = {}
    if request.body:
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            data = {}
    enable = data.get("enable", False)
    mode = "enabled" if enable else "disabled"
    return JsonResponse(
        message_response(
            f"Emergency mode {mode}",
            details={
                "emergency_mode": enable,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    )


@require_GET
@guard.require_ip(whitelist=["127.0.0.1"])
def cloud_status(request: HttpRequest) -> JsonResponse:
    from advanced_app.security import security_config

    last_updated = {}
    # `cloud_handler` is the default app's; this app's own manager:
    for provider, dt in cloud_handler_for(security_config).last_updated.items():
        last_updated[provider] = dt.isoformat() if dt else None
    return JsonResponse(
        message_response(
            "Cloud provider IP range status",
            details={
                "refresh_interval": security_config.cloud_ip_refresh_interval,
                "providers": last_updated,
            },
        )
    )


urlpatterns = [
    path("unban-ip", unban_ip_address),
    path("stats", get_security_stats),
    path("clear-cache", clear_security_cache),
    path("emergency-mode", toggle_emergency_mode),
    path("cloud-status", cloud_status),
]
