import json

from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from advanced_app.models import message_response
from advanced_app.security import guard
from djangoapi_guard.adapters import DjangoGuardResponse


@require_GET
@guard.block_user_agents(["bot", "crawler", "spider", "scraper"])
def block_bots(request: HttpRequest) -> JsonResponse:
    return JsonResponse(message_response("Human users only - bots blocked"))


@csrf_exempt
@require_POST
@guard.content_type_filter(["application/json"])
def json_content_only(request: HttpRequest) -> JsonResponse:
    data = {}
    if request.body:
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            data = {}
    return JsonResponse(
        message_response(
            "JSON content received",
            details={"data": data},
        )
    )


@csrf_exempt
@require_POST
@guard.max_request_size(1024 * 100)
def limited_upload_size(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        message_response(
            "Data received within size limit",
            details={"size_limit": "100KB"},
        )
    )


@require_GET
@guard.require_referrer(["https://example.com", "https://app.example.com"])
def check_referrer(request: HttpRequest) -> JsonResponse:
    referrer = request.headers.get("referer", "No referrer")
    return JsonResponse(
        message_response(
            "Valid referrer",
            details={"referrer": referrer},
        )
    )


def custom_validator(req: SyncGuardRequest) -> GuardResponse | None:
    user_agent = req.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return DjangoGuardResponse(
            JsonResponse(
                {"detail": "Suspicious user agent"},
                status=403,
            )
        )
    return None


@require_GET
@guard.custom_validation(custom_validator)
def custom_content_validation(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        message_response(
            "Custom validation passed",
            details={"validator": "custom_validator"},
        )
    )


urlpatterns = [
    path("no-bots", block_bots),
    path("json-only", json_content_only),
    path("size-limit", limited_upload_size),
    path("referrer-check", check_referrer),
    path("custom-validation", custom_content_validation),
]
