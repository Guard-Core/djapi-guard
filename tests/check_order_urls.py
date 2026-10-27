from django.http import HttpRequest, JsonResponse
from django.urls import path
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityDecorator

BANNED_IP = "10.0.0.99"

config = SecurityConfig[SyncGuardRequest](
    blacklist=(BANNED_IP,),
    trusted_proxies=("127.0.0.1",),
    enable_redis=False,
    enable_agent=False,
    enable_penetration_detection=False,
    enable_cors=True,
    cors_allow_origins=["https://app.example.com"],
    auth_verifier=lambda request, credential: {"user": "ok"} if credential else None,
)
security = SecurityDecorator(config)


@security.require_headers({"X-Client-ID": "required"})
def needs_header(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": "yes"})


@security.rate_limit(requests=1, window=60)
@security.require_auth()
def limited_and_authed(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": "yes"})


urlpatterns = [
    path("needs-header/", needs_header),
    path("limited-and-authed/", limited_and_authed),
]
