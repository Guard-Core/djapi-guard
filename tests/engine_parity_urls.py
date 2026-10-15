from django.http import HttpRequest, JsonResponse
from django.urls import path
from guard_core.models import SecurityConfig

from djangoapi_guard import SecurityDecorator

security = SecurityDecorator(
    SecurityConfig(enable_redis=False, behavior_scan_response_body=True)
)


def health(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "ok"})


def open_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "Echo response"})


@security.bypass(["all"])
def bypassed(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "real view"})


urlpatterns = [
    path("health/", health),
    path("open/", open_view),
    path("bypassed/", bypassed),
]
