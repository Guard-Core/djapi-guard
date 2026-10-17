from django.http import HttpRequest, JsonResponse
from django.urls import path
from guard_core.models import SecurityConfig

from djangoapi_guard import SecurityDecorator

security = SecurityDecorator(SecurityConfig(enable_redis=False))


@security.api_key_auth()
def api_key_default(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "API key required (default header)"})


@security.api_key_auth(header_name="Authorization")
def api_key_custom(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "API key required (custom header)"})


urlpatterns = [
    path("api-key-default/", api_key_default),
    path("api-key-custom/", api_key_custom),
]
