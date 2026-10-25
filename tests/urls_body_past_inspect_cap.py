from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import path

from djangoapi_guard import SecurityConfig, SecurityDecorator

LARGE_LIMIT = 7000

guard_security_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
assert isinstance(guard_security_config, SecurityConfig)
guard_deco = SecurityDecorator(guard_security_config)


def small(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": "small"})


@guard_deco.max_request_size(LARGE_LIMIT)
def large(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": "large"})


urlpatterns = [path("small", small), path("large", large)]
