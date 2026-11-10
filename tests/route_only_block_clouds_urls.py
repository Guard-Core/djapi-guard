from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import path

from djangoapi_guard import SecurityConfig, SecurityDecorator

guard_security_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
assert isinstance(guard_security_config, SecurityConfig)
guard_deco = SecurityDecorator(guard_security_config)


@guard_deco.block_clouds(["AWS"])
def route(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": "yes"})


urlpatterns = [path("r", route)]
