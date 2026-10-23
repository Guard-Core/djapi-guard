from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import path

from djangoapi_guard import SecurityConfig, SecurityDecorator

guard_security_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
assert isinstance(guard_security_config, SecurityConfig)
guard_deco = SecurityDecorator(guard_security_config)
other_deco = SecurityDecorator(guard_security_config)


@guard_deco.rate_limit(requests=1, window=60)
def limited_endpoint(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"data": "limited"})


urlpatterns = [path("limited", limited_endpoint)]
