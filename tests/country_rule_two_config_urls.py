from django.http import HttpRequest, JsonResponse
from django.urls import path

from djangoapi_guard import SecurityConfig, SecurityDecorator

guard_deco = SecurityDecorator(SecurityConfig(enable_redis=False))


@guard_deco.block_countries(["CN"])
def blocked_endpoint(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"data": "blocked"})


urlpatterns = [path("blocked", blocked_endpoint)]
