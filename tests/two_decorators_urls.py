from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import path

from djangoapi_guard import SecurityDecorator

guard_deco = SecurityDecorator(settings.GUARD_SECURITY_CONFIG)
other_deco = SecurityDecorator(settings.GUARD_SECURITY_CONFIG)


@guard_deco.rate_limit(requests=1, window=60)
def limited_endpoint(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"data": "limited"})


urlpatterns = [path("limited", limited_endpoint)]
