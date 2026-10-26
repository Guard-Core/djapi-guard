from django.http import HttpRequest, JsonResponse
from django.urls import path
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import SecurityDecorator

security = SecurityDecorator(
    SecurityConfig[SyncGuardRequest](enable_redis=False, fail_on_misconfiguration=False)
)


@security.block_countries(["CN"])
def geo_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"route": "ok"})


urlpatterns = [path("geo/", geo_view)]
