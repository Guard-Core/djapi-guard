from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import include, path, re_path

from djangoapi_guard import SecurityConfig, SecurityDecorator

guard_security_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
assert isinstance(guard_security_config, SecurityConfig)
guard_deco = SecurityDecorator(guard_security_config)


def item(request: HttpRequest, pk: int, **kwargs: str) -> JsonResponse:
    return JsonResponse({"pk": pk})


def old(request: HttpRequest, year: str, **kwargs: str) -> JsonResponse:
    return JsonResponse({"year": year})


@guard_deco.detection_exclusion(path_params={"name"})
def excluded(request: HttpRequest, name: str, **kwargs: str) -> JsonResponse:
    return JsonResponse({"name": name})


def guarded(request: HttpRequest, name: str, **kwargs: str) -> JsonResponse:
    return JsonResponse({"name": name})


leaf = [
    path("items/<int:pk>/", item),
    re_path(r"^old/(?P<year>[0-9]{4})/$", old),
    path("excluded/<str:name>/", excluded),
    path("guarded/<str:name>/", guarded),
]
middle = [path("teams/<slug:team>/", include(leaf))]

urlpatterns = [path("orgs/<int:org>/", include(middle))]
