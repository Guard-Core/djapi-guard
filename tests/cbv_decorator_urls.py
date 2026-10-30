from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.utils.decorators import method_decorator
from django.views import View

from djangoapi_guard import SecurityConfig, SecurityDecorator

guard_security_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
assert isinstance(guard_security_config, SecurityConfig)
guard_deco = SecurityDecorator(guard_security_config)
need = guard_deco.require_headers({"X-Need": "required"})


class OnAsView(View):
    def get(self, request: HttpRequest) -> JsonResponse:
        return JsonResponse({"v": "as_view"})


class OnMethod(View):
    @method_decorator(need)
    def get(self, request: HttpRequest) -> JsonResponse:
        return JsonResponse({"v": "method"})

    def post(self, request: HttpRequest) -> JsonResponse:
        return JsonResponse({"v": "post"})


@method_decorator(need, name="dispatch")
class OnDispatch(View):
    def get(self, request: HttpRequest) -> JsonResponse:
        return JsonResponse({"v": "dispatch"})


@need
class OnClass(View):
    def get(self, request: HttpRequest) -> JsonResponse:
        return JsonResponse({"v": "class"})


class Both(View):
    @method_decorator(need)
    def get(self, request: HttpRequest) -> JsonResponse:
        return JsonResponse({"v": "both"})


def plain(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"v": "function"})


urlpatterns = [
    path("function/", need(plain)),
    path("as-view/", need(OnAsView.as_view())),
    path("method/", OnMethod.as_view()),
    path("dispatch/", OnDispatch.as_view()),
    path("class/", OnClass.as_view()),
    path("both/", need(Both.as_view())),
]
