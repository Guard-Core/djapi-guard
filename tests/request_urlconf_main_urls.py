from django.http import HttpRequest, JsonResponse
from django.urls import path


def hello(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": 1})


urlpatterns = [path("hello/", hello)]
