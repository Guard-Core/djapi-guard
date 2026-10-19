from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import path, re_path


def echo(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"received": len(request.body)})


def page(request: HttpRequest, **kwargs: str) -> HttpResponse:
    return HttpResponse("page")


urlpatterns = [
    path("echo", echo),
    path("shop/cart.php", page),
    re_path(r"^forum/viewtopic\.php$", page),
    path("files/<path:name>", page),
]
