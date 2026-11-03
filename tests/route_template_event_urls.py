from django.http import HttpRequest, JsonResponse
from django.urls import path


def item(request: HttpRequest, item_id: int) -> JsonResponse:
    return JsonResponse({"id": item_id})


urlpatterns = [path("items/<int:item_id>", item)]
