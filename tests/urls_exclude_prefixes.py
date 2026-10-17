from django.conf.urls.i18n import i18n_patterns
from django.http import HttpRequest, HttpResponse
from django.urls import include, path, re_path


def view(request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
    return HttpResponse("ok")


admin_patterns = [path("panel/", view)]

urlpatterns = [
    re_path(r"^health$", view),
    path("items/<int:item_id>/", view),
    path("admin/", include(admin_patterns)),
    *i18n_patterns(path("account/", view)),
]
