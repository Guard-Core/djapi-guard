from collections.abc import Callable

from django.http import HttpRequest, HttpResponse


class UrlconfByHost:
    """What django-hosts and similar do: choose the urlconf of this request."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.get_host().split(":")[0] == "admin.example.com":
            request.urlconf = "tests.request_urlconf_admin_urls"
        return self.get_response(request)
