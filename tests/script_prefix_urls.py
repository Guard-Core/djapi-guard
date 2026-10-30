from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.urls import path

from djangoapi_guard import SecurityConfig, SecurityDecorator

guard_security_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
assert isinstance(guard_security_config, SecurityConfig)
guard_deco = SecurityDecorator(guard_security_config)


@guard_deco.require_ip(whitelist=["10.9.9.9"])
def admin_only(request: HttpRequest) -> HttpResponse:
    return HttpResponse("SECRET")


urlpatterns = [path("admin-only/", admin_only)]
