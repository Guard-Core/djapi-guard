"""Fresh-process probe: djapi-guard under a per-request urlconf.

One process per case: decorator adoption keeps a module-level weakref list and Django
caches urlconf modules, so a second case in the same process would not start cold.
Usage: request_urlconf_probe.py <workdir> <json spec>; the last stdout line is
`RESULT <json>`.
"""

import importlib
import json
import logging
import sys
import warnings
from pathlib import Path

import django
from django.conf import settings
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

WORK = Path(sys.argv[1])
SPEC = json.loads(sys.argv[2])

ROOT_PLAIN = """
from django.http import JsonResponse
from django.urls import path

def hello(request):
    return JsonResponse({"ok": 1})

urlpatterns = [path("hello/", hello)]
"""
ROOT_DECORATED = """
from django.conf import settings
from django.http import JsonResponse
from django.urls import path
from djangoapi_guard import SecurityDecorator

guard_deco = SecurityDecorator(settings.GUARD_SECURITY_CONFIG)

@guard_deco.require_headers({"X-Root": "required"})
def hello(request):
    return JsonResponse({"ok": 1})

urlpatterns = [path("hello/", hello)]
"""
ROOT_SHARED = ROOT_DECORATED.replace(
    '@guard_deco.require_headers({"X-Root": "required"})\n', ""
)
ROOT_ADMIN_DECORATED = ROOT_DECORATED.replace("hello", "admin").replace(
    "X-Root", "X-Need"
)
HOST_PLAIN = """
from django.http import JsonResponse
from django.urls import path

def admin(request):
    return JsonResponse({"admin": "reached"})

urlpatterns = [path("admin/", admin)]
"""
HOST_DECORATED = """
from django.conf import settings
from django.http import JsonResponse
from django.urls import path
from djangoapi_guard import SecurityDecorator

guard_deco = SecurityDecorator(settings.GUARD_SECURITY_CONFIG)

@guard_deco.require_headers({"X-Need": "required"})
def admin(request):
    return JsonResponse({"admin": "reached"})

urlpatterns = [path("admin/", admin)]
"""
HOST_SHARED_DECORATOR = """
from django.http import JsonResponse
from django.urls import path
from wp_root import guard_deco

@guard_deco.require_headers({"X-Need": "required"})
def admin(request):
    return JsonResponse({"admin": "reached"})

urlpatterns = [path("admin/", admin)]
"""
HOST_BAD_DECLARATION = """
from django.http import JsonResponse
from django.urls import path
from wp_root import guard_deco

@guard_deco.detection_exclusion(path_params={"ghost"})
def item(request, item_id):
    return JsonResponse({"item": item_id})

urlpatterns = [path("item/<str:item_id>/", item)]
"""
OTHER_PLAIN = """
from django.http import JsonResponse
from django.urls import path

def other(request):
    return JsonResponse({"other": "reached"})

urlpatterns = [path("other/", other)]
"""
MIDDLEWARE_SOURCE = '''
from django.http import HttpResponse

from djangoapi_guard.middleware import DjangoAPIGuard

URLCONFS = {"admin.example.com": "wp_host", "other.example.com": "wp_other"}


class UrlconfByHost:
    """What django-hosts and similar do: choose the urlconf of this request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        urlconf = URLCONFS.get(request.get_host().split(":")[0])
        if urlconf is not None:
            request.urlconf = urlconf
        return self.get_response(request)


class GuardWithItsDecoratorSet(DjangoAPIGuard):
    def __init__(self, get_response):
        super().__init__(get_response)
        from wp_root import guard_deco

        self.set_decorator_handler(guard_deco)
'''
ROOTS = {
    "plain": ROOT_PLAIN,
    "decorated": ROOT_DECORATED,
    "shared": ROOT_SHARED,
    "admin_decorated": ROOT_ADMIN_DECORATED,
}
HOSTS = {
    "plain": HOST_PLAIN,
    "decorated": HOST_DECORATED,
    "shared_decorator": HOST_SHARED_DECORATOR,
    "bad_declaration": HOST_BAD_DECLARATION,
}

(WORK / "wp_mw.py").write_text(MIDDLEWARE_SOURCE)
(WORK / "wp_root.py").write_text(ROOTS[SPEC["root"]])
(WORK / "wp_host.py").write_text(HOSTS[SPEC["host"]])
(WORK / "wp_other.py").write_text(OTHER_PLAIN)
sys.path.insert(0, str(WORK))

records: list[list[str]] = []
_original_handle = logging.Logger.handle


def _recording_handle(self: logging.Logger, record: logging.LogRecord) -> None:
    records.append([record.name, record.levelname, record.getMessage()])
    _original_handle(self, record)


HANDLE = "handle"
setattr(logging.Logger, HANDLE, _recording_handle)

config = SecurityConfig[SyncGuardRequest](
    enable_redis=False,
    enable_agent=False,
    enable_penetration_detection=False,
    enable_rate_limiting=False,
    ban_on_hostile_signals=False,
    fail_on_misconfiguration=SPEC.get("fail", False),
    route_resolution_strict=SPEC.get("strict", False),
    blacklist=("203.0.113.9",),
    **({"exclude_paths": SPEC["excludes"]} if "excludes" in SPEC else {}),
)
extra: dict[str, object] = {}
if SPEC.get("explicit") == "setting":
    extra["GUARD_DECORATOR"] = "wp_root.guard_deco"
if "urlconfs" in SPEC:
    extra["GUARD_URLCONFS"] = SPEC["urlconfs"]
settings.configure(
    SECRET_KEY="x",
    ALLOWED_HOSTS=["*"],
    ROOT_URLCONF="wp_root",
    INSTALLED_APPS=["django.contrib.contenttypes", "djangoapi_guard"],
    DATABASES={},
    GUARD_SECURITY_CONFIG=config,
    MIDDLEWARE=[
        "wp_mw.UrlconfByHost",
        "wp_mw.GuardWithItsDecoratorSet"
        if SPEC.get("explicit") == "call"
        else "djangoapi_guard.middleware.DjangoAPIGuard",
    ],
    **extra,
)
django.setup()

run_checks = importlib.import_module("django.core.checks").run_checks
Client = importlib.import_module("django.test").Client

out: dict[str, object] = {
    "files": [
        importlib.import_module("guard_core").__file__,
        importlib.import_module("djangoapi_guard").__file__,
        importlib.import_module("django").__file__,
    ],
    "host_in_sys_modules_before": "wp_host" in sys.modules,
}
client = Client(raise_request_exception=True)


def status(host: str, path: str, headers: dict[str, str], addr: str) -> object:
    try:
        return client.get(path, HTTP_HOST=host, REMOTE_ADDR=addr, **headers).status_code
    except Exception as error:
        return f"{type(error).__name__}: {str(error)[:1200]}"


with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    if SPEC.get("run_checks"):
        out["check_messages"] = [f"{m.id}: {m.msg}" for m in run_checks()]
    statuses: list[object] = []
    for index, (host, path, headers, *rest) in enumerate(SPEC["requests"]):
        statuses.append(
            status(host, path, headers, rest[0] if rest else "198.51.100.7")
        )
        if index == 0:
            out["messages_after_first_request"] = [r[2] for r in records] + [
                str(w.message) for w in caught
            ]
    out["statuses"] = statuses
    out["host_in_sys_modules_after"] = "wp_host" in sys.modules
    out["messages"] = [r[2] for r in records] + [str(w.message) for w in caught]
print("RESULT " + json.dumps(out))
