import sys
import types
from collections.abc import Iterator
from pathlib import Path

import pytest
from django.contrib.staticfiles.views import serve as staticfiles_serve
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import path, re_path
from django.views.decorators.cache import never_cache
from django.views.static import serve
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard

URLCONF = "tests._static_gate_urls"


def _tree(root: Path) -> Path:
    for name in (
        "hls/live/segment_001.ts",
        "static/js/app.4f3a.js.map",
        "static/app.py",
        "static/dump.sql",
        "static/app.php",
        "static/real.ts",
        "collected/js/served.ts",
        "secret.ts",
    ):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    (root / "static" / "folder.ts").mkdir()
    return root


def _page(request: object, **kwargs: str) -> HttpResponse:
    return HttpResponse("page")


@pytest.fixture
def urlconf(tmp_path: Path) -> Iterator[Path]:
    root = _tree(tmp_path)
    module = types.ModuleType(URLCONF)
    module.__dict__["urlpatterns"] = [
        re_path(r"^hls/(?P<path>.*)$", serve, {"document_root": root / "hls"}),
        re_path(
            r"^static/(?P<path>.*)$",
            never_cache(serve),
            {"document_root": str(root / "static")},
        ),
        re_path(r"^collected/(?P<path>.*)$", staticfiles_serve),
        re_path(r"^open/(?P<path>.*)$", serve),
        re_path(r"^other/(?P<path>.*)$", _page),
        path("page/<path:name>", _page),
    ]
    sys.modules[URLCONF] = module
    try:
        yield root
    finally:
        del sys.modules[URLCONF]


def _middleware() -> DjangoAPIGuard:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        ban_on_hostile_signals=False,
        exclude_paths=[],
    )
    with override_settings(GUARD_SECURITY_CONFIG=config):
        return DjangoAPIGuard(lambda request: HttpResponse("OK"))


@pytest.mark.parametrize(
    ("request_path", "status"),
    [
        ("/hls/live/segment_001.ts", 200),
        ("/static/js/app.4f3a.js.map", 200),
        ("/static/real.ts", 200),
        ("/static/real.ts;jsessionid=1", 400),
        ("/hls/live/missing.ts", 400),
        ("/static/js/missing.js.map", 400),
        ("/static/folder.ts", 400),
        ("/static/app.py", 400),
        ("/static/dump.sql", 400),
        ("/static/app.php", 400),
        ("/static/../secret.ts", 400),
        ("/hls/../secret.ts", 400),
        ("/open/live/segment_001.ts", 400),
        ("/page/segment_001.ts", 400),
        ("/nowhere/live/segment_001.ts", 400),
    ],
)
def test_a_ts_or_map_file_is_clean_only_when_the_static_mount_has_it(
    urlconf: Path, request_path: str, status: int
) -> None:
    with override_settings(ROOT_URLCONF=URLCONF):
        middleware = _middleware()
        assert middleware(RequestFactory().get(request_path)).status_code == status


def test_the_lookup_is_traversal_safe_and_never_cached(urlconf: Path) -> None:
    late = urlconf / "static" / "late.ts"
    with override_settings(
        ROOT_URLCONF=URLCONF,
        STATICFILES_DIRS=[str(urlconf / "collected")],
        STATICFILES_FINDERS=["django.contrib.staticfiles.finders.FileSystemFinder"],
    ):
        middleware = _middleware()

        assert middleware.static_file_exists("/static/real.ts") is True
        assert middleware.static_file_exists("/static/../secret.ts") is False
        assert middleware.static_file_exists("/static//etc/passwd.ts") is False
        assert middleware.static_file_exists("/static/late.ts") is False
        late.write_text("x")
        assert middleware.static_file_exists("/static/late.ts") is True
        late.unlink()
        assert middleware.static_file_exists("/static/late.ts") is False
        assert middleware.static_file_exists("/collected/js/served.ts") is True
        assert middleware.static_file_exists("/collected/js/missing.ts") is False
        assert middleware.static_file_exists("/collected/../secret.ts") is False
        assert middleware.static_file_exists("/open/js/served.ts") is False
        assert middleware.static_file_exists("/other/js/served.ts") is False
        assert middleware.static_file_exists("/page/served.ts") is False
        assert middleware.static_file_exists("/nowhere/served.ts") is False


STATIC_MOUNT_CORPUS = (
    "hls/live/segment_000.ts",
    "hls/live/segment_001.ts",
    "hls/vod/720p/chunk-00042.ts",
    "hls/vod/1080p/chunk-00001.ts",
    "hls/audio/seg-12.ts",
    "assets/index-4f3a9c1e.js.map",
    "assets/vendor-b82d.js.map",
    "assets/main.css.map",
    "_next/static/chunks/app/page-9d8c.js.map",
    "_next/static/chunks/webpack-1a2b.js.map",
    "static/js/main.4f3a.chunk.js.map",
    "static/css/main.8e1.chunk.css.map",
    "dist/bundle.min.js.map",
    "build/static/js/2.abc123.chunk.js.map",
    "js/jquery.min.map",
    "assets/ts/sample.ts",
    "examples/demo.ts",
)


@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
def test_the_static_mount_benign_corpus_is_clean_when_the_files_exist(
    urlconf: Path, name: str
) -> None:
    target = urlconf / "hls" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x")
    with override_settings(ROOT_URLCONF=URLCONF):
        middleware = _middleware()
        assert middleware(RequestFactory().get(f"/hls/{name}")).status_code == 200


@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
def test_the_static_mount_benign_corpus_is_flagged_without_a_static_mount(
    urlconf: Path, name: str
) -> None:
    with override_settings(ROOT_URLCONF=URLCONF):
        middleware = _middleware()
        assert middleware(RequestFactory().get(f"/page/{name}")).status_code == 400
