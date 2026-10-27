import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django
import pytest

django.setup()


def test_all_exports_importable() -> None:
    import djangoapi_guard

    for name in djangoapi_guard.__all__:
        assert hasattr(djangoapi_guard, name), f"{name} not found"


def test_middleware_importable() -> None:
    from djangoapi_guard.middleware import DjangoAPIGuard

    assert DjangoAPIGuard is not None


def test_adapters_importable() -> None:
    from djangoapi_guard.adapters import (
        DjangoGuardRequest,
        DjangoGuardResponse,
        DjangoResponseFactory,
    )

    assert DjangoGuardRequest is not None
    assert DjangoGuardResponse is not None
    assert DjangoResponseFactory is not None


def test_version_exported_matches_package_metadata() -> None:
    from importlib.metadata import version

    from djangoapi_guard import __version__

    assert __version__ == version("djapi-guard")
    assert __version__ != "0.0.0+unknown"


def test_version_falls_back_when_package_metadata_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib
    from importlib.metadata import PackageNotFoundError

    import djangoapi_guard

    def _raise(name: str) -> str:
        raise PackageNotFoundError(name)

    monkeypatch.setattr("importlib.metadata.version", _raise)
    reloaded = importlib.reload(djangoapi_guard)
    try:
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        importlib.reload(djangoapi_guard)


def test_endpoint_rate_limit_key_problems_is_the_engines_function() -> None:
    import guard_core.sync

    import djangoapi_guard

    assert "endpoint_rate_limit_key_problems" in djangoapi_guard.__all__
    assert (
        djangoapi_guard.endpoint_rate_limit_key_problems
        is guard_core.sync.endpoint_rate_limit_key_problems
    )
