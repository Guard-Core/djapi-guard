"""A per-request urlconf (django-hosts and similar) and the reads the middleware made
of ROOT_URLCONF alone: decorator adoption, the exclude_paths route check and the
path-param report.

Each case runs tests/request_urlconf_probe.py in a fresh process (decorator adoption
keeps a module-level weakref list and Django caches urlconf modules), and each
asserts that the host module was not imported before the middleware read it."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROBE = Path(__file__).with_name("request_urlconf_probe.py")
NO_ROUTE = "matches no registered route"
HINT = "GUARD_URLCONFS"
UNKNOWN_ROUTE = "does not know"
AMBIGUOUS = "SecurityDecorator instances are registered"
ROOT = "www.example.com"
HOST = "admin.example.com"
OTHER = "other.example.com"
BLACKLISTED = "203.0.113.9"


def _run(tmp_path: Path, **spec: Any) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, str(PROBE), str(tmp_path), json.dumps(spec)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=120,
        check=False,
    )
    lines = [x for x in done.stdout.splitlines() if x.startswith("RESULT ")]
    assert lines, done.stderr[-2000:]
    result: dict[str, Any] = json.loads(lines[-1][len("RESULT ") :])
    assert result["host_in_sys_modules_before"] is False, (
        "host module was imported before the first request"
    )
    return result


def _count(result: dict[str, Any], text: str) -> int:
    return sum(text in message for message in result["messages"])


def _refused(status: object) -> bool:
    return "ImproperlyConfigured" in str(status)


def test_a_decorator_made_only_in_the_host_urlconf_is_enforced(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="decorated",
        requests=[[HOST, "/admin/", {}], [HOST, "/admin/", {"HTTP_X_NEED": "1"}]],
    )
    assert result["statuses"] == [400, 200]


def test_it_stays_enforced_after_the_host_module_was_imported(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="decorated",
        requests=[
            [HOST, "/admin/", {"HTTP_X_NEED": "1"}],
            [HOST, "/admin/", {}],
            [HOST, "/admin/", {}],
        ],
    )
    assert result["host_in_sys_modules_after"] is True
    assert result["statuses"] == [200, 400, 400]


def test_after_the_adoption_the_root_and_the_host_checks_both_run(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="decorated",
        requests=[
            [ROOT, "/hello/", {}, BLACKLISTED],
            [HOST, "/admin/", {}],
            [ROOT, "/hello/", {}, BLACKLISTED],
            [ROOT, "/hello/", {}],
            [HOST, "/admin/", {"HTTP_X_NEED": "1"}],
        ],
    )
    assert result["statuses"] == [403, 400, 403, 200, 200]


def test_a_decorator_in_the_root_urlconf_is_enforced_for_its_route(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="admin_decorated",
        host="plain",
        requests=[[ROOT, "/admin/", {}], [ROOT, "/admin/", {"HTTP_X_NEED": "1"}]],
    )
    assert result["statuses"] == [400, 200]


def test_two_decorators_with_none_named_refuse_the_request_of_the_second(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        fail=True,
        requests=[
            [ROOT, "/hello/", {}],
            [ROOT, "/hello/", {"HTTP_X_ROOT": "1"}],
            [HOST, "/admin/", {}],
        ],
    )
    assert result["statuses"][:2] == [400, 200]
    assert _refused(result["statuses"][2])
    assert "settings.GUARD_DECORATOR" in result["statuses"][2]
    assert "share one decorator instance" in result["statuses"][2]


def test_once_ambiguous_every_request_is_refused_the_root_ones_too(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        fail=True,
        requests=[
            [HOST, "/admin/", {}],
            [ROOT, "/hello/", {"HTTP_X_ROOT": "1"}],
            [HOST, "/admin/", {"HTTP_X_NEED": "1"}],
        ],
    )
    assert all(_refused(status) for status in result["statuses"])


def test_two_decorators_without_the_flag_log_once_and_keep_the_first(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        fail=False,
        requests=[
            [HOST, "/admin/", {}],
            [HOST, "/admin/", {}],
            [ROOT, "/hello/", {}],
        ],
    )
    assert result["statuses"] == [200, 200, 400]
    assert _count(result, AMBIGUOUS) == 1


def test_the_old_knob_and_the_new_refusal_agree_under_strict_resolution(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        fail=True,
        strict=True,
        requests=[[HOST, "/admin/", {}], [HOST, "/admin/", {"HTTP_X_NEED": "1"}]],
    )
    assert all(_refused(status) for status in result["statuses"])


def test_the_old_knob_alone_still_answers_500_for_the_unknown_route(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        fail=False,
        strict=True,
        requests=[[HOST, "/admin/", {}]],
    )
    assert result["statuses"] == [500]


def test_a_decorator_named_by_the_setting_is_never_refused(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        fail=True,
        explicit="setting",
        requests=[[HOST, "/admin/", {}], [ROOT, "/hello/", {}]],
    )
    assert result["statuses"] == [200, 400]
    assert _count(result, UNKNOWN_ROUTE) == 1
    assert _count(result, AMBIGUOUS) == 0


def test_a_decorator_set_by_the_call_is_never_refused(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        fail=True,
        explicit="call",
        requests=[[HOST, "/admin/", {}], [ROOT, "/hello/", {}]],
    )
    assert result["statuses"] == [200, 400]
    assert _count(result, UNKNOWN_ROUTE) == 1
    assert _count(result, AMBIGUOUS) == 0


def test_one_decorator_shared_by_both_urlconfs_is_enforced_on_both(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="shared_decorator",
        fail=True,
        requests=[
            [ROOT, "/hello/", {}],
            [HOST, "/admin/", {}],
            [HOST, "/admin/", {"HTTP_X_NEED": "1"}],
        ],
    )
    assert result["statuses"] == [400, 400, 200]


def test_a_listed_urlconf_is_read_at_startup_so_its_decorator_is_adopted(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="decorated",
        urlconfs=["wp_host"],
        requests=[[HOST, "/admin/", {}], [HOST, "/admin/", {"HTTP_X_NEED": "1"}]],
    )
    assert result["statuses"] == [400, 200]


def test_a_listed_urlconf_with_a_second_decorator_refuses_at_startup(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="decorated",
        host="decorated",
        urlconfs=["wp_host"],
        requests=[[ROOT, "/hello/", {}]],
    )
    assert _refused(result["statuses"][0])


def test_a_listed_urlconf_that_does_not_import_is_a_misconfiguration(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="plain",
        urlconfs=["no_such_urlconf_module"],
        requests=[[ROOT, "/hello/", {}]],
    )
    assert _refused(result["statuses"][0])
    assert "GUARD_URLCONFS" in result["statuses"][0]
    assert "no_such_urlconf_module" in result["statuses"][0]


def test_an_exclude_path_of_an_unlisted_urlconf_is_still_called_a_typo(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="plain",
        excludes=["/admin"],
        requests=[[HOST, "/admin/", {}]],
    )
    assert _count(result, NO_ROUTE) == 1


def test_an_exclude_path_of_a_listed_urlconf_is_not_called_a_typo(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="plain",
        excludes=["/admin"],
        urlconfs=["wp_host"],
        requests=[[HOST, "/admin/", {}]],
    )
    assert _count(result, NO_ROUTE) == 0
    assert _count(result, HINT) == 0


def test_an_exclude_path_of_the_root_urlconf_logs_nothing(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="plain",
        excludes=["/hello"],
        requests=[[HOST, "/admin/", {}]],
    )
    assert _count(result, NO_ROUTE) == 0


def test_an_unlisted_urlconf_is_named_once_when_exclude_paths_had_something_to_check(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="plain",
        excludes=["/admin", "/other"],
        requests=[
            [HOST, "/admin/", {}],
            [HOST, "/admin/", {}],
            [OTHER, "/other/", {}],
            [OTHER, "/other/", {}],
        ],
    )
    hints = [m for m in result["messages"] if HINT in m]
    assert len(hints) == 2
    assert "wp_host" in hints[0]
    assert "wp_other" in hints[1]
    assert "exclude_paths" in hints[0]


def test_an_unlisted_urlconf_with_a_path_params_declaration_is_named(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="shared",
        host="bad_declaration",
        explicit="setting",
        requests=[[HOST, "/item/1/", {}], [HOST, "/item/2/", {}]],
    )
    hints = [m for m in result["messages"] if HINT in m]
    assert len(hints) == 1
    assert "wp_host" in hints[0]
    assert "path_params" in hints[0]


def test_an_unlisted_urlconf_with_nothing_to_check_gets_no_hint(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="plain",
        host="plain",
        requests=[[HOST, "/admin/", {}], [OTHER, "/other/", {}]],
    )
    assert _count(result, HINT) == 0


def test_the_startup_report_and_the_system_check_name_a_bad_listed_declaration(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="shared",
        host="bad_declaration",
        explicit="setting",
        urlconfs=["wp_host"],
        run_checks=True,
        requests=[[ROOT, "/hello/", {}]],
    )
    startup = result["messages_after_first_request"]
    assert any("ghost" in message for message in startup)
    assert any("ghost" in message for message in result["check_messages"])


def test_without_the_setting_the_first_host_request_still_names_the_declaration(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        root="shared",
        host="bad_declaration",
        explicit="setting",
        run_checks=True,
        requests=[[ROOT, "/hello/", {}], [HOST, "/item/1/", {}]],
    )
    assert not any("ghost" in message for message in result["check_messages"])
    assert not any(
        "ghost" in message for message in result["messages_after_first_request"]
    )
    assert any("ghost" in message for message in result["messages"])
