from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard.middleware import DjangoAPIGuard

BLOCKED_IP = "203.0.113.10"


def _config(**overrides: object) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        blacklist=(BLOCKED_IP,),
        enable_rate_limiting=False,
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        **overrides,  # type: ignore[arg-type]
    )


def _make_middleware(config: SecurityConfig[SyncGuardRequest]) -> DjangoAPIGuard:
    import django.conf

    django.conf.settings.GUARD_SECURITY_CONFIG = config

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("OK", status=200)

    return DjangoAPIGuard(get_response)


def _blocked_response_headers(
    config: SecurityConfig[SyncGuardRequest],
) -> tuple[int, str, str]:
    middleware = _make_middleware(config)
    factory = RequestFactory()
    request = factory.get("/ping")
    request.META["REMOTE_ADDR"] = BLOCKED_IP
    response = middleware(request)
    return (
        response.status_code,
        response.get("Content-Type", ""),
        response.get("X-Content-Type-Options", ""),
    )


def test_block_response_is_plain_text() -> None:
    assert _blocked_response_headers(_config()) == (
        403,
        "text/plain; charset=utf-8",
        "nosniff",
    )


def test_custom_error_message_is_plain_text() -> None:
    config = _config(custom_error_responses={403: "Access denied"})

    status_code, content_type, _nosniff = _blocked_response_headers(config)

    assert (status_code, content_type) == (403, "text/plain; charset=utf-8")


def test_response_modifier_can_still_set_its_own_content_type() -> None:
    def problem_json(response: GuardResponse) -> GuardResponse:
        response.headers["Content-Type"] = "application/problem+json"
        return response

    config = _config(custom_response_modifier=problem_json)

    status_code, content_type, _nosniff = _blocked_response_headers(config)

    assert (status_code, content_type) == (403, "application/problem+json")
