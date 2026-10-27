import asyncio
import inspect

from django.http import HttpRequest, HttpResponse
from django.test import override_settings
from guard_agent import SyncGuardAgentHandler
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from djangoapi_guard import DjangoAPIGuard


def get_response(request: HttpRequest) -> HttpResponse:
    return HttpResponse("OK")


async def _build_middleware() -> DjangoAPIGuard:
    return DjangoAPIGuard(get_response)


def test_a_middleware_built_inside_a_running_loop_holds_the_sync_agent_handler() -> (
    None
):
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False, enable_agent=True, agent_api_key="sk-test-0123456789"
    )

    with override_settings(GUARD_SECURITY_CONFIG=config):
        middleware = asyncio.run(_build_middleware())

    assert isinstance(middleware.agent_handler, SyncGuardAgentHandler)
    assert not inspect.iscoroutinefunction(middleware.agent_handler.start)
    assert not inspect.iscoroutinefunction(middleware.agent_handler.stop)
