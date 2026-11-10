import ipaddress
import sys
import time
from unittest.mock import MagicMock

import pytest
from django.test import Client, override_settings
from django.urls import clear_url_caches
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

AWS_RANGE = ipaddress.ip_network("198.51.100.0/24")
CLIENT_IP = "198.51.100.77"
URLCONF = "tests.route_only_block_clouds_urls"


def test_a_route_only_block_clouds_loads_its_ranges_and_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetch_aws = MagicMock(return_value=({AWS_RANGE}, {}))
    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler._fetch_provider_ranges", fetch_aws
    )
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )
    sys.modules.pop(URLCONF, None)
    clear_url_caches()
    try:
        with override_settings(ROOT_URLCONF=URLCONF, GUARD_SECURITY_CONFIG=config):
            client = Client()
            client.get("/r", REMOTE_ADDR=CLIENT_IP)
            time.sleep(0.5)
            response = client.get("/r", REMOTE_ADDR=CLIENT_IP)
    finally:
        sys.modules.pop(URLCONF, None)
        clear_url_caches()

    fetch_aws.assert_called_with("AWS")
    assert response.status_code == 403
