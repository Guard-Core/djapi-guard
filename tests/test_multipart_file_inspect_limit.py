from collections.abc import Iterator

import pytest
from django.test import Client, override_settings
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

BODY_LIMIT = 262144
DEFAULT_FILE_LIMIT = SecurityConfig().detection_max_file_inspect_bytes
PAST_THE_LIMIT_PADDING = BODY_LIMIT + 1024
RAISED_FILE_LIMIT = 1_000_000
BOUNDARY = "wp251boundary"
_PAYLOAD = "1' UNION SELECT password FROM users--"
_FORWARDED = {"X-Forwarded-For": "203.0.113.50"}
_MULTIPART_TYPE = f"multipart/form-data; boundary={BOUNDARY}"


def _multipart_body() -> bytes:
    pad = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="pad"\r\n\r\n'
        f"{'A' * PAST_THE_LIMIT_PADDING}\r\n"
    )
    comment = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="comment"\r\n\r\n'
        f"{_PAYLOAD}\r\n--{BOUNDARY}--\r\n"
    )
    return (pad + comment).encode()


def _json_body() -> bytes:
    pad = "A" * PAST_THE_LIMIT_PADDING
    return ('{"pad": "' + pad + '", "comment": "' + _PAYLOAD + '"}').encode()


def _config(file_limit: int) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_agent=False,
        enable_penetration_detection=True,
        trusted_proxies=("127.0.0.1",),
        detection_max_file_inspect_bytes=file_limit,
    )


def _serve(file_limit: int) -> Iterator[Client]:
    with override_settings(
        ROOT_URLCONF="tests.urls_body_past_inspect_cap",
        GUARD_SECURITY_CONFIG=_config(file_limit),
        GUARD_DECORATOR="tests.urls_body_past_inspect_cap.guard_deco",
        DATA_UPLOAD_MAX_MEMORY_SIZE=None,
    ):
        yield Client()


@pytest.fixture
def served_raised() -> Iterator[Client]:
    yield from _serve(RAISED_FILE_LIMIT)


@pytest.fixture
def served_default() -> Iterator[Client]:
    yield from _serve(DEFAULT_FILE_LIMIT)


def _post(client: Client, body: bytes, content_type: str) -> tuple[int, bytes]:
    response = client.post(
        "/small", data=body, content_type=content_type, headers=_FORWARDED
    )
    return response.status_code, response.content


def test_multipart_past_the_body_limit_is_scanned_under_a_raised_file_limit(
    served_raised: Client,
) -> None:
    status, content = _post(served_raised, _multipart_body(), _MULTIPART_TYPE)

    assert status == 400
    assert b"Suspicious activity detected" in content


def test_a_multipart_body_past_the_default_file_limit_is_refused_not_passed(
    served_default: Client,
) -> None:
    status, content = _post(served_default, _multipart_body(), _MULTIPART_TYPE)

    assert status == 400
    assert b"Suspicious activity detected" not in content


def test_a_json_body_of_the_same_size_stays_refused_under_a_raised_file_limit(
    served_raised: Client,
) -> None:
    status, content = _post(served_raised, _json_body(), "application/json")

    assert status == 400
    assert b"Suspicious activity detected" not in content
