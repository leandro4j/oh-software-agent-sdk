"""Tests for the Agent Box MVP runtime-contract driver."""

import json

import pytest

from scripts.agent_box_mvp_acceptance import (
    CheckCollector,
    image_name_for_project,
    parse_sandbox_runtime,
    serialize_result,
)


def test_parse_sandbox_runtime_extracts_agent_server_credentials() -> None:
    payload = {
        "id": "sandbox-123",
        "sandbox_spec_id": "agent-box/agent-box-mvp-run-1-software-agent-sdk:local",
        "status": "RUNNING",
        "session_api_key": "runtime-secret",
        "exposed_urls": [
            {"name": "VSCODE", "url": "http://127.0.0.1:32768", "port": 8001},
            {"name": "AGENT_SERVER", "url": "http://127.0.0.1:32767", "port": 8000},
        ],
    }

    runtime = parse_sandbox_runtime(payload)

    assert runtime is not None
    assert runtime.sandbox_id == "sandbox-123"
    assert runtime.base_url == "http://127.0.0.1:32767"
    assert runtime.session_api_key == "runtime-secret"
    assert parse_sandbox_runtime(payload, "wrong-local-image") is None
    assert (
        parse_sandbox_runtime(
            payload, "agent-box/agent-box-mvp-run-1-software-agent-sdk:local"
        )
        is not None
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"id": "sandbox-123", "status": "STARTING"},
        {
            "id": "sandbox-123",
            "status": "RUNNING",
            "session_api_key": "runtime-secret",
            "exposed_urls": [],
        },
        {
            "id": "sandbox-123",
            "status": "RUNNING",
            "session_api_key": "runtime-secret",
            "exposed_urls": [
                {"name": "AGENT_SERVER", "url": "not-a-url", "port": 8000}
            ],
        },
    ],
)
def test_parse_sandbox_runtime_rejects_incomplete_payload(payload: object) -> None:
    assert parse_sandbox_runtime(payload) is None


def test_image_name_is_local_and_project_scoped() -> None:
    assert image_name_for_project("agent-box-mvp-run-1") == (
        "agent-box/agent-box-mvp-run-1-software-agent-sdk:local"
    )


def test_image_name_rejects_untrusted_project_names() -> None:
    with pytest.raises(ValueError):
        image_name_for_project("agent-box-mvp/run-1")


def test_result_serialization_is_machine_readable() -> None:
    result = serialize_result(
        passed=True,
        assertions=[
            {
                "name": "runtime-http-auth",
                "status": "passed",
                "durationMs": 12,
                "resourceIds": ["sha256:abc123"],
            }
        ],
    )

    assert result["kind"] == "passed"
    assert result["assertions"] == [
        {
            "name": "runtime-http-auth",
            "status": "passed",
            "durationMs": 12,
            "resourceIds": ["sha256:abc123"],
        }
    ]


async def test_failed_check_does_not_serialize_exception_text() -> None:
    checks = CheckCollector()

    async def fail() -> None:
        raise RuntimeError("runtime-secret")

    await checks.run("runtime-http-auth", fail)
    result = serialize_result(passed=False, assertions=checks.assertions)

    assert "runtime-secret" not in json.dumps(result)
    assert result["kind"] == "failed"
