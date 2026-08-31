#!/usr/bin/env python3
"""Verify the frozen full Agent Server image through its runtime APIs.

The driver is intentionally opt-in. It talks to a running Sandbox Server when
``AGENT_BOX_MVP_SANDBOX_SERVER_URL`` is set, creates one disposable sandbox, and
then exercises the session-key, conversation, terminal, file, Git, and
WebSocket contracts. When the product run also provides its local SDK image,
the driver starts a second disposable container to verify the VS Code base
path on the full image itself. The Sandbox Server owns cleanup of its sandbox;
the verifier removes its own direct verification container.

Only sanitized JSON is written to stdout because the product integration runner
parses stdout as its acceptance result. Runtime and control-plane keys remain
process-local and are never included in results or error messages.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import websockets
from websockets.exceptions import ConnectionClosed


FROZEN_SDK_SHA = "704cbe6015e3d59cabe04632175d99df2d448999"
WORKSPACE_PATH = "/workspace/project"
CONTRACT_MESSAGE = "agent-box-mvp-contract-message"
VSCODE_BASE_PATH = "/agent-box-contract-vscode"
DEFAULT_SANDBOX_TIMEOUT_SECONDS = 90.0
DEFAULT_RUNTIME_TIMEOUT_SECONDS = 45.0
_PROJECT_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{12,64}$")
_CONTAINER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class RuntimeTarget:
    """A runtime URL and its session key obtained from a trusted setup path."""

    base_url: str
    session_api_key: str
    sandbox_id: str | None = None


@dataclass(frozen=True)
class DirectImage:
    """A locally started full-image container and its mapped ports."""

    container_id: str
    runtime: RuntimeTarget
    vscode_port: int


def _is_http_url(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlsplit(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _base_url(value: object) -> str | None:
    if not _is_http_url(value):
        return None
    assert isinstance(value, str)
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        return None
    return value.rstrip("/")


def parse_sandbox_runtime(
    payload: object, expected_sandbox_spec_id: str | None = None
) -> RuntimeTarget | None:
    """Extract a running Agent Server target from Sandbox Server JSON."""
    if not isinstance(payload, dict):
        return None
    if payload.get("status") != "RUNNING":
        return None

    sandbox_id = payload.get("id")
    sandbox_spec_id = payload.get("sandbox_spec_id")
    session_api_key = payload.get("session_api_key")
    exposed_urls = payload.get("exposed_urls")
    if not isinstance(sandbox_id, str) or not sandbox_id:
        return None
    if (
        expected_sandbox_spec_id is not None
        and sandbox_spec_id != expected_sandbox_spec_id
    ):
        return None
    if not isinstance(session_api_key, str) or not session_api_key:
        return None
    if not isinstance(exposed_urls, list):
        return None

    for exposed_url in exposed_urls:
        if not isinstance(exposed_url, dict):
            continue
        if exposed_url.get("name") != "AGENT_SERVER":
            continue
        base_url = _base_url(exposed_url.get("url"))
        if base_url is not None:
            return RuntimeTarget(base_url, session_api_key, sandbox_id)
    return None


def image_name_for_project(project_name: str) -> str:
    """Return the product runner's local SDK image tag."""
    if not _PROJECT_NAME_PATTERN.fullmatch(project_name):
        raise ValueError("invalid product project name")
    return f"agent-box/{project_name}-software-agent-sdk:local"


def serialize_result(
    *, passed: bool, assertions: Sequence[dict[str, object]]
) -> dict[str, object]:
    """Build the product runner's sanitized machine-readable result."""
    result: dict[str, object] = {
        "kind": "passed" if passed else "failed",
        "assertions": list(assertions),
    }
    if not passed:
        result["message"] = "Agent Server runtime contract failed."
    return result


class CheckCollector:
    """Run checks and retain only names, statuses, timings, and safe IDs."""

    def __init__(self) -> None:
        self.assertions: list[dict[str, object]] = []

    def add(
        self,
        name: str,
        status: str,
        duration_ms: int,
        resource_ids: Sequence[str] = (),
    ) -> None:
        assertion: dict[str, object] = {
            "name": name,
            "status": status,
            "durationMs": max(0, duration_ms),
        }
        if resource_ids:
            assertion["resourceIds"] = list(resource_ids)
        self.assertions.append(assertion)

    async def run(
        self,
        name: str,
        operation: Callable[[], Awaitable[Any]],
        resource_ids: Callable[[Any], Sequence[str]] | None = None,
    ) -> Any | None:
        started = time.monotonic()
        try:
            value = await operation()
        except Exception:
            self.add(name, "failed", _duration_ms(started))
            return None
        ids = resource_ids(value) if resource_ids is not None else ()
        self.add(name, "passed", _duration_ms(started), ids)
        return value


def _duration_ms(started: float) -> int:
    return int(max(0.0, time.monotonic() - started) * 1000)


def _control_headers(control_plane_key: str | None) -> dict[str, str]:
    if control_plane_key:
        return {"X-Session-API-Key": control_plane_key}
    return {}


def _runtime_headers(runtime: RuntimeTarget) -> dict[str, str]:
    return {"X-Session-API-Key": runtime.session_api_key}


def _positive_float(value: str | None, default: float) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


async def _delete_sandbox(
    client: httpx.AsyncClient,
    sandbox_server_url: str,
    sandbox_id: str,
    control_plane_key: str | None,
) -> bool:
    try:
        response = await client.delete(
            f"{sandbox_server_url.rstrip('/')}/api/v1/sandboxes/{sandbox_id}",
            headers=_control_headers(control_plane_key),
            timeout=30.0,
        )
        return response.status_code in {200, 202, 204, 404}
    except Exception:
        return False


async def _provision_sandbox(
    client: httpx.AsyncClient,
    sandbox_server_url: str,
    control_plane_key: str | None,
    expected_sandbox_spec_id: str,
) -> RuntimeTarget:
    headers = _control_headers(control_plane_key)
    sandbox_id: str | None = None
    try:
        response = await client.post(
            f"{sandbox_server_url.rstrip('/')}/api/v1/sandboxes",
            headers=headers,
            params={"sandbox_spec_id": expected_sandbox_spec_id},
            timeout=15.0,
        )
        if response.status_code not in {200, 201}:
            raise RuntimeError("sandbox creation failed")
        created = response.json()
        if not isinstance(created, dict):
            raise RuntimeError("sandbox creation returned an invalid payload")
        raw_id = created.get("id")
        if not isinstance(raw_id, str) or not raw_id:
            raise RuntimeError("sandbox creation returned no id")
        sandbox_id = raw_id

        deadline = time.monotonic() + _positive_float(
            os.environ.get("AGENT_BOX_MVP_SANDBOX_TIMEOUT_SECONDS"),
            DEFAULT_SANDBOX_TIMEOUT_SECONDS,
        )
        while time.monotonic() < deadline:
            response = await client.get(
                f"{sandbox_server_url.rstrip('/')}/api/v1/sandboxes",
                params={"id": sandbox_id},
                headers=headers,
                timeout=15.0,
            )
            if response.status_code != 200:
                raise RuntimeError("sandbox status request failed")
            payload = response.json()
            if isinstance(payload, list) and payload:
                current = payload[0]
                if isinstance(current, dict) and current.get("status") == "ERROR":
                    raise RuntimeError("sandbox entered an error state")
                runtime = parse_sandbox_runtime(current, expected_sandbox_spec_id)
                if runtime is not None:
                    return runtime
            await asyncio.sleep(0.5)
        raise RuntimeError("sandbox did not become ready")
    except Exception:
        if sandbox_id is not None:
            await _delete_sandbox(
                client, sandbox_server_url, sandbox_id, control_plane_key
            )
            await asyncio.to_thread(_remove_container, sandbox_id)
        raise


async def _wait_for_runtime(client: httpx.AsyncClient, runtime: RuntimeTarget) -> None:
    deadline = time.monotonic() + _positive_float(
        os.environ.get("AGENT_BOX_MVP_RUNTIME_TIMEOUT_SECONDS"),
        DEFAULT_RUNTIME_TIMEOUT_SECONDS,
    )
    while time.monotonic() < deadline:
        try:
            alive = await client.get(f"{runtime.base_url}/alive", timeout=10.0)
            ready = await client.get(f"{runtime.base_url}/ready", timeout=10.0)
            if alive.status_code == 200 and ready.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.5)
    raise RuntimeError("Agent Server did not become ready")


async def _check_http_auth(
    client: httpx.AsyncClient, runtime: RuntimeTarget, expected_sha: str
) -> None:
    protected_url = f"{runtime.base_url}/api/conversations/search"
    missing = await client.get(protected_url, timeout=15.0)
    if missing.status_code != 401:
        raise RuntimeError("missing session key was accepted")

    invalid = await client.get(
        protected_url,
        headers={"X-Session-API-Key": "invalid-session-key"},
        timeout=15.0,
    )
    if invalid.status_code != 401:
        raise RuntimeError("invalid session key was accepted")

    valid = await client.get(
        protected_url, headers=_runtime_headers(runtime), timeout=15.0
    )
    if valid.status_code != 200:
        raise RuntimeError("valid session key was rejected")

    info = await client.get(f"{runtime.base_url}/server_info", timeout=15.0)
    if info.status_code != 200:
        raise RuntimeError("server metadata is unavailable")
    metadata = info.json()
    if not isinstance(metadata, dict) or metadata.get("build_git_sha") != expected_sha:
        raise RuntimeError("server metadata does not identify the frozen revision")


async def _create_conversation(
    client: httpx.AsyncClient, runtime: RuntimeTarget
) -> str:
    response = await client.post(
        f"{runtime.base_url}/api/conversations",
        headers=_runtime_headers(runtime),
        json={
            "agent": {
                "kind": "Agent",
                "llm": {
                    "usage_id": "agent-box-mvp-contract",
                    "model": "contract/no-network",
                    "api_key": None,
                },
                "tools": [],
            },
            "workspace": {"working_dir": WORKSPACE_PATH},
        },
        timeout=30.0,
    )
    if response.status_code not in {200, 201}:
        raise RuntimeError("conversation creation failed")
    payload = response.json()
    conversation_id = payload.get("id") if isinstance(payload, dict) else None
    if not isinstance(conversation_id, str) or not conversation_id:
        raise RuntimeError("conversation creation returned no id")
    return conversation_id


async def _check_chat_events(
    client: httpx.AsyncClient, runtime: RuntimeTarget, conversation_id: str
) -> None:
    response = await client.post(
        f"{runtime.base_url}/api/conversations/{conversation_id}/events",
        headers=_runtime_headers(runtime),
        json={
            "role": "user",
            "content": [{"type": "text", "text": CONTRACT_MESSAGE}],
            "run": False,
        },
        timeout=20.0,
    )
    if response.status_code != 200:
        raise RuntimeError("chat event submission failed")

    response = await client.get(
        f"{runtime.base_url}/api/conversations/{conversation_id}/events/search",
        headers=_runtime_headers(runtime),
        params={"body": CONTRACT_MESSAGE, "limit": 100},
        timeout=20.0,
    )
    if response.status_code != 200:
        raise RuntimeError("chat event search failed")
    payload = response.json()
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list) or not any(
        CONTRACT_MESSAGE in json.dumps(item) for item in items
    ):
        raise RuntimeError("submitted chat event was not readable")


async def _check_terminal(client: httpx.AsyncClient, runtime: RuntimeTarget) -> None:
    command = "\n".join(
        [
            "set -eu",
            f"mkdir -p {WORKSPACE_PATH}",
            f"git -C {WORKSPACE_PATH} init -q",
            f"git -C {WORKSPACE_PATH} config user.email "
            "agent-box-contract@example.invalid",
            f"git -C {WORKSPACE_PATH} config user.name agent-box-contract",
            f"printf 'before\\n' > {WORKSPACE_PATH}/agent-box-contract.txt",
            f"git -C {WORKSPACE_PATH} add agent-box-contract.txt",
            f"git -C {WORKSPACE_PATH} commit -qm baseline",
            f"printf 'after\\n' >> {WORKSPACE_PATH}/agent-box-contract.txt",
        ]
    )
    response = await client.post(
        f"{runtime.base_url}/api/bash/execute_bash_command",
        headers=_runtime_headers(runtime),
        json={"command": command, "cwd": "/", "timeout": 30},
        timeout=45.0,
    )
    if response.status_code != 200:
        raise RuntimeError("terminal request failed")
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("exit_code") != 0:
        raise RuntimeError("terminal command failed")


async def _check_files(client: httpx.AsyncClient, runtime: RuntimeTarget) -> None:
    path = f"{WORKSPACE_PATH}/agent-box-upload.txt"
    file_bytes = b"agent-box-file-contract\n"
    response = await client.post(
        f"{runtime.base_url}/api/file/upload",
        headers=_runtime_headers(runtime),
        params={"path": path},
        files={"file": ("agent-box-upload.txt", file_bytes, "text/plain")},
        timeout=20.0,
    )
    if response.status_code != 200:
        raise RuntimeError("file upload failed")

    response = await client.get(
        f"{runtime.base_url}/api/file/download",
        headers=_runtime_headers(runtime),
        params={"path": path},
        timeout=20.0,
    )
    if response.status_code != 200 or response.content != file_bytes:
        raise RuntimeError("file download did not round-trip")


async def _check_git(client: httpx.AsyncClient, runtime: RuntimeTarget) -> None:
    response = await client.get(
        f"{runtime.base_url}/api/git/changes",
        headers=_runtime_headers(runtime),
        params={"path": WORKSPACE_PATH, "ref": "HEAD"},
        timeout=20.0,
    )
    if response.status_code != 200:
        raise RuntimeError("Git changes request failed")
    changes = response.json()
    if not isinstance(changes, list) or not any(
        isinstance(change, dict)
        and change.get("path") in {"agent-box-contract.txt", "agent-box-upload.txt"}
        for change in changes
    ):
        raise RuntimeError("Git changes did not expose the runtime workspace")

    response = await client.get(
        f"{runtime.base_url}/api/git/diff",
        headers=_runtime_headers(runtime),
        params={
            "path": f"{WORKSPACE_PATH}/agent-box-contract.txt",
            "ref": "HEAD",
        },
        timeout=20.0,
    )
    if response.status_code != 200:
        raise RuntimeError("Git diff request failed")
    diff = response.json()
    if not isinstance(diff, dict) or "after" not in str(diff.get("modified")):
        raise RuntimeError("Git diff did not expose the modified file")

    response = await client.get(
        f"{runtime.base_url}/api/git/commits",
        headers=_runtime_headers(runtime),
        params={"path": WORKSPACE_PATH, "limit": 10},
        timeout=20.0,
    )
    if response.status_code != 200:
        raise RuntimeError("Git commits request failed")
    commits = response.json()
    if not isinstance(commits, dict) or not commits.get("commits"):
        raise RuntimeError("Git commits did not expose the baseline commit")


def _websocket_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}{path}"


async def _receive_websocket_contract(websocket: Any, marker: str) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
        payload = await asyncio.wait_for(websocket.recv(), timeout=remaining)
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="replace")
        if marker in payload:
            return
    raise RuntimeError("WebSocket event was not received")


async def _check_websocket(runtime: RuntimeTarget, conversation_id: str) -> None:
    invalid_url = _websocket_url(runtime.base_url, f"/sockets/events/{uuid4()}")
    try:
        async with websockets.connect(invalid_url, open_timeout=10) as websocket:
            await websocket.send(
                json.dumps({"type": "auth", "session_api_key": "invalid-session-key"})
            )
            await websocket.recv()
    except ConnectionClosed as error:
        close_code = error.rcvd.code if error.rcvd is not None else error.code
        if close_code != 4001:
            raise RuntimeError("invalid WebSocket key used the wrong close code")
    else:
        raise RuntimeError("invalid WebSocket key was accepted")

    valid_url = _websocket_url(
        runtime.base_url,
        f"/sockets/events/{conversation_id}?resend_all=true",
    )
    async with websockets.connect(
        valid_url,
        additional_headers=_runtime_headers(runtime),
        open_timeout=10,
    ) as websocket:
        await websocket.send(
            json.dumps(
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "websocket-header-contract"}],
                }
            )
        )
        await _receive_websocket_contract(websocket, "websocket-header-contract")

    async with websockets.connect(valid_url, open_timeout=10) as websocket:
        await websocket.send(
            json.dumps({"type": "auth", "session_api_key": runtime.session_api_key})
        )
        await websocket.send(
            json.dumps(
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "websocket-first-frame-contract"}
                    ],
                }
            )
        )
        await _receive_websocket_contract(websocket, "websocket-first-frame-contract")


def _run_docker(args: Sequence[str], *, check: bool = True) -> str:
    result = subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def _mapped_port(container_id: str, container_port: int) -> int:
    output = _run_docker(["port", container_id, f"{container_port}/tcp"])
    matches = re.findall(r":(\d+)\s*$", output, flags=re.MULTILINE)
    if not matches:
        raise RuntimeError("Docker did not map the expected port")
    return int(matches[-1])


def _remove_container(container_id: str) -> bool:
    if not (
        _CONTAINER_ID_PATTERN.fullmatch(container_id)
        or _CONTAINER_NAME_PATTERN.fullmatch(container_id)
    ):
        return False
    result = subprocess.run(
        ["docker", "rm", "--force", "--volumes", container_id],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode == 0


def _inspect_image(image_name: str) -> str:
    image_id = _run_docker(["image", "inspect", "--format", "{{.Id}}", image_name])
    if not _IMAGE_ID_PATTERN.fullmatch(image_id):
        raise RuntimeError("local image identity was not a content digest")
    return image_id


def _inspect_container_image(container_name: str) -> str:
    if not _CONTAINER_NAME_PATTERN.fullmatch(container_name):
        raise RuntimeError("Sandbox Server returned an invalid container identity")
    image_id = _run_docker(["inspect", "--format", "{{.Image}}", container_name])
    if not _IMAGE_ID_PATTERN.fullmatch(image_id):
        raise RuntimeError("Sandbox Server container has no content identity")
    return image_id


def _verify_container_image(container_name: str, expected_image_id: str) -> str:
    image_id = _inspect_container_image(container_name)
    if image_id != expected_image_id:
        raise RuntimeError("Sandbox Server used a different image identity")
    return image_id


def _start_direct_image(image_name: str) -> DirectImage:
    session_api_key = secrets.token_urlsafe(32)
    container_id = ""
    try:
        container_id = _run_docker(
            [
                "run",
                "--detach",
                "--rm",
                "--publish",
                "127.0.0.1::8000",
                "--publish",
                "127.0.0.1::8001",
                "--env",
                f"SESSION_API_KEY={session_api_key}",
                "--env",
                f"OH_SESSION_API_KEYS_0={session_api_key}",
                "--env",
                f"OH_VSCODE_BASE_PATH={VSCODE_BASE_PATH}",
                image_name,
            ]
        )
        if not _CONTAINER_ID_PATTERN.fullmatch(container_id):
            raise RuntimeError("Docker returned an invalid container identity")
        app_port = _mapped_port(container_id, 8000)
        vscode_port = _mapped_port(container_id, 8001)
        return DirectImage(
            container_id=container_id,
            runtime=RuntimeTarget(
                base_url=f"http://127.0.0.1:{app_port}",
                session_api_key=session_api_key,
            ),
            vscode_port=vscode_port,
        )
    except Exception:
        if container_id:
            _remove_container(container_id)
        raise


async def _check_vscode_base_path(
    client: httpx.AsyncClient,
    image: DirectImage,
    expected_sha: str,
) -> None:
    await _wait_for_runtime(client, image.runtime)
    headers = _runtime_headers(image.runtime)

    info = await client.get(f"{image.runtime.base_url}/server_info", timeout=15.0)
    if info.status_code != 200:
        raise RuntimeError("full image metadata is unavailable")
    metadata = info.json()
    if not isinstance(metadata, dict) or metadata.get("build_git_sha") != expected_sha:
        raise RuntimeError("full image metadata does not identify the frozen revision")

    status = await client.get(
        f"{image.runtime.base_url}/api/vscode/status",
        headers=headers,
        timeout=15.0,
    )
    status_payload = status.json() if status.status_code == 200 else None
    if (
        status.status_code != 200
        or not isinstance(status_payload, dict)
        or status_payload.get("enabled") is not True
        or status_payload.get("running") is not True
    ):
        raise RuntimeError("full image VS Code service is not running")

    response = await client.get(
        f"{image.runtime.base_url}/api/vscode/url",
        headers=headers,
        params={
            "base_url": f"http://127.0.0.1:{image.vscode_port}",
            "workspace_dir": WORKSPACE_PATH,
        },
        timeout=15.0,
    )
    if response.status_code != 200:
        raise RuntimeError("VS Code URL endpoint failed")
    payload = response.json()
    vscode_url = payload.get("url") if isinstance(payload, dict) else None
    if not isinstance(vscode_url, str) or not _is_http_url(vscode_url):
        raise RuntimeError("VS Code URL endpoint returned no URL")

    parsed = urlsplit(vscode_url)
    if parsed.path.rstrip("/") != VSCODE_BASE_PATH:
        raise RuntimeError("VS Code URL omitted the configured base path")
    query = parse_qs(parsed.query)
    if not query.get("tkn") or not query.get("folder"):
        raise RuntimeError("VS Code URL omitted its connection parameters")


async def _check_runtime_contract(
    client: httpx.AsyncClient,
    runtime: RuntimeTarget,
    expected_sha: str,
    checks: CheckCollector,
) -> None:
    await checks.run(
        "runtime-readiness",
        lambda: _wait_for_runtime(client, runtime),
    )
    await checks.run(
        "runtime-http-session-key-auth",
        lambda: _check_http_auth(client, runtime, expected_sha),
    )
    conversation_id = await checks.run(
        "runtime-conversation",
        lambda: _create_conversation(client, runtime),
    )
    if conversation_id is None:
        for name in (
            "runtime-chat-events",
            "runtime-terminal",
            "runtime-files",
            "runtime-git",
            "runtime-websocket",
        ):
            checks.add(name, "failed", 0)
        return

    try:
        await checks.run(
            "runtime-chat-events",
            lambda: _check_chat_events(client, runtime, conversation_id),
        )
        await checks.run(
            "runtime-terminal",
            lambda: _check_terminal(client, runtime),
        )
        await checks.run(
            "runtime-files",
            lambda: _check_files(client, runtime),
        )
        await checks.run(
            "runtime-git",
            lambda: _check_git(client, runtime),
        )
        await checks.run(
            "runtime-websocket",
            lambda: _check_websocket(runtime, conversation_id),
        )
    finally:
        try:
            await client.delete(
                f"{runtime.base_url}/api/conversations/{conversation_id}",
                headers=_runtime_headers(runtime),
                timeout=15.0,
            )
        except Exception:
            pass


async def _check_full_image_contract(
    client: httpx.AsyncClient,
    image_name: str,
    expected_sha: str,
    checks: CheckCollector,
) -> str | None:
    image_id = await checks.run(
        "full-image-identity",
        lambda: asyncio.to_thread(_inspect_image, image_name),
        resource_ids=lambda value: [value] if isinstance(value, str) else (),
    )
    if image_id is None:
        checks.add("full-image-vscode-base-path", "failed", 0)
        return None

    direct_image = await checks.run(
        "full-image-container",
        lambda: asyncio.to_thread(_start_direct_image, image_name),
        resource_ids=lambda image: [image.container_id]
        if isinstance(image, DirectImage)
        else (),
    )
    if direct_image is None:
        checks.add("full-image-vscode-base-path", "failed", 0)
        return image_id

    try:
        await checks.run(
            "full-image-vscode-base-path",
            lambda: _check_vscode_base_path(client, direct_image, expected_sha),
        )
    finally:
        cleanup_ok = await asyncio.to_thread(
            _remove_container, direct_image.container_id
        )
        if not cleanup_ok:
            checks.add("full-image-container-cleanup", "failed", 0)
    return image_id


async def _run_acceptance() -> dict[str, object]:
    sandbox_server_url = os.environ.get("AGENT_BOX_MVP_SANDBOX_SERVER_URL")
    project_name = os.environ.get("AGENT_BOX_MVP_PROJECT")
    if project_name is None:
        raise RuntimeError("product project name was not supplied")
    image_name = image_name_for_project(project_name)

    control_plane_key = os.environ.get("AGENT_BOX_CONTROL_PLANE_KEY") or None
    if sandbox_server_url is None:
        raise RuntimeError("Sandbox Server URL was not supplied")
    if _base_url(sandbox_server_url) is None:
        raise RuntimeError("Sandbox Server URL is invalid")

    checks = CheckCollector()
    async with httpx.AsyncClient(follow_redirects=False) as client:
        sandbox_runtime: RuntimeTarget | None = None
        sandbox_runtime = await checks.run(
            "sandbox-server-full-image-runtime",
            lambda: _provision_sandbox(
                client,
                sandbox_server_url.rstrip("/"),
                control_plane_key,
                image_name,
            ),
            resource_ids=lambda runtime: [runtime.sandbox_id]
            if isinstance(runtime, RuntimeTarget) and runtime.sandbox_id
            else (),
        )

        try:
            if sandbox_runtime is None:
                checks.add("runtime-readiness", "failed", 0)
            else:
                await _check_runtime_contract(
                    client, sandbox_runtime, FROZEN_SDK_SHA, checks
                )
                image_id = await _check_full_image_contract(
                    client, image_name, FROZEN_SDK_SHA, checks
                )
                if image_id is not None and isinstance(sandbox_runtime.sandbox_id, str):
                    sandbox_id_for_check: str = sandbox_runtime.sandbox_id
                    await checks.run(
                        "sandbox-server-image-identity",
                        lambda: asyncio.to_thread(
                            _verify_container_image,
                            sandbox_id_for_check,
                            image_id,
                        ),
                        resource_ids=lambda value: [value]
                        if isinstance(value, str)
                        else (),
                    )
        finally:
            if sandbox_runtime is not None and sandbox_runtime.sandbox_id:
                sandbox_id = sandbox_runtime.sandbox_id
                if sandbox_server_url:
                    server_cleanup_ok = await _delete_sandbox(
                        client,
                        sandbox_server_url.rstrip("/"),
                        sandbox_id,
                        control_plane_key,
                    )
                    container_cleanup_ok = await asyncio.to_thread(
                        _remove_container, sandbox_id
                    )
                    if not (server_cleanup_ok or container_cleanup_ok):
                        checks.add("sandbox-cleanup", "failed", 0)

    passed = bool(checks.assertions) and all(
        assertion.get("status") == "passed" for assertion in checks.assertions
    )
    return serialize_result(passed=passed, assertions=checks.assertions)


def main() -> int:
    try:
        result = asyncio.run(_run_acceptance())
    except KeyboardInterrupt:
        result = serialize_result(
            passed=False,
            assertions=[
                {"name": "agent-server-contract", "status": "failed", "durationMs": 0}
            ],
        )
    except Exception:
        result = serialize_result(
            passed=False,
            assertions=[
                {"name": "agent-server-contract", "status": "failed", "durationMs": 0}
            ],
        )
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result["kind"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
