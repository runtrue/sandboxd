"""Protocol-v2 request construction and Unix-socket transport."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import time
from pathlib import Path


RESOURCE_CEILINGS = {
    "maximum_services": 4,
    "maximum_timeout_ms": 10_000,
    "memory_bytes_per_service": 268_435_456,
    "cpu_per_service_millis": 1_000,
    "pids_per_service": 64,
    "tmpfs_bytes": 67_108_864,
    "writable_root_bytes_per_service": 67_108_864,
    "maximum_volumes": 8,
    "maximum_volume_bytes": 536_870_912,
    "maximum_output_bytes": 1_048_576,
}


def compact_json(value: object) -> bytes:
    """Encode with the compact representation used by the Rust signer."""

    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def build_ping_request(key: bytes, run_id: str, index: int) -> bytes:
    """Build one uniquely signed workload ping request."""

    request_id = f"perf-{run_id}-{index}"
    operation = {"kind": "ping"}
    now_millis = time.time_ns() // 1_000_000
    claims = {
        "schema_version": 3,
        "tenant_id": "performance",
        "workspace_id": "control-plane",
        "subject_id": "github-runner",
        "request_id": request_id,
        "operation": "ping",
        "sandbox_id": None,
        "assignment_epoch": 1,
        "issued_unix_millis": now_millis,
        "expires_unix_millis": now_millis + 240_000,
        "nonce": f"nonce-{run_id}-{index}",
        "operation_digest": f"sha256:{hashlib.sha256(compact_json(operation)).hexdigest()}",
        "resource_ceilings": RESOURCE_CEILINGS,
    }
    signature = hmac.new(key, compact_json(claims), hashlib.sha256).hexdigest()
    request = {
        "schema_version": 2,
        "request_id": request_id,
        "authorization": {
            "kind": "work_order",
            "work_order": {"claims": claims, "signature": signature},
        },
        "operation": operation,
    }
    return compact_json(request) + b"\n"


def round_trip(socket_path: Path, payload: bytes) -> None:
    """Send one request on a fresh connection and validate its response."""

    expected_request_id = json.loads(payload)["request_id"]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(socket_path))
        connection.sendall(payload)
        response = bytearray()
        while not response.endswith(b"\n"):
            chunk = connection.recv(64 * 1024)
            if not chunk:
                raise RuntimeError("daemon closed an unterminated response")
            response.extend(chunk)
            if len(response) > 4 * 1024 * 1024:
                raise RuntimeError("daemon response exceeds the protocol limit")
    decoded = json.loads(response)
    if not decoded.get("ok") or decoded.get("request_id") != expected_request_id:
        raise RuntimeError(f"daemon rejected performance request: {decoded}")
