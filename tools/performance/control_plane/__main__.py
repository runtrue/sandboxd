"""Run the signed control-plane benchmark and emit one JSON document."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

from .measure import concurrent, sequential
from .protocol import build_ping_request, round_trip


def bounded_integer(minimum: int, maximum: int):
    def parse(value: str) -> int:
        parsed = int(value)
        if parsed < minimum or parsed > maximum:
            raise argparse.ArgumentTypeError(
                f"must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--key", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--binary-size", required=True, type=int)
    parser.add_argument("--warmup", default=250, type=bounded_integer(0, 2_000))
    parser.add_argument("--sequential", default=250, type=bounded_integer(50, 2_000))
    parser.add_argument("--samples", default=12_000, type=bounded_integer(100, 20_000))
    parser.add_argument("--concurrency", default=16, type=bounded_integer(1, 64))
    return parser.parse_args()


def requests(key: bytes, run_id: str, start: int, count: int) -> list[bytes]:
    return [build_ping_request(key, run_id, index) for index in range(start, start + count)]


def main() -> None:
    options = arguments()
    try:
        key = bytes.fromhex(options.key)
    except ValueError as error:
        raise SystemExit("--key must be hexadecimal") from error
    if len(key) != 32:
        raise SystemExit("--key must contain exactly 32 bytes")

    run_id = f"{os.getpid()}-{time.time_ns()}"
    offset = 0
    for payload in requests(key, run_id, offset, options.warmup):
        round_trip(options.socket, payload)
    offset += options.warmup

    sequential_result = sequential(
        options.socket, requests(key, run_id, offset, options.sequential)
    )
    offset += options.sequential
    concurrent_result = concurrent(
        options.socket,
        requests(key, run_id, offset, options.samples),
        options.concurrency,
    )

    result = {
        "schema_version": 1,
        "revision": options.revision,
        "binary_size_bytes": options.binary_size,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
        },
        "configuration": {
            "warmup_requests": options.warmup,
            "sequential_requests": options.sequential,
            "concurrent_requests": options.samples,
            "concurrency": options.concurrency,
        },
        "sequential": sequential_result,
        "concurrent": concurrent_result,
    }
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
