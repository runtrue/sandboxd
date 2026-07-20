"""Latency and throughput measurement primitives."""

from __future__ import annotations

import concurrent.futures as futures
import math
import time
from pathlib import Path
from typing import Iterable

from .protocol import round_trip


def summarize(latencies_ns: list[int], elapsed_ns: int) -> dict[str, float | int]:
    """Return deterministic nearest-rank latency statistics."""

    ordered = sorted(latencies_ns)
    return {
        "requests": len(ordered),
        "requests_per_second": len(ordered) / (elapsed_ns / 1_000_000_000),
        "mean_ms": sum(ordered) / len(ordered) / 1_000_000,
        "p50_ms": percentile(ordered, 50) / 1_000_000,
        "p95_ms": percentile(ordered, 95) / 1_000_000,
        "p99_ms": percentile(ordered, 99) / 1_000_000,
        "max_ms": ordered[-1] / 1_000_000,
    }


def percentile(ordered: list[int], percentage: int) -> int:
    rank = max(1, math.ceil(len(ordered) * percentage / 100))
    return ordered[rank - 1]


def sequential(socket_path: Path, payloads: Iterable[bytes]) -> dict[str, float | int]:
    latencies = []
    started = time.perf_counter_ns()
    for payload in payloads:
        request_started = time.perf_counter_ns()
        round_trip(socket_path, payload)
        latencies.append(time.perf_counter_ns() - request_started)
    return summarize(latencies, time.perf_counter_ns() - started)


def concurrent(
    socket_path: Path, payloads: list[bytes], workers: int
) -> dict[str, float | int]:
    def measure(payload: bytes) -> int:
        request_started = time.perf_counter_ns()
        round_trip(socket_path, payload)
        return time.perf_counter_ns() - request_started

    started = time.perf_counter_ns()
    with futures.ThreadPoolExecutor(max_workers=workers) as executor:
        latencies = list(executor.map(measure, payloads))
    return summarize(latencies, time.perf_counter_ns() - started)
