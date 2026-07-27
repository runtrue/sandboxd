#!/usr/bin/env python3
"""Evaluate a measured warm-worker service objective and capacity policy."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """The policy, catalog, or measurement is not internally consistent."""


def positive_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PolicyError(f"{field} must be a positive integer")
    return value


def nonnegative_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PolicyError(f"{field} must be a non-negative integer")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{path} must contain a JSON object")
    return value


def capacity_headroom(
    peak_arrivals_per_second: int,
    burst_tasks: int,
    replacement_p99_budget_ms: int,
    safety_margin_percent: int,
) -> dict[str, int]:
    replacement_demand = math.ceil(
        peak_arrivals_per_second * replacement_p99_budget_ms / 1_000
    )
    demand_before_margin = max(burst_tasks, replacement_demand)
    recommended = math.ceil(
        demand_before_margin * (100 + safety_margin_percent) / 100
    )
    return {
        "replacement_window_demand": replacement_demand,
        "demand_before_margin": demand_before_margin,
        "recommended_warm_headroom": recommended,
    }


def find_pool(catalog: dict[str, Any], pool_name: str) -> dict[str, Any]:
    pools = catalog.get("pools")
    if not isinstance(pools, list):
        raise PolicyError("catalog pools must be an array")
    matches = [
        pool
        for pool in pools
        if isinstance(pool, dict) and pool.get("name") == pool_name
    ]
    if len(matches) != 1:
        raise PolicyError(f"catalog must contain exactly one pool named {pool_name}")
    return matches[0]


def measured_distribution(
    measurement: dict[str, Any], field: str
) -> dict[str, Any]:
    worker = measurement.get("one_sandbox_per_worker")
    if not isinstance(worker, dict):
        raise PolicyError("measurement omits one_sandbox_per_worker")
    distribution = worker.get(field)
    if not isinstance(distribution, dict):
        raise PolicyError(f"measurement omits {field}")
    declared_p99 = positive_integer(distribution.get("p99"), f"{field}.p99")
    samples = distribution.get("samples")
    if not isinstance(samples, list) or not samples:
        raise PolicyError(f"{field}.samples must be a non-empty array")
    for index, sample in enumerate(samples):
        nonnegative_integer(sample, f"{field}.samples[{index}]")
    ordered = sorted(samples)
    rank = max(1, math.ceil(len(ordered) * 99 / 100))
    calculated_p99 = ordered[rank - 1]
    if declared_p99 != calculated_p99:
        raise PolicyError(
            f"{field}.p99 does not match the nearest-rank sample percentile"
        )
    return distribution


def evaluate(
    measurement: dict[str, Any],
    policy: dict[str, Any],
    catalog: dict[str, Any],
    prime_measurement: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected_policy_fields = {
        "schema_version",
        "pool_name",
        "activation_p99_budget_ms",
        "replacement_p99_budget_ms",
        "maximum_concurrent_starts_per_node",
        "minimum_activation_samples",
        "peak_arrivals_per_second",
        "burst_tasks",
        "safety_margin_percent",
        "task_model",
        "pause_policy",
    }
    if set(policy) != expected_policy_fields:
        raise PolicyError("warm-pool policy fields do not match schema version 1")
    if policy.get("schema_version") != 1:
        raise PolicyError("warm-pool policy schema_version must be 1")
    if measurement.get("schema_version") != 1:
        raise PolicyError("measurement schema_version must be 1")

    pool_name = policy.get("pool_name")
    if not isinstance(pool_name, str) or not pool_name:
        raise PolicyError("pool_name must be a non-empty string")
    activation_budget = positive_integer(
        policy.get("activation_p99_budget_ms"), "activation_p99_budget_ms"
    )
    replacement_budget = positive_integer(
        policy.get("replacement_p99_budget_ms"), "replacement_p99_budget_ms"
    )
    concurrent_starts = positive_integer(
        policy.get("maximum_concurrent_starts_per_node"),
        "maximum_concurrent_starts_per_node",
    )
    minimum_samples = positive_integer(
        policy.get("minimum_activation_samples"), "minimum_activation_samples"
    )
    peak_rate = positive_integer(
        policy.get("peak_arrivals_per_second"), "peak_arrivals_per_second"
    )
    burst_tasks = positive_integer(policy.get("burst_tasks"), "burst_tasks")
    safety_margin = nonnegative_integer(
        policy.get("safety_margin_percent"), "safety_margin_percent"
    )
    if safety_margin > 1_000:
        raise PolicyError("safety_margin_percent cannot exceed 1000")
    if policy.get("task_model") != "fresh_sandbox_per_assignment":
        raise PolicyError("task_model must preserve fresh sandbox assignments")
    expected_pause_policy = {
        "short_pause": "retain_worker",
        "capacity_releasing_suspend": "stop_and_move_snapshot",
        "independent_child_pause": False,
    }
    if policy.get("pause_policy") != expected_pause_policy:
        raise PolicyError("pause_policy does not match the reviewed lifecycle")

    slots = positive_integer(measurement.get("slots"), "measurement.slots")
    issuance = measurement.get("methodology", {}).get("activation_issuance")
    if not isinstance(issuance, str):
        raise PolicyError("measurement activation_issuance is missing")
    activation = measured_distribution(measurement, "activation_milliseconds")
    replacement = measured_distribution(
        measurement, "cleanup_to_replacement_milliseconds"
    )

    pool = find_pool(catalog, pool_name)
    pool_policy = pool.get("policy")
    if not isinstance(pool_policy, dict):
        raise PolicyError("catalog pool policy must be an object")
    configured_headroom = nonnegative_integer(
        pool_policy.get("warm_headroom"), "catalog warm_headroom"
    )
    maximum_workers = positive_integer(
        pool_policy.get("maximum_workers"), "catalog maximum_workers"
    )

    capacity = capacity_headroom(
        peak_rate, burst_tasks, replacement_budget, safety_margin
    )
    recommended = capacity["recommended_warm_headroom"]
    minimum_nodes_for_burst = math.ceil(burst_tasks / concurrent_starts)
    nodes_for_full_headroom_burst = math.ceil(recommended / concurrent_starts)

    activation_passed = (
        issuance.startswith("concurrent")
        and slots == concurrent_starts
        and len(activation["samples"]) >= minimum_samples
        and activation["p99"] <= activation_budget
    )
    replacement_passed = (
        len(replacement["samples"]) >= minimum_samples
        and replacement["p99"] <= replacement_budget
    )
    capacity_passed = configured_headroom >= recommended
    capacity_feasible = maximum_workers >= recommended
    overall_passed = (
        activation_passed
        and replacement_passed
        and capacity_passed
        and capacity_feasible
    )

    result: dict[str, Any] = {
        "schema_version": 1,
        "revision": measurement.get("revision"),
        "node": measurement.get("node"),
        "pool_name": pool_name,
        "workload_model": {
            "assignment": policy.get("task_model"),
            "pause": policy.get("pause_policy"),
        },
        "service_objective": {
            "activation_p99_budget_ms": activation_budget,
            "activation_p99_measured_ms": activation["p99"],
            "activation_samples_ms": activation["samples"],
            "maximum_concurrent_starts_per_node": concurrent_starts,
            "minimum_activation_samples": minimum_samples,
            "activation_sample_count": len(activation["samples"]),
            "measurement_slots": slots,
            "activation_issuance": issuance,
            "activation_passed": activation_passed,
            "replacement_p99_budget_ms": replacement_budget,
            "replacement_p99_measured_ms": replacement["p99"],
            "replacement_samples_ms": replacement["samples"],
            "replacement_sample_count": len(replacement["samples"]),
            "replacement_passed": replacement_passed,
        },
        "capacity": {
            "peak_arrivals_per_second": peak_rate,
            "burst_tasks": burst_tasks,
            "safety_margin_percent": safety_margin,
            **capacity,
            "configured_warm_headroom": configured_headroom,
            "maximum_workers": maximum_workers,
            "minimum_nodes_for_declared_burst": minimum_nodes_for_burst,
            "nodes_for_full_headroom_burst": nodes_for_full_headroom_burst,
            "capacity_passed": capacity_passed,
            "capacity_feasible": capacity_feasible,
        },
        "overall_passed": overall_passed,
    }
    if prime_measurement is not None:
        prime_activation = measured_distribution(
            prime_measurement, "activation_milliseconds"
        )
        prime_replacement = measured_distribution(
            prime_measurement, "cleanup_to_replacement_milliseconds"
        )
        result["prime_observation"] = {
            "activation_p99_ms": prime_activation["p99"],
            "replacement_p99_ms": prime_replacement["p99"],
        }
    return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measurement", required=True, type=Path)
    parser.add_argument("--prime-measurement", type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        result = evaluate(
            load_json(arguments.measurement),
            load_json(arguments.policy),
            load_json(arguments.catalog),
            load_json(arguments.prime_measurement)
            if arguments.prime_measurement
            else None,
        )
    except PolicyError as error:
        raise SystemExit(f"error: {error}") from error
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
