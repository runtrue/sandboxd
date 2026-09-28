"""Tests for the measured warm-pool service objective."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from warm_pool import PolicyError, capacity_headroom, evaluate  # noqa: E402


def measurement(
    activation_p99: int = 900,
    replacement_p99: int = 8_500,
    samples: int = 100,
):
    return {
        "schema_version": 1,
        "revision": "abc",
        "node": "worker-a",
        "slots": 2,
        "methodology": {
            "activation_issuance": (
                "concurrent while retaining every sandbox so all slots are active"
            )
        },
        "one_sandbox_per_worker": {
            "activation_milliseconds": {
                "samples": [800] * (samples - 2) + [activation_p99] * 2,
                "p99": activation_p99,
            },
            "cleanup_to_replacement_milliseconds": {
                "samples": [8_000] * (samples - 2) + [replacement_p99] * 2,
                "p99": replacement_p99,
            },
        },
    }


def policy():
    return {
        "schema_version": 1,
        "pool_name": "fixed-standard-warm",
        "activation_p99_budget_ms": 1_000,
        "replacement_p99_budget_ms": 9_000,
        "maximum_concurrent_starts_per_node": 2,
        "minimum_activation_samples": 100,
        "peak_arrivals_per_second": 1,
        "burst_tasks": 2,
        "safety_margin_percent": 25,
        "task_model": "fresh_sandbox_per_assignment",
        "pause_policy": {
            "short_pause": "retain_worker",
            "capacity_releasing_suspend": "stop_and_move_snapshot",
            "independent_child_pause": False,
        },
    }


def catalog(headroom: int = 12):
    return {
        "pools": [
            {
                "name": "fixed-standard-warm",
                "policy": {"warm_headroom": headroom, "maximum_workers": 100},
            }
        ]
    }


class WarmPoolTests(unittest.TestCase):
    def test_capacity_includes_replacement_window_and_margin(self) -> None:
        result = capacity_headroom(1, 2, 9_000, 25)
        self.assertEqual(result["replacement_window_demand"], 9)
        self.assertEqual(result["demand_before_margin"], 9)
        self.assertEqual(result["recommended_warm_headroom"], 12)

    def test_passing_measurement_proves_slo_and_capacity(self) -> None:
        result = evaluate(measurement(), policy(), catalog())
        self.assertTrue(result["overall_passed"])
        self.assertEqual(result["capacity"]["minimum_nodes_for_declared_burst"], 1)
        self.assertEqual(result["capacity"]["nodes_for_full_headroom_burst"], 6)
        self.assertEqual(
            result["workload_model"]["assignment"], "fresh_sandbox_per_assignment"
        )

    def test_activation_and_capacity_fail_closed(self) -> None:
        result = evaluate(measurement(activation_p99=1_001), policy(), catalog(11))
        self.assertFalse(result["service_objective"]["activation_passed"])
        self.assertFalse(result["capacity"]["capacity_passed"])
        self.assertFalse(result["overall_passed"])

    def test_sequential_measurement_cannot_satisfy_concurrent_slo(self) -> None:
        candidate = measurement()
        candidate["methodology"]["activation_issuance"] = "sequential"
        self.assertFalse(
            evaluate(candidate, policy(), catalog())["service_objective"][
                "activation_passed"
            ]
        )

    def test_insufficient_sample_count_fails_closed(self) -> None:
        result = evaluate(measurement(samples=99), policy(), catalog())
        self.assertFalse(result["service_objective"]["activation_passed"])
        self.assertFalse(result["service_objective"]["replacement_passed"])
        self.assertFalse(result["overall_passed"])

    def test_tampered_percentile_is_rejected(self) -> None:
        candidate = measurement()
        candidate["one_sandbox_per_worker"]["activation_milliseconds"]["p99"] = 1
        with self.assertRaises(PolicyError):
            evaluate(candidate, policy(), catalog())

    def test_invalid_policy_is_rejected(self) -> None:
        candidate = policy()
        candidate["safety_margin_percent"] = -1
        with self.assertRaises(PolicyError):
            evaluate(measurement(), candidate, catalog())


if __name__ == "__main__":
    unittest.main()
