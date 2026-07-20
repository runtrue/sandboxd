"""Tests for performance summary calculations."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_plane.measure import summarize  # noqa: E402


class MeasureTests(unittest.TestCase):
    def test_summary_uses_nearest_rank_percentiles(self) -> None:
        samples = [value * 1_000_000 for value in range(1, 101)]
        result = summarize(samples, 1_000_000_000)
        self.assertEqual(result["requests"], 100)
        self.assertEqual(result["requests_per_second"], 100)
        self.assertEqual(result["p50_ms"], 50)
        self.assertEqual(result["p95_ms"], 95)
        self.assertEqual(result["p99_ms"], 99)
        self.assertEqual(result["max_ms"], 100)


if __name__ == "__main__":
    unittest.main()
