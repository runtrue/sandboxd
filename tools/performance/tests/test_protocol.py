"""Tests for the cross-language work-order encoder."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_plane.protocol import build_ping_request, compact_json  # noqa: E402


class ProtocolTests(unittest.TestCase):
    def test_ping_request_matches_signing_contract(self) -> None:
        key = bytes(range(32))
        with mock.patch("control_plane.protocol.time.time_ns", return_value=1_000_000_000):
            encoded = build_ping_request(key, "run-1", 7)

        self.assertTrue(encoded.endswith(b"\n"))
        request = json.loads(encoded)
        work_order = request["authorization"]["work_order"]
        claims = work_order["claims"]
        operation = request["operation"]
        self.assertEqual(request["request_id"], claims["request_id"])
        self.assertEqual(claims["nonce"], "nonce-run-1-7")
        self.assertEqual(claims["expires_unix_millis"], 241_000)
        self.assertEqual(
            claims["operation_digest"],
            f"sha256:{hashlib.sha256(compact_json(operation)).hexdigest()}",
        )
        self.assertEqual(
            work_order["signature"],
            hmac.new(key, compact_json(claims), hashlib.sha256).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
