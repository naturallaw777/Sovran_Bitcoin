"""Regression tests for LndRestClient.pay_invoice against LND 0.21+ REST.

LND 0.21 removed the deprecated `POST /v1/channels/transactions`
(lnrpc.SendPaymentSync) REST route — every NWC spend then failed with an HTTP
404 ("Not Found") from LND's REST gateway. Payments must be sent through
`POST /v2/router/send` (routerrpc.SendPaymentV2), which streams
newline-delimited `lnrpc.Payment` JSON updates whose `payment_preimage` /
`payment_hash` fields are hex strings (not base64).

Run with:  python3 tests/test_lnd_rest_pay.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "sovran_nwc" not in sys.modules:
    _pkg = types.ModuleType("sovran_nwc")
    _pkg.__path__ = [_PKG_ROOT]  # type: ignore[attr-defined]
    sys.modules["sovran_nwc"] = _pkg
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sovran_nwc import nwc_lnd as lnd_mod  # noqa: E402


class StubLnd:
    """Programmable HTTP stub for the LND REST surface used by NwcRestClient."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.status = 200
        self.body = b""
        self.content_type = "application/json"
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                stub.requests.append(
                    {
                        "method": "POST",
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": json.loads(raw.decode("utf-8")) if raw else None,
                    }
                )
                self.send_response(stub.status)
                self.send_header("Content-Type", stub.content_type)
                self.send_header("Content-Length", str(len(stub.body)))
                self.end_headers()
                self.wfile.write(stub.body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host, port = self.server.server_address[:2]
        self.url = f"http://{host}:{port}"
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class LndRestPayInvoiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = StubLnd()
        self.addCleanup(self.stub.close)
        self.client = lnd_mod.LndRestClient(
            rest_url=self.stub.url,
            cert_file="/dev/null",
            macaroon_file="/dev/null",
        )
        # Bypass the macaroon file read; the stub does not check auth.
        self.client._get_macaroon_hex = lambda: "00"  # type: ignore[method-assign]

    def _pay(self, **kwargs: Any) -> dict[str, Any]:
        args: dict[str, Any] = {"bolt11": "lnbcrt5000n1pspend", "fee_limit_msat": 10_000}
        args.update(kwargs)
        return self.client.pay_invoice(**args)

    def test_spends_via_router_send_payment_v2(self) -> None:
        """Must call routerrpc.SendPaymentV2, not the removed SendPaymentSync."""
        self.stub.body = (
            json.dumps(
                {
                    "payment_hash": "ab" * 32,
                    "payment_preimage": "cd" * 32,
                    "status": "SUCCEEDED",
                    "fee_msat": "1500",
                }
            ).encode()
            + b"\n"
        )
        result = self._pay()
        self.assertEqual(len(self.stub.requests), 1)
        req = self.stub.requests[0]
        self.assertEqual(req["path"], "/v2/router/send")
        body = req["body"]
        self.assertEqual(body["payment_request"], "lnbcrt5000n1pspend")
        self.assertEqual(body["fee_limit_msat"], "10000")
        self.assertTrue(body["allow_self_payment"])
        self.assertNotIn("amt_msat", body)
        # The removed endpoint must never be called again.
        self.assertNotIn("/v1/channels/transactions", req["path"])
        # Preimage/hash from lnrpc.Payment are hex — returned as-is.
        self.assertEqual(result["preimage"], "cd" * 32)
        self.assertEqual(result["payment_hash"], "ab" * 32)
        self.assertEqual(result["fees_paid_msat"], 1500)

    def test_zero_amount_invoice_sends_amt_msat(self) -> None:
        self.stub.body = json.dumps(
            {
                "payment_hash": "ab" * 32,
                "payment_preimage": "cd" * 32,
                "status": "SUCCEEDED",
                "fee_msat": "0",
            }
        ).encode()
        self._pay(amount_msat=2_500_000)
        body = self.stub.requests[0]["body"]
        self.assertEqual(body["amt_msat"], "2500000")

    def test_parses_multichunk_stream_and_uses_terminal_update(self) -> None:
        inflight = json.dumps(
            {"payment_hash": "ab" * 32, "status": "IN_FLIGHT", "fee_msat": "0"}
        )
        settled = json.dumps(
            {
                "payment_hash": "ab" * 32,
                "payment_preimage": "ef" * 32,
                "status": "SUCCEEDED",
                "fee_msat": "2100",
            }
        )
        self.stub.body = (inflight + "\n" + settled + "\n").encode()
        result = self._pay()
        self.assertEqual(result["preimage"], "ef" * 32)
        self.assertEqual(result["fees_paid_msat"], 2100)

    def test_failed_payment_raises_readable_reason(self) -> None:
        self.stub.body = (
            json.dumps(
                {
                    "payment_hash": "ab" * 32,
                    "status": "FAILED",
                    "failure_reason": "FAILURE_REASON_NO_ROUTE",
                }
            ).encode()
            + b"\n"
        )
        with self.assertRaises(lnd_mod.LndPaymentError) as ctx:
            self._pay()
        self.assertIn("No route", str(ctx.exception))

    def test_removed_endpoint_404_maps_to_not_found(self) -> None:
        """Documents the pre-fix symptom: a 404 surfaces as LndError(NOT_FOUND)."""
        self.stub.status = 404
        self.stub.content_type = "text/plain; charset=utf-8"
        self.stub.body = b"Not Found"
        with self.assertRaises(lnd_mod.LndError) as ctx:
            self._pay()
        self.assertEqual(ctx.exception.code, "NOT_FOUND")
        self.assertIn("404", str(ctx.exception))

    def test_empty_stream_raises_payment_error(self) -> None:
        self.stub.body = b""
        with self.assertRaises(lnd_mod.LndPaymentError):
            self._pay()

    def test_parse_json_stream_variants(self) -> None:
        single = '{"a": 1}\n'
        multi = '{"a": 1}\n{"b": 2}\n'
        glued = '{"a": 1}{"b": 2}'
        self.assertEqual(lnd_mod.LndRestClient.parse_json_stream(single), [{"a": 1}])
        self.assertEqual(
            lnd_mod.LndRestClient.parse_json_stream(multi), [{"a": 1}, {"b": 2}]
        )
        self.assertEqual(
            lnd_mod.LndRestClient.parse_json_stream(glued), [{"a": 1}, {"b": 2}]
        )
        self.assertEqual(lnd_mod.LndRestClient.parse_json_stream(""), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class LndRestPayKeysendTest(unittest.TestCase):
    """Request shape of keysend (spontaneous) payments via SendPaymentV2."""

    def setUp(self) -> None:
        self.stub = StubLnd()
        self.addCleanup(self.stub.close)
        self.lnd = lnd_mod.LndRestClient(rest_url=self.stub.url)
        self.lnd._get_macaroon_hex = lambda: "00"  # type: ignore[method-assign]

    def test_keysend_body_and_success_parse(self) -> None:
        preimage = "ab" * 32
        self.stub.body = (
            b'{"result":{"status":"SUCCEEDED","payment_hash":"cd32",'
            b'"payment_preimage":"' + preimage.encode() + b'","fee_msat":"750"}}\n'
        )
        result = self.lnd.pay_keysend(
            dest_pubkey_hex="02" + "ff" * 32,
            amount_msat=500_000,
            fee_limit_msat=5_000,
            preimage_hex=preimage,
            tlv_records=[{"type": 696969, "value": "cafe"}],
        )
        req = self.stub.requests[-1]
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["path"], "/v2/router/send")
        body = req["body"]
        # Destination is the raw pubkey bytes (base64) per grpc-gateway.
        self.assertEqual(body["dest"], base64.b64encode(bytes.fromhex("02" + "ff" * 32)).decode())
        self.assertEqual(body["amt_msat"], "500000")
        self.assertEqual(body["fee_limit_msat"], "5000")
        self.assertEqual(body["timeout_seconds"], 60)
        self.assertTrue(body["allow_self_payment"])
        self.assertTrue(body["no_inflight_updates"])
        self.assertNotIn("payment_request", body)
        records = body["dest_custom_records"]
        # TLV 5482373484 carries the keysend preimage (base64 of raw bytes).
        self.assertEqual(records["5482373484"], base64.b64encode(bytes.fromhex(preimage)).decode())
        self.assertEqual(records["696969"], base64.b64encode(bytes.fromhex("cafe")).decode())
        self.assertEqual(result["preimage"], preimage)
        self.assertEqual(result["fees_paid_msat"], 750)

    def test_keysend_generates_preimage_when_absent(self) -> None:
        self.stub.body = (
            b'{"result":{"status":"SUCCEEDED","payment_hash":"cd32",'
            b'"payment_preimage":"' + b"11" * 32 + b'","fee_msat":"10"}}\n'
        )
        result = self.lnd.pay_keysend(
            dest_pubkey_hex="02" + "ee" * 32,
            amount_msat=1_000,
            fee_limit_msat=10,
        )
        body = self.stub.requests[-1]["body"]
        records = body["dest_custom_records"]
        sent_preimage_b64 = records["5482373484"]
        sent_preimage = base64.b64decode(sent_preimage_b64).hex()
        self.assertEqual(len(sent_preimage), 64)
        # The daemon reuses the generated preimage; LND echoes its own.
        self.assertEqual(result["preimage"], "11" * 32)

    def test_keysend_failure_maps_reason(self) -> None:
        self.stub.body = (
            b'{"result":{"status":"FAILED","payment_hash":"cd32",'
            b'"failure_reason":"NO_ROUTE"}}\n'
        )
        with self.assertRaises(lnd_mod.LndPaymentError) as ctx:
            self.lnd.pay_keysend(
                dest_pubkey_hex="02" + "ee" * 32,
                amount_msat=1_000,
                fee_limit_msat=10,
            )
        self.assertIn("No route found", str(ctx.exception))
