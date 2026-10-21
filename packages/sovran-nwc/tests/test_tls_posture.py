"""TLS posture tests (CWE-327): both outbound TLS contexts enforce TLS 1.2+.

Regression guard for GitHub code scanning alert `py/insecure-protocol`
(CWE-327) on `ssl.create_default_context()`. Python's default context already
floors at TLS 1.2, but the floor was implicit; these tests assert it is
explicit, so a future edit cannot silently drop it.
"""

from __future__ import annotations

import os
import ssl
import sys
import tempfile
import types
import unittest

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "sovran_nwc" not in sys.modules:
    _pkg = types.ModuleType("sovran_nwc")
    _pkg.__path__ = [_PKG_ROOT]  # type: ignore[attr-defined]
    sys.modules["sovran_nwc"] = _pkg

from sovran_nwc import nwc_lnd as lnd  # noqa: E402
from sovran_nwc import nwc_nostr as nostr  # noqa: E402

_TLS12_OR_BETTER = (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)

# Throwaway self-signed cert standing in for LND's own TLS cert, so the LND
# context can be built without touching the host's secret store.
_TEST_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUYzOtBnjtHSWwf4SKSEdJlKg9pnIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MTAyMTE2NDQzMFoXDTM2MTAx
ODE2NDQzMFowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAnxUz3iEg2pU+mL0QBcMGDImyxqOOhtWrU7oAJ3V6wyt0
YU4VqenNNMP0OgNnfIXyV4vTYKoTPT2WQu6uB+M5XHkKTR/JaHGwXNBdsDX+x873
STCPatcfIowj/f0uRZkf1F9PSCo4HGwrd9jdBI0QjscvJrXRp5XL40rnxtrDC1fu
dRwWb8PlqbMzLxwvM3oNQ0/Wf0hqShlzqY95a7whQJr3OnMJyP/X4iUp4STUK/Yw
asYl0UBzjrIQXEeixTMuCXxYbBEZ3F9GklyGAe6a0gQT7gzRx92ZyY0FPGjrcRLE
9ZxcOTxd0IIvtJ+E3IiP7l+cuPiPOcf10WR5VrxdoQIDAQABo28wbTAdBgNVHQ4E
FgQUyOu09WM1kce8tntOn6OJQFyUe2cwHwYDVR0jBBgwFoAUyOu09WM1kce8tntO
n6OJQFyUe2cwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2Nh
bGhvc3QwDQYJKoZIhvcNAQELBQADggEBABd8hyZfcUZXlbOY7KjK5Tu1Kn+1gxpG
NY4iVkRCeELsX/LP+LnZ5HdBsspaVjot/v96to7lnrTcFvc8x7K/VlmrJiWkYTMe
LVO3ZwtsEu+VX1IqMhFb/+rMk+Mt+OVhKlxWmep6Ta3F743vI5Jsjcl53FOelSoD
YOXDGRbxtF51kFT0p18VQtT7Wdye+S3CSFGrADcd66Fd5S+LhsF8qXbvxzbN/c+Y
Z0/lcKwS/fFRip+qR9PFAUJfulNRRr1geKcwBifTKaQGgAs3s5npY/UdFDkQFRdb
cY/QlYOws3igL22fLOJbqsUYhHdW0hA2z//KZbPEPX8M8e2ZFe3Zdhw=
-----END CERTIFICATE-----
"""


class TlsPostureTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".pem", delete=False, encoding="ascii"
        )
        self._tmp.write(_TEST_CERT_PEM)
        self._tmp.close()
        self.cert_file = self._tmp.name

    def tearDown(self) -> None:
        try:
            os.unlink(self.cert_file)
        except OSError:
            pass

    def test_relay_context_floors_at_tls12(self) -> None:
        ctx = nostr._tls_context()
        self.assertIn(ctx.minimum_version, _TLS12_OR_BETTER)
        # Certificate and hostname verification must stay on for relays.
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_relay_context_rejects_legacy_protocols(self) -> None:
        ctx = nostr._tls_context()
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertNotIn(
            ctx.minimum_version, (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
        )

    def test_lnd_context_floors_at_tls12(self) -> None:
        client = lnd.LndRestClient(cert_file=self.cert_file)
        ctx = client._ssl_context()
        self.assertIsNotNone(ctx)
        assert ctx is not None
        self.assertIn(ctx.minimum_version, _TLS12_OR_BETTER)
        # LND uses a self-signed cert: verification stays on against that cert.
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_plain_http_skips_tls_context(self) -> None:
        client = lnd.LndRestClient(
            rest_url="http://127.0.0.1:8080", cert_file=self.cert_file
        )
        self.assertIsNone(client._ssl_context())


if __name__ == "__main__":
    unittest.main()
