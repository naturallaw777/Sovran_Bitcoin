# Example: the full Sovran Bitcoin stack.
#
# Base node + BTCPay Server, RTL, Mempool, NWC (Alby Hub) and self-hosted
# LNURL Lightning Addresses.
#
# Clearnet is deliberately NOT handled by the flake. Every web service binds
# to loopback; put your own webserver in front:
#
#   Service      Loopback endpoint
#   -----------  -------------------------------
#   BTCPay       http://127.0.0.1:23000   (also NBXplorer at :24444)
#   Mempool UI   http://127.0.0.1:60845
#   RTL          http://127.0.0.1:3050
#   Alby Hub UI  http://127.0.0.1:18080   (keep private! SSH tunnel or onion)
#   LNURL        http://127.0.0.1:8181    (proxy /.well-known/lnurlp and /lnurlp)
#
# All of them also get Tor onion services (nix-bitcoin.onionServices.*).
{ ... }:

{
  sovran-bitcoin = {
    enable = true;
    operatorName = "myuser";

    features = {
      electrs = true;   # default
      lnd = true;       # default
      rtl = true;
      btcpayserver = true;
      mempool = true;
      nwc = true;
      lnurl = true;     # implies nwc
    };
  };

  # Lightning Addresses: alias@pay.example.com
  # Either set the domain directly (as here) or point `domainFile` at a file
  # managed out-of-band (e.g. DDNS).
  services.sovran-lnurl.domain = "pay.example.com";

  # Example tweaks — the preset only sets defaults, so these just work:
  # services.bitcoind.prune = 0;               # full archive node (default)
  # services.rtl.extraCurrency = "USD";        # fiat display (disables tor.enforce for RTL)
  # services.albyhub.relay = "wss://relay.example.com";  # self-hosted Nostr relay
}
