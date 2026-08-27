# The Sovran opinionated preset.
#
# Mirrors Sovran_SystemsOS' Bitcoin ecosystem defaults (modules/bitcoinecosystem.nix)
# without the OS-specific couplings (second-drive paths, Sovran Hub, domain
# provisioning, firewall port 3051).
#
#   sovran-bitcoin.enable = true;
#     → bitcoind + electrs + lnd, Tor proxy + enforcement, onion services,
#       generated secrets, operator user, nodeinfo, lndconnect (Zeus over Tor)
#
#   sovran-bitcoin.features.<name> = true;
#     → rtl, btcpayserver (+nbxplorer, LND backend), mempool, nwc (Alby Hub),
#       lnurl (self-hosted Lightning Addresses)
#
# All values here are `mkDefault` (or otherwise low priority) so users can
# override anything through the plain `services.*` options without mkForce,
# e.g. `services.bitcoind.prune = 550;`.
{ config, lib, pkgs, ... }:

with lib;
let
  options.sovran-bitcoin = {
    enable = mkEnableOption "the Sovran Bitcoin stack: an opinionated, Tor-first Bitcoin node (bitcoind + electrs + LND) with optional BTCPay Server, RTL, Mempool, NWC (Alby Hub) and LNURL add-ons";

    operatorName = mkOption {
      type = types.str;
      default = "operator";
      description = ''
        Name of the unprivileged operator user that gets interactive access
        to node tooling (`bitcoin-cli`, `lncli`, `nodeinfo`, …).
        Set this to your main system user.
      '';
    };

    bitcoindTorGossip = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Announce the bitcoind onion address to peers via Bitcoin addr gossip.
        The onion service itself always stays available; this only controls
        whether its address is advertised.
      '';
    };

    features = {
      electrs = mkOption {
        type = types.bool;
        default = true;
        description = "Electrum server (also used by the Mempool backend).";
      };
      lnd = mkOption {
        type = types.bool;
        default = true;
        description = "LND Lightning node (required by RTL, BTCPay, NWC and LNURL).";
      };
      rtl = mkOption {
        type = types.bool;
        default = false;
        description = "Ride The Lightning — web UI for LND.";
      };
      btcpayserver = mkOption {
        type = types.bool;
        default = false;
        description = "BTCPay Server (with NBXplorer and the LND backend). Bring your own reverse proxy for clearnet.";
      };
      mempool = mkOption {
        type = types.bool;
        default = false;
        description = "Mempool explorer (backend + local web frontend).";
      };
      nwc = mkOption {
        type = types.bool;
        default = false;
        description = "NWC wallet server via Alby Hub (Sovran's LND-only fork), bound to 127.0.0.1.";
      };
      lnurl = mkOption {
        type = types.bool;
        default = false;
        description = "Self-hosted LNURL-pay service (Lightning Addresses) backed by Alby Hub. Implies `nwc`.";
      };
    };
  };

  cfg = config.sovran-bitcoin;
  feat = cfg.features;
in {
  inherit options;

  config = mkIf cfg.enable {
    # ── Base node ─────────────────────────────────────────────────────
    services.bitcoind = {
      enable = true;
      # Keep the normal loopback P2P socket available for local clients such as
      # Bisq. `address` defaults to 127.0.0.1, so this does NOT expose a
      # clearnet/LAN listener.
      listen = mkDefault true;
      txindex = mkDefault true;
      tor.proxy = mkDefault true;
      tor.enforce = mkDefault true;
      # Sovran default: no hot wallet on a plain node.
      # NBXplorer needs the bitcoind wallet, so it is re-enabled for BTCPay.
      disablewallet = mkDefault (!feat.btcpayserver);
      extraConfig = ''
        peerbloomfilters=1
        server=1
      '';
    };

    nix-bitcoin.onionServices.bitcoind = {
      enable = true;
      public = mkDefault cfg.bitcoindTorGossip;
    };

    # ── Electrs ───────────────────────────────────────────────────────
    services.electrs = mkIf feat.electrs {
      enable = true;
      tor.enforce = mkDefault true;
    };
    nix-bitcoin.onionServices.electrs.enable = mkIf feat.electrs true;

    # ── LND ───────────────────────────────────────────────────────────
    services.lnd = mkIf feat.lnd {
      enable = true;
      tor.proxy = mkDefault true;
      tor.enforce = mkDefault true;
      extraConfig = ''
        protocol.option-scid-alias=true
      '';
      # Zeus & friends: `lndconnect` prints a QR pointing at the REST onion
      lndconnect = {
        enable = true;
        onion = true;
      };
    };
    nix-bitcoin.onionServices.lnd.public = mkIf feat.lnd true;

    # ── RTL ───────────────────────────────────────────────────────────
    services.rtl = mkIf feat.rtl {
      enable = true;
      port = mkDefault 3050;
      nightTheme = mkDefault true;
      nodes.lnd.enable = true;
      tor.enforce = mkDefault true;
    };
    nix-bitcoin.onionServices.rtl.enable = mkIf feat.rtl true;

    # ── BTCPay Server ─────────────────────────────────────────────────
    # No webserver/TLS is provided: put BTCPay behind your own reverse proxy
    # (it listens on 127.0.0.1:23000) for full clearnet operation.
    services.btcpayserver = mkIf feat.btcpayserver {
      enable = true;
      lightningBackend = mkDefault "lnd";
    };

    # ── Mempool ───────────────────────────────────────────────────────
    services.mempool = mkIf feat.mempool {
      enable = true;
      frontend.enable = mkDefault true;
    };
    nix-bitcoin.onionServices.mempool-frontend.enable = mkIf feat.mempool true;

    # ── NWC (Alby Hub) + LNURL ────────────────────────────────────────
    services.albyhub.enable = mkIf (feat.nwc || feat.lnurl) true;
    services.sovran-lnurl = mkIf feat.lnurl {
      enable = true;
    };

    # ── Tor ───────────────────────────────────────────────────────────
    # The stack is Tor-first: proxy outgoing connections and publish onion
    # services (see nix-bitcoin.onionServices above).
    services.tor = {
      enable = true;
      client.enable = true;
    };

    # ── Secrets / operator / nodeinfo ─────────────────────────────────
    nix-bitcoin.generateSecrets = true;
    nix-bitcoin.nodeinfo.enable = true;

    nix-bitcoin.operator = {
      enable = true;
      name = cfg.operatorName;
    };
  };
}
