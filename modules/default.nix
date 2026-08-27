# Sovran Bitcoin — an opinionated, Tor-first Bitcoin & Lightning stack for NixOS.
#
# Vendored and tailored from Sovran_SystemsOS (modules/bitcoin) and
# fort-nix/nix-bitcoin. Opinions inherited from the Sovran repo:
#   - LND only (no clightning), packages from nixpkgs
#   - hard systemd units (nix-bitcoin defaultHardening)
#   - secrets generated on the host, onion services via Tor
#   - BTCPay/nbxplorer pinned to nixos-26.05 via the flake overlay
#
# Consumed via:
#   sovran-bitcoin.enable = true;            # base node (see ./preset.nix)
#   sovran-bitcoin.features.<name> = true;   # btcpayserver, rtl, mempool, nwc, lnurl
#
# Every underlying service stays configurable through the plain
# `services.*` (nix-bitcoin style) options.
{ config, lib, pkgs, ... }:

{
  imports = [
    # Vendored nix-bitcoin common infrastructure
    # (secrets, operator, security, onion services, nodeinfo, lib)
    ./nix-bitcoin

    # Services
    ./bitcoind.nix
    ./electrs.nix
    ./lnd.nix
    ./lndconnect.nix
    ./rtl.nix
    ./btcpayserver.nix
    ./mempool.nix
    ./albyhub.nix
    ./lnurl.nix

    # The opinionated preset behind `sovran-bitcoin.enable`
    ./preset.nix
  ];

  # The vendored bitcoind module replaces the nixpkgs one.
  disabledModules = [ "services/networking/bitcoind.nix" ];
}
