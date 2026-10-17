# Packages vendored by the Sovran Bitcoin flake.
#
# Called via the flake overlay:
#   pkgs.sovran-bitcoin.<name>
#
# BTCPay Server and NBXplorer are supplied directly by nixpkgs and are
# not part of this package set.
{ lib
, callPackage
, ...
}:

let
  fetchNodeModules = callPackage ./build-support/fetch-node-modules.nix { };
  mempool = callPackage ./mempool { inherit fetchNodeModules; };
  nwc = callPackage ./sovran-nwc { };
in
{
  inherit fetchNodeModules;

  rtl = callPackage ./rtl { inherit fetchNodeModules; };

  inherit (mempool)
    mempool-backend
    mempool-frontend
    mempool-nginx-conf;

  inherit nwc;

  # Backwards-compatible package alias: `sovran-nwc` now provides the native
  # NWC wallet server (`nwc-daemon` / `albyhub`), `nwc-lnurl`, and `nwc-wallet`.
  albyhub = nwc;
}
