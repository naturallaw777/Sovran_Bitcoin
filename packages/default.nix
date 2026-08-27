# Packages vendored by the Sovran Bitcoin flake.
#
# Called via the flake overlay:
#   pkgs.sovran-bitcoin.<name>
#
# btcpayserver and nbxplorer are NOT built here — the overlay adds them,
# pinned to the flake's nixos-26.05 input (matching Sovran_SystemsOS).
{ lib
, callPackage
, ...
}:

let
  fetchNodeModules = callPackage ./build-support/fetch-node-modules.nix { };
  mempool = callPackage ./mempool { inherit fetchNodeModules; };
in
{
  inherit fetchNodeModules;

  rtl = callPackage ./rtl { inherit fetchNodeModules; };

  inherit (mempool)
    mempool-backend
    mempool-frontend
    mempool-nginx-conf;

  albyhub = callPackage ./albyhub { };

  nwc = callPackage ./sovran-nwc { };
}
