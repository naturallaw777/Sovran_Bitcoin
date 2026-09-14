# Packages vendored by the Sovran Bitcoin flake.
#
# Called via the flake overlay:
#   pkgs.sovran-bitcoin.<name>
#
# btcpayserver and nbxplorer are not built here; the overlay adds the
# versions from the flake's nixpkgs input.
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
