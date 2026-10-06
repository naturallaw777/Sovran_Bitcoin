# Config-level assertions for the REST and gRPC lndconnect endpoints.
{ nixpkgs, overlay, system ? "x86_64-linux" }:

let
  lib = nixpkgs.lib;
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ overlay ];
    config.allowUnfree = true;
  };

  config = (lib.nixosSystem {
    inherit system;
    modules = [
      { nixpkgs.hostPlatform = system; nixpkgs.overlays = [ overlay ]; }
      ../modules
      ../tests/minimal-hardware.nix
      {
        nix-bitcoin.generateSecrets = true;
        nix-bitcoin.secretsDir = "/build/secrets";
        sovran-bitcoin.enable = true;
        services.bitcoind.dataDir = "/build/bitcoind";
        services.lnd.dataDir = "/build/lnd";
        system.stateVersion = "26.05";
      }
    ];
  }).config;

  grpcOnion = config.services.tor.relay.onionServices.lnd-grpc;
  grpcMap = builtins.head grpcOnion.map;
  packageNames = map (package: package.name or "") config.environment.systemPackages;
in
assert lib.assertMsg config.services.lnd.lndconnect.grpcOnion
  "the Sovran preset must enable the gRPC onion helper";
assert lib.assertMsg (config.services.lnd.rpcAddress == "127.0.0.1"
  && config.services.lnd.rpcPort == 10009)
  "LND gRPC should remain on its default loopback endpoint";
assert lib.assertMsg (grpcMap.port == 10009
  && grpcMap.target.addr == "127.0.0.1"
  && grpcMap.target.port == 10009)
  "the gRPC onion must forward port 10009 to LND on loopback";
assert lib.assertMsg (builtins.elem "lnd-grpc" config.nix-bitcoin.onionAddresses.access.operator)
  "the operator must be able to read the gRPC onion hostname";
assert lib.assertMsg (builtins.elem "lnd-grpc" config.nix-bitcoin.onionAddresses.access.lnd)
  "the lnd user must be able to read the gRPC onion hostname for the QR wrapper";
assert lib.assertMsg (builtins.elem "lndconnect-grpc" packageNames)
  "the lndconnect-grpc QR/URI command must be installed";
assert lib.assertMsg (builtins.elem "lndconnect" packageNames)
  "the existing REST lndconnect command must remain installed";
pkgs.runCommand "sovran-bitcoin-lndconnect" {} ''
  echo ok > $out
''
