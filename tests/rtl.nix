# Config-level assertions for Ride The Lightning.
# The UI is served under /rtl/; `/` is redirected there in the package.
{ nixpkgs, overlay, system ? "x86_64-linux" }:

let
  lib = nixpkgs.lib;
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ overlay ];
    config.allowUnfree = true;
  };

  eval = features: extra:
    (lib.nixosSystem {
      inherit system;
      modules = [
        { nixpkgs.hostPlatform = system; nixpkgs.overlays = [ overlay ]; }
        ../modules
        ../tests/minimal-hardware.nix
        {
          nix-bitcoin.generateSecrets = true;
          nix-bitcoin.secretsDir = "/build/secrets";
          sovran-bitcoin = {
            enable = true;
            features = features;
          };
          services.bitcoind.dataDir = "/build/bitcoind";
          services.lnd.dataDir = "/build/lnd";
          system.stateVersion = "26.05";
        }
        extra
      ];
    }).config;

  cfg = eval { rtl = true; } {};

  json = cfg.services.rtl.configJson;
  node = builtins.head json.nodes;
in
assert lib.assertMsg cfg.services.rtl.enable
  "preset features.rtl must enable services.rtl";
assert lib.assertMsg (cfg.services.rtl.port == 3050)
  "preset must put RTL on 3050";
assert lib.assertMsg (cfg.services.rtl.address == "127.0.0.1")
  "RTL must bind loopback";
assert lib.assertMsg (cfg.systemd.services.rtl.environment.RTL_CONFIG_PATH == "/var/lib/rtl")
  "RTL_CONFIG_PATH must be the data dir";
assert lib.assertMsg (cfg.systemd.services.rtl.serviceConfig.WorkingDirectory == "/var/lib/rtl")
  "WorkingDirectory must be the data dir";
assert lib.assertMsg (json.host == "127.0.0.1" && json.port == 3050)
  "generated config must listen on 127.0.0.1:3050";
assert lib.assertMsg (json.trustedProxies == "127.0.0.1")
  "0.15.12 trustedProxies must be the loopback proxy hop";
assert lib.assertMsg (node ? authentication && !(node ? Authentication))
  "RTL v0.15.8+ schema requires lowercase authentication";
assert lib.assertMsg (node ? settings && !(node ? Settings))
  "RTL v0.15.8+ schema requires lowercase settings";
assert lib.assertMsg (node.lnImplementation == "LND")
  "Sovran RTL is LND-only";
assert lib.assertMsg (lib.hasPrefix "https://127.0.0.1:" node.settings.lnServerUrl)
  "lnServerUrl must target loopback LND REST, not 0.0.0.0";
assert lib.assertMsg (node.authentication.macaroonPath == "/var/lib/rtl/macaroons")
  "macaroonPath must be the copied-macaroon directory";
pkgs.runCommand "sovran-bitcoin-rtl" {} ''
  echo ok > $out
''
