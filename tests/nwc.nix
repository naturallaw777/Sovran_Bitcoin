# Config-level assertions for the Nix-native Sovran NWC daemon + LNURL service.
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

  cfg = eval { nwc = true; lnurl = true; } {
    services.sovran-lnurl.domain = "pay.example.com";
    services.sovran-nwc.wallets.pocket = {
      alias = "pocket";
      limitSats = 5000;
    };
  };

  nwcUnit = cfg.systemd.services.albyhub;
  lnurlUnit = cfg.systemd.services.nwc-lnurl;
in
assert lib.assertMsg cfg.services.albyhub.enable
  "preset features.nwc must enable services.albyhub";
assert lib.assertMsg (cfg.services.albyhub.address == "127.0.0.1" && cfg.services.albyhub.port == 18080)
  "Sovran NWC daemon must bind loopback 127.0.0.1:18080 by default";
assert lib.assertMsg (pkgs.sovran-bitcoin.albyhub == pkgs.sovran-bitcoin.nwc)
  "albyhub package must resolve to the native sovran-nwc package";
assert lib.assertMsg (nwcUnit.environment.LND_REST_ADDRESS == "127.0.0.1:8080")
  "Sovran NWC must connect to loopback LND REST on 127.0.0.1:8080";
assert lib.assertMsg (nwcUnit.environment ? NWC_TOR_SOCKS_PROXY)
  "Sovran NWC must receive NWC_TOR_SOCKS_PROXY when Tor client is enabled";
assert lib.assertMsg (nwcUnit.environment.NWC_FORCE_TOR_RELAY == "1")
  "Sovran NWC must route clearnet relay connections through Tor when the Tor client is enabled";
assert lib.assertMsg (nwcUnit.serviceConfig.ProtectSystem == "strict" && nwcUnit.serviceConfig.NoNewPrivileges)
  "Sovran NWC unit must run with nix-bitcoin systemd hardening";
assert lib.assertMsg (nwcUnit.serviceConfig.IPAddressDeny == "any"
  && builtins.elem "127.0.0.1/32" nwcUnit.serviceConfig.IPAddressAllow
  && builtins.elem "::1/128" nwcUnit.serviceConfig.IPAddressAllow)
  "Sovran NWC must retain deny-by-default networking while permitting loopback API, LND REST, and Tor SOCKS traffic";
assert lib.assertMsg (cfg.services.albyhub.wallets ? pocket && cfg.services.albyhub.wallets.pocket.limitSats == 5000)
  "services.sovran-nwc.wallets alias must populate declarative sub-wallets";
assert lib.assertMsg (builtins.length nwcUnit.serviceConfig.ExecStartPost == 1)
  "declarative wallets must attach the ExecStartPost provisioning script";
assert lib.assertMsg (lnurlUnit.environment.NWC_HUB_PERMISSION == "invoice")
  "nwc-lnurl must use the least-privilege 'invoice' token scope, not 'full'";
pkgs.runCommand "sovran-bitcoin-nwc" {} ''
  echo ok > $out
''
