{
  description = "Sovran Bitcoin — an opinionated, Tor-first Bitcoin stack for NixOS (bitcoind, LND, electrs, BTCPay Server, RTL, Mempool, Alby Hub/NWC, LNURL), vendored from Sovran_SystemsOS and nix-bitcoin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:

  let
    lib = nixpkgs.lib;
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = f: lib.genAttrs systems (system: f system);

    pkgsFor = system: import nixpkgs {
      inherit system;
      config.allowUnfree = true;
    };

    # The single overlay consumed by the NixOS module (auto-applied on import)
    # and available as `overlays.default` for manual use.
    overlay = final: prev: {
      sovran-bitcoin = prev.callPackage ./packages { };
    };

    # Full-stack regtest configuration used by the evaluation check below.
    demoSystem = system: lib.nixosSystem {
      inherit system;
      modules = [
        self.nixosModules.sovran-bitcoin
        ./tests/demo.nix
      ];
    };
  in
  {
    overlays = {
      default = overlay;
      sovran-bitcoin = overlay;
    };

    packages = forAllSystems (system:
      let
        pkgs = pkgsFor system;
        sovranBitcoin = pkgs.callPackage ./packages { };
      in
      {
        default = sovranBitcoin.rtl;
        rtl = sovranBitcoin.rtl;
        mempool-backend = sovranBitcoin.mempool-backend;
        mempool-frontend = sovranBitcoin.mempool-frontend;
        albyhub = sovranBitcoin.albyhub;
        nwc = sovranBitcoin.nwc;
      }
    );

    nixosModules = {
      sovran-bitcoin = {
        # The module auto-applies the flake overlay so vendored packages
        # (rtl, mempool, albyhub, nwc, BTCPay Server and NBXplorer) resolve.
        # Import `overlays.default` yourself instead if you prefer.
        nixpkgs.overlays = [ overlay ];
        imports = [ ./modules ];
      };
      default = self.nixosModules.sovran-bitcoin;
    };

    checks = forAllSystems (system:
      let
        pkgs = pkgsFor system;
      in
      {
        # Full-stack regtest configuration evaluation.
        demo-system-eval = pkgs.runCommand "sovran-bitcoin-demo-eval" {
          drvPath = (demoSystem system).config.system.build.toplevel.drvPath;
        } "echo ok > $out";

        # Evaluation with only the base node enabled.
        base-node-eval = pkgs.runCommand "sovran-bitcoin-base-eval" {
          drvPath = (lib.nixosSystem {
            inherit system;
            modules = [
              self.nixosModules.sovran-bitcoin
              ./tests/minimal-hardware.nix
              {
                sovran-bitcoin.enable = true;
                system.stateVersion = "26.05";
                services.bitcoind.dataDir = "/build/bitcoind";
              }
            ];
          }).config.system.build.toplevel.drvPath;
        } "echo ok > $out";

        # Config-level hardening assertions for BTCPay + bitcoind,
        # adapted from Sovran_SystemsOS.
        bitcoin-btcpay-hardening = import ./tests/bitcoin-btcpay-hardening.nix {
          inherit system;
          inherit nixpkgs;
          inherit overlay;
        };

        # RTL schema + loopback listen (UI is served under /rtl/).
        rtl = import ./tests/rtl.nix {
          inherit system;
          inherit nixpkgs;
          inherit overlay;
        };
      });
  };
}
