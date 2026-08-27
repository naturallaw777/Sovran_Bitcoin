{
  description = "Sovran Bitcoin — an opinionated, Tor-first Bitcoin stack for NixOS (bitcoind, LND, electrs, BTCPay Server, RTL, Mempool, Alby Hub/NWC, LNURL), vendored from Sovran_SystemsOS and nix-bitcoin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # BTCPay Server / NBXplorer are pinned to stable, matching Sovran_SystemsOS.
    # Override these pins by setting services.btcpayserver.package /
    # services.nbxplorer.package in your config.
    nixpkgs-stable.url = "github:nixos/nixpkgs/nixos-26.05";
  };

  outputs = { self, nixpkgs, nixpkgs-stable, ... }:

  let
    lib = nixpkgs.lib;
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = f: lib.genAttrs systems (system: f system);

    pkgsFor = system: import nixpkgs {
      inherit system;
      config.allowUnfree = true;
    };

    stableFor = system: import nixpkgs-stable {
      inherit system;
      config.allowUnfree = true;
    };

    # The single overlay consumed by the NixOS module (auto-applied on import)
    # and available as `overlays.default` for manual use.
    overlay = final: prev: {
      sovran-bitcoin = prev.callPackage ./packages { } // {
        # Pinned exactly like Sovran_SystemsOS (nixos-26.05).
        inherit (stableFor prev.stdenv.hostPlatform.system)
          nbxplorer
          btcpayserver;
      };
    };

    # A NixOS configuration used by `checks` and as a runnable demo:
    #   nix build .#nixosConfigurations.demo.config.system.build.vm
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
        # (rtl, mempool, albyhub, pinned btcpayserver/nbxplorer) resolve.
        # Import `overlays.default` yourself instead if you prefer.
        nixpkgs.overlays = [ overlay ];
        imports = [ ./modules ];
      };
      default = self.nixosModules.sovran-bitcoin;
    };

    nixosConfigurations.demo = demoSystem "x86_64-linux";

    checks = forAllSystems (system:
      let
        pkgs = pkgsFor system;
      in
      {
        # Full evaluation of the demo system (all features enabled).
        # Instantiating the toplevel drvPath forces the whole module eval.
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
      });
  };
}
