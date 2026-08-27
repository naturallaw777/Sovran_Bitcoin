{ config, pkgs, lib, ... }:

with lib;
{
  options = {
    nix-bitcoin = {
      # Kept for compatibility, now simply aliases system pkgs
      pkgs = mkOption {
        type = types.attrs;
        default = pkgs;
        defaultText = "pkgs";
        description = "Alias to system pkgs (vendored nix-bitcoin now uses nixpkgs directly).";
      };

      useVersionLockedPkgs = mkOption {
        type = types.bool;
        default = false;
        description = "Deprecated — vendored modules always use system pkgs.";
      };

      pkgOverlays = mkOption {
        internal = true;
        type = with types; functionTo attrs;
        default = _: _: {};
        description = "Deprecated stub.";
      };

      lib = mkOption {
        readOnly = true;
        default = import ./lib.nix lib pkgs config;
        defaultText = "vendor/nix-bitcoin/lib.nix";
      };

      torClientAddressWithPort = mkOption {
        readOnly = true;
        default = with config.services.tor.client.socksListenAddress;
          "${addr}:${toString port}";
        defaultText = "(See source)";
      };

      torify = mkOption {
        readOnly = true;
        default = pkgs.writers.writeBashBin "torify" ''
          ${pkgs.tor}/bin/torify \
            --address ${config.services.tor.client.socksListenAddress.addr} \
            "$@"
        '';
        defaultText = "(See source)";
      };

      runAsUserCmd = mkOption {
        readOnly = true;
        default = if config.security.doas.enable
                  then "doas -u"
                  else "sudo -u";
        defaultText = "(See source)";
      };
    };
  };
}
