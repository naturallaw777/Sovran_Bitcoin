{ config, lib, ... }:
with lib;
let
  options.nix-bitcoin.configVersion = mkOption {
    type = with types; nullOr str;
    default = null;
    description = "Vendored stub — no version migration needed.";
  };
in {
  inherit options;
  config = {};
}
