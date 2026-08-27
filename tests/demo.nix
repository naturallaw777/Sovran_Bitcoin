# Demo NixOS configuration — the full Sovran Bitcoin stack on regtest.
#
# Used by `checks` (evaluation) and runnable as a VM:
#   nix run .#nixosConfigurations.demo.config.system.build.vm
#
# regtest is used so the VM never touches mainnet. Flip
# `services.bitcoind.regtest` to false for a mainnet box.
{ lib, ... }:

{
  imports = [ ./minimal-hardware.nix ];

  sovran-bitcoin = {
    enable = true;
    operatorName = "operator";
    features = {
      electrs = true;
      lnd = true;
      rtl = true;
      btcpayserver = true;
      mempool = true;
      nwc = true;
      lnurl = true;
    };
  };

  # Lightning Addresses need a public domain — example only.
  services.sovran-lnurl.domain = "pay.example.com";

  services.bitcoind = {
    regtest = lib.mkDefault true;
    dataDir = "/var/lib/bitcoind";
  };

  # Demo VM ergonomics
  users.users.root.password = "demo";
  services.getty.autologinUser = lib.mkDefault "root";
  # When running as a VM you can add e.g.:
  #   virtualisation.memorySize = 4096;

  system.stateVersion = "26.05";
}
