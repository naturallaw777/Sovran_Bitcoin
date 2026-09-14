# Demo NixOS configuration — the full Sovran Bitcoin stack on regtest.
#
# Used by the full-stack evaluation check in `flake.nix`.
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

  users.users.root.password = "demo";
  services.getty.autologinUser = lib.mkDefault "root";

  system.stateVersion = "26.05";
}
