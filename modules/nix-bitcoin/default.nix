# Common Bitcoin infrastructure: secrets, onion services, nodeinfo, security.
# Extracted from nix-bitcoin, tailored for Sovran (lnd-only).
{ config, lib, pkgs, ... }:
{
  imports = [
    ./nix-bitcoin.nix
    ./secrets/secrets.nix
    ./operator.nix
    ./security.nix
    ./onion-addresses.nix
    ./onion-services.nix
    ./nodeinfo.nix
    ./versioning.nix
  ];
}
