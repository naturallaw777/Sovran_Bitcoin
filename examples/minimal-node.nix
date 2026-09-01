# Example: a plain, opinionated Sovran Bitcoin node.
#
# bitcoind (txindex, Tor-proxied & enforced) + electrs + LND,
# onion services, generated secrets, operator user, nodeinfo, lndconnect.
{ config, pkgs, lib, ... }:

{
  # Add to your flake inputs:
  #   inputs.sovran-bitcoin.url = "git+https://git.sovransystems.com/Sovran_Systems/Sovran_Bitcoin";
  # and import the module:
  #   imports = [ inputs.sovran-bitcoin.nixosModules.default ];
  #
  # Then, in your NixOS configuration:

  sovran-bitcoin = {
    enable = true;
    operatorName = "myuser"; # your interactive user, gets bitcoin-cli/lncli access
    bitcoindTorGossip = false; # don't gossip the onion address (default)
  };

  # Everything stays overridable through the plain nix-bitcoin-style options:
  # services.bitcoind.prune = 10000;
  # services.bitcoind.dbCache = 2000;
  # services.lnd.extraConfig = "...";
}
