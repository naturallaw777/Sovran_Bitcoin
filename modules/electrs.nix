{ config, lib, pkgs, ... }:

with lib;
let
  options.services.electrs = {
    enable = mkEnableOption "electrs, an Electrum server implemented in Rust";
    address = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Address to listen for RPC connections.";
    };
    port = mkOption {
      type = types.port;
      default = 50001;
      description = "Port to listen for RPC connections.";
    };
    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/electrs";
      description = "The data directory for electrs.";
    };
    monitoringPort = mkOption {
      type = types.port;
      default = 4224;
      description = "Prometheus monitoring port.";
    };
    extraArgs = mkOption {
      type = types.separatedString " ";
      default = "";
      description = "Extra command line arguments passed to electrs.";
    };
    user = mkOption {
      type = types.str;
      default = "electrs";
      description = "The user as which to run electrs.";
    };
    group = mkOption {
      type = types.str;
      default = cfg.user;
      description = "The group as which to run electrs.";
    };
    tor.enforce = nbLib.tor.enforce;
  };

  cfg = config.services.electrs;
  nbLib = config.nix-bitcoin.lib;
  secretsDir = config.nix-bitcoin.secretsDir;
  bitcoind = config.services.bitcoind;
in {
  inherit options;

  config = mkIf cfg.enable {
    assertions = [
      { assertion = bitcoind.prune == 0;
        message = "electrs does not support bitcoind pruning.";
      }
    ];

    services.bitcoind = {
      enable = true;
      rest = true;
    };

    systemd.tmpfiles.rules = [
      "d '${cfg.dataDir}' 0770 ${cfg.user} ${cfg.group} - -"
    ];

    systemd.services.electrs = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "bitcoind.service" ];
      after = [ "bitcoind.service" "nix-bitcoin-secrets.target" ];
      preStart = ''
        echo "auth = \"${bitcoind.rpc.users.public.name}:$(cat ${secretsDir}/bitcoin-rpcpassword-public)\"" \
          > electrs.toml

        # electrs 0.12.0 switched to bindex (format v1) and panics on startup
        # if a pre-0.12.0 (format v0 / FixedPrefix.8) RocksDB store is present.
        dbNetDir='${cfg.dataDir}/${bitcoind.makeNetworkName "bitcoin" "regtest"}'
        if [[ -d "$dbNetDir" ]] && grep -q 'prefix_extractor=rocksdb\.FixedPrefix\.8' "$dbNetDir"/OPTIONS-* 2>/dev/null; then
          echo "electrs: removing pre-0.12.0 database at $dbNetDir for bindex 0.12.0 reindex"
          rm -rf "$dbNetDir"
        fi
        '';
      serviceConfig = nbLib.defaultHardening // {
        # electrs only uses the working directory for reading electrs.toml
        WorkingDirectory = cfg.dataDir;
        ExecStart = ''
          ${pkgs.electrs}/bin/electrs \
          --log-filters=INFO \
          --network=${bitcoind.makeNetworkName "bitcoin" "regtest"} \
          --db-dir='${cfg.dataDir}' \
          --daemon-dir='${bitcoind.dataDir}' \
          --electrum-rpc-addr=${cfg.address}:${toString cfg.port} \
          --monitoring-addr=${cfg.address}:${toString cfg.monitoringPort} \
          --daemon-rpc-addr=${nbLib.addressWithPort bitcoind.rpc.address bitcoind.rpc.port} \
          ${cfg.extraArgs}
        '';
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        RestartSec = "10s";
        ReadWritePaths = [ cfg.dataDir ];
        # RocksDB (with max_open_files = -1, the upstream default) keeps one
        # open file descriptor per .sst file in the index. The electrs 0.12
        # (bindex) mainnet index runs to thousands of .sst files (7,873 at the
        # time of writing), while systemd's default soft NOFILE limit is 1024.
        # Under that default, descriptor exhaustion makes
        # `blockchain.scripthash.subscribe` fail ("Too many open files"), which
        # aborts every Sparrow/Electrum wallet load with
        # "Failed to subscribe to paths". 65536 comfortably covers the SST
        # files plus sockets, threads and RPC connections. mkForce so no module
        # default can silently win. Runtime-only: no reindex, and it takes
        # effect on the next service restart.
        LimitNOFILE = lib.mkForce 65536;
      } // nbLib.allowedIPAddresses cfg.tor.enforce;
    };

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      extraGroups = [ "bitcoinrpc-public" ];
    };
    users.groups.${cfg.group} = {};
  };
}
