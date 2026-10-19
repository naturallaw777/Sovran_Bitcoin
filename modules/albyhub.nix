# Sovran NWC (`services.albyhub` / `services.sovran-nwc`) — Nix-native
# Nostr Wallet Connect (NIP-47) wallet server for LND.
#
# Powered by `pkgs.sovran-bitcoin.nwc` (`nwc-daemon`), a pure-stdlib Python
# implementation with SQLite sub-wallet isolation, direct LND REST integration,
# always-private route hints, and least-privilege token scopes (`full`,
# `invoice`, `read`).
#
# Both `services.albyhub.*` and `services.sovran-nwc.*` are supported via a
# NixOS option alias for seamless backwards compatibility.
{ config, lib, pkgs, ... }:

with lib;
let
  walletSubmodule = { name, ... }: {
    options = {
      alias = mkOption {
        type = types.str;
        default = name;
        description = ''
          Lightning Address alias (`<alias>@<domain>`) for this sub-wallet.
        '';
      };

      limitSats = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = ''
          Initial funding and spending balance in satoshis.
          When `null` (default), the sub-wallet is created as receive-only.
        '';
      };
    };
  };

  options.services.albyhub = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enable the Sovran NWC wallet server (`nwc-daemon`, LND-only:
        no web UI, loopback bind, always-private route hints, SQLite sub-wallet
        ledger). Wallets connect over Nostr Wallet Connect (NIP-47). Manage
        wallets imperatively with `nwc-wallet` or declaratively via
        {option}`services.albyhub.wallets` / {option}`services.sovran-nwc.wallets`.
      '';
    };

    package = mkOption {
      type = types.package;
      default = pkgs.sovran-bitcoin.nwc;
      defaultText = "pkgs.sovran-bitcoin.nwc";
      description = "The package providing the Sovran NWC daemon (`nwc-daemon`).";
    };

    address = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Address the management API binds to. Keep this on loopback.";
    };

    port = mkOption {
      type = types.port;
      default = 18080;
      description = "Port the management API binds to. Not a web UI.";
    };

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/albyhub";
      description = "Sovran NWC data directory (SQLite ledger + auto-unlock password).";
    };

    relay = mkOption {
      type = types.str;
      default = "wss://relay.getalby.com,wss://relay2.getalby.com";
      description = ''
        Comma-separated Nostr relay(s) used for NWC communication.
        Point this at a self-hosted or `.onion` relay for a fully sovereign setup.
      '';
    };

    wallets = mkOption {
      type = types.attrsOf (types.submodule walletSubmodule);
      default = {};
      example = literalExpression ''
        {
          pocket = {
            alias = "pocket";
            limitSats = 5000;
          };
          tips = {
            alias = "tips";
          };
        }
      '';
      description = ''
        Declarative NWC sub-wallets provisioned idempotently when the service starts.
        For each newly created wallet, its `nostr+walletconnect://` pairing URI is
        written with mode `0600` to `<dataDir>/wallets/<alias>.pairing-uri`.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "albyhub";
      description = "The user as which to run the NWC daemon.";
    };

    group = mkOption {
      type = types.str;
      default = cfg.user;
      description = "The group as which to run the NWC daemon.";
    };
  };

  cfg = config.services.albyhub;
  nbLib = config.nix-bitcoin.lib;

  lndRpcAddress = config.services.lnd.rpcAddress;
  lndRpcPort = config.services.lnd.rpcPort;
  lndRestAddress = config.services.lnd.restAddress;
  lndRestPort = config.services.lnd.restPort;
  lndCertPath = config.services.lnd.certPath;

  albyhubWrapper = pkgs.writeShellScript "nwc-daemon-wrapper" ''
    set -euo pipefail
    password_file="${cfg.dataDir}/unlock-password"
    if [ ! -s "$password_file" ]; then
      umask 077
      ${pkgs.openssl}/bin/openssl rand -hex 32 > "$password_file"
    fi
    export AUTO_UNLOCK_PASSWORD="$(cat "$password_file")"
    exec ${cfg.package}/bin/nwc-daemon
  '';

  # ── LNURL domain env for the CLI wrapper ────────────────────────
  lnurlCfg = config.services.sovran-lnurl or {};
  lnurlEnabled = (lnurlCfg.enable or false);
  lnurlDomainExport =
    if lnurlEnabled && (lnurlCfg.domain or null) != null then
      "export NWC_LNURL_DOMAIN='${lnurlCfg.domain}'"
    else if lnurlEnabled && (lnurlCfg.domainFile or null) != null then
      "export NWC_LNURL_DOMAIN_FILE='${toString lnurlCfg.domainFile}'"
    else
      "# LNURL domain not configured at build time";

  # CLI wallet manager with the right env baked in (`full` admin permission).
  wrappedNwcWallet = lib.hiPrio (pkgs.writeShellScriptBin "nwc-wallet" ''
    export NWC_ALBY_HUB_API_BASE='http://${cfg.address}:${toString cfg.port}'
    export NWC_LND_ADDRESS='${lndRpcAddress}:${toString lndRpcPort}'
    export NWC_LND_REST_ADDRESS='${lndRestAddress}:${toString lndRestPort}'
    export NWC_LND_CERT_FILE='${lndCertPath}'
    export NWC_LND_MACAROON_FILE='/run/lnd/albyhub.macaroon'
    export NWC_UNLOCK_PASSWORD_FILE='${cfg.dataDir}/unlock-password'
    export NWC_HUB_PERMISSION='full'
    export NWC_RELAY='${cfg.relay}'
    ${lnurlDomainExport}
    exec ${cfg.package}/bin/nwc-wallet "$@"
  '');

  # Declarative wallet provisioning script (runs idempotently in ExecStartPost).
  provisionWalletsScript = pkgs.writeShellScript "nwc-provision-wallets" ''
    set -euo pipefail
    mkdir -p "${cfg.dataDir}/wallets"
    chmod 0700 "${cfg.dataDir}/wallets"
    ${concatStringsSep "\n" (mapAttrsToList (name: w:
      let
        modeFlag =
          if w.limitSats != null
          then "--limit-sats ${toString w.limitSats}"
          else "--receive-only";
      in ''
        if ! ${wrappedNwcWallet}/bin/nwc-wallet list | ${pkgs.jq}/bin/jq -e --arg alias ${escapeShellArg w.alias} '.wallets[] | select(.alias == $alias)' >/dev/null 2>&1; then
          umask 077
          out="$(${wrappedNwcWallet}/bin/nwc-wallet create ${escapeShellArg name} ${escapeShellArg w.alias} ${modeFlag})"
          printf '%s\n' "$out" | ${pkgs.jq}/bin/jq -r '.pairing_uri' > "${cfg.dataDir}/wallets/${w.alias}.pairing-uri"
        fi
      ''
    ) cfg.wallets)}
  '';
in {
  imports = [
    (mkAliasOptionModule [ "services" "sovran-nwc" ] [ "services" "albyhub" ])
  ];

  inherit options;

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.lnd.enable;
        message = "Sovran NWC requires services.lnd.enable = true.";
      }
      {
        assertion = !(lib.attrByPath [ "nix-bitcoin" "netns-isolation" "enable" ] false config);
        message = "Sovran NWC requires nix-bitcoin.netns-isolation.enable = false.";
      }
      {
        assertion = cfg.port != config.services.lnd.restPort;
        message = "Sovran NWC and LND REST must use different ports.";
      }
      {
        assertion = cfg.port != 8181;
        message = "Sovran NWC and the LNURL service must use different ports.";
      }
      {
        assertion = !(lib.elem cfg.port config.networking.firewall.allowedTCPPorts);
        message = "Sovran NWC management port must not be opened on the public TCP firewall.";
      }
    ];

    users.groups.${cfg.group} = { };
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.dataDir;
      createHome = false;
    };

    systemd.tmpfiles.rules = [
      "d '${cfg.dataDir}' 0700 ${cfg.user} ${cfg.group} - -"
    ];

    environment.systemPackages = [ wrappedNwcWallet ];

    services.lnd.macaroons.albyhub = {
      user = cfg.user;
      permissions = lib.concatStringsSep "," [
        ''{"entity":"info","action":"read"}''
        ''{"entity":"offchain","action":"read"}''
        ''{"entity":"offchain","action":"write"}''
        ''{"entity":"invoices","action":"read"}''
        ''{"entity":"invoices","action":"write"}''
      ];
    };

    systemd.services.albyhub = {
      description = "Sovran NWC — Nostr Wallet Connect server for LND";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "lnd.service" ];
      requires = [ "lnd.service" ];

      environment = {
        HOME = cfg.dataDir;
        WORK_DIR = cfg.dataDir;
        DATABASE_URI = "${cfg.dataDir}/nwc.db";
        HOST = cfg.address;
        PORT = toString cfg.port;
        LND_ADDRESS = "${lndRpcAddress}:${toString lndRpcPort}";
        LND_REST_ADDRESS = "${lndRestAddress}:${toString lndRestPort}";
        LND_CERT_FILE = lndCertPath;
        LND_MACAROON_FILE = "/run/lnd/albyhub.macaroon";
        RELAY = cfg.relay;
      } // optionalAttrs config.services.tor.client.enable {
        NWC_TOR_SOCKS_PROXY = config.nix-bitcoin.torClientAddressWithPort;
        # The default public relays use wss://, but defaultHardening blocks
        # direct egress. Route those clearnet relay connections through Tor too.
        NWC_FORCE_TOR_RELAY = "1";
      };

      serviceConfig = nbLib.defaultHardening // {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        WorkingDirectory = cfg.dataDir;
        ExecStart = albyhubWrapper;
        ExecStartPost = optional (cfg.wallets != {}) provisionWalletsScript;
        Restart = "on-failure";
        RestartSec = "10s";
        UMask = "0077";
        NoNewPrivileges = true;
        # The local CLI, LND REST API, and Tor SOCKS proxy all use loopback.
        # Keep defaultHardening's IPAddressDeny=any for every non-loopback address.
        IPAddressAllow = [ "127.0.0.1/32" "::1/128" ];
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.dataDir ];
        ReadOnlyPaths = [ lndCertPath "/run/lnd" ];
      };
    };
  };
}
