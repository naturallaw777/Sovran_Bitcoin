# Alby Hub — NWC (Nostr Wallet Connect) wallet server, LND-only.
#
# Decoupled from Sovran_SystemsOS' `modules/nwc-wallets.nix`:
#   - no dependency on the Sovran Hub web app or sovran_systemsOS options
#   - relay configurable (`services.albyhub.relay`)
#   - dataDir configurable
#
# The management UI binds to 127.0.0.1 only. Expose it via SSH tunnel,
# a reverse proxy, or an onion service of your choice.
{ config, lib, pkgs, ... }:

with lib;
let
  options.services.albyhub = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enable Alby Hub, a self-hosted NWC wallet server (Sovran's LND-only fork:
        no built-in frontend, loopback bind, always-private route hints).
        Wallets connect over Nostr Wallet Connect; manage the hub at
        {option}`services.albyhub.address`:{option}`services.albyhub.port`.
      '';
    };

    package = mkOption {
      type = types.package;
      default = pkgs.sovran-bitcoin.albyhub;
      defaultText = "pkgs.sovran-bitcoin.albyhub";
      description = "The package providing Alby Hub.";
    };

    address = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Address the management API/UI binds to. Keep this on loopback.";
    };

    port = mkOption {
      type = types.port;
      default = 18080;
      description = "Port the management API/UI binds to.";
    };

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/albyhub";
      description = "Alby Hub data directory (hub database + auto-unlock password).";
    };

    relay = mkOption {
      type = types.str;
        default = "wss://relay.getalby.com,wss://relay2.getalby.com";
      description = ''
        Comma-separated Nostr relay(s) used for NWC communication.
        Point this at a self-hosted relay for a fully sovereign setup.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "albyhub";
      description = "The user as which to run Alby Hub.";
    };

    group = mkOption {
      type = types.str;
      default = cfg.user;
      description = "The group as which to run Alby Hub.";
    };
  };

  cfg = config.services.albyhub;

  lndRpcAddress = config.services.lnd.rpcAddress;
  lndRpcPort = config.services.lnd.rpcPort;
  lndCertPath = config.services.lnd.certPath;

  albyhubWrapper = pkgs.writeShellScript "albyhub-wrapper" ''
    set -euo pipefail
    password_file="${cfg.dataDir}/unlock-password"
    if [ ! -s "$password_file" ]; then
      umask 077
      ${pkgs.openssl}/bin/openssl rand -hex 32 > "$password_file"
    fi
    export AUTO_UNLOCK_PASSWORD="$(cat "$password_file")"
    exec ${lib.getExe cfg.package}
  '';

  # ── LNURL domain env for the CLI wrapper ────────────────────────
  # When the LNURL service is enabled, bake the Lightning Address domain
  # into the nwc-wallet wrapper so the CLI can construct addresses and
  # QR codes without requiring the caller to set env vars manually.
  lnurlCfg = config.services.sovran-lnurl or {};
  lnurlEnabled = (lnurlCfg.enable or false);
  lnurlDomainExport =
    if lnurlEnabled && (lnurlCfg.domain or null) != null then
      "export NWC_LNURL_DOMAIN='${lnurlCfg.domain}'"
    else if lnurlEnabled && (lnurlCfg.domainFile or null) != null then
      "export NWC_LNURL_DOMAIN_FILE='${toString lnurlCfg.domainFile}'"
    else
      "# LNURL domain not configured at build time";

  # CLI wallet manager with the right env baked in.
  # Note: needs root/operator rights to read the unlock password and macaroon.
  wrappedNwcWallet = lib.hiPrio (pkgs.writeShellScriptBin "nwc-wallet" ''
    export NWC_ALBY_HUB_API_BASE='http://${cfg.address}:${toString cfg.port}'
    export NWC_LND_ADDRESS='${lndRpcAddress}:${toString lndRpcPort}'
    export NWC_LND_CERT_FILE='${lndCertPath}'
    export NWC_LND_MACAROON_FILE='/run/lnd/albyhub.macaroon'
    export NWC_UNLOCK_PASSWORD_FILE='${cfg.dataDir}/unlock-password'
    export NWC_RELAY='${cfg.relay}'
    ${lnurlDomainExport}
    exec ${pkgs.sovran-bitcoin.nwc}/bin/nwc-wallet "$@"
  '');
in {
  inherit options;

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.lnd.enable;
        message = "Alby Hub (NWC) requires services.lnd.enable = true.";
      }
      {
        assertion = !(lib.attrByPath [ "nix-bitcoin" "netns-isolation" "enable" ] false config);
        message = "Alby Hub (NWC) requires nix-bitcoin.netns-isolation.enable = false.";
      }
      {
        assertion = cfg.port != config.services.lnd.restPort;
        message = "Alby Hub and LND REST must use different ports.";
      }
      {
        assertion = cfg.port != 8181;
        message = "Alby Hub and the LNURL service must use different ports.";
      }
      {
        assertion = !(lib.elem cfg.port config.networking.firewall.allowedTCPPorts);
        message = "Alby Hub management port must not be opened on the public TCP firewall.";
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
        ''{"entity":"onchain","action":"read"}''
        ''{"entity":"address","action":"read"}''
        ''{"entity":"message","action":"read"}''
        ''{"entity":"message","action":"write"}''
      ];
    };

    systemd.services.albyhub = {
      description = "Alby Hub — NWC wallet server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "lnd.service" ];
      requires = [ "lnd.service" ];

      environment = {
        HOME = cfg.dataDir;
        WORK_DIR = cfg.dataDir;
        DATABASE_URI = "${cfg.dataDir}/nwc.db";
        HOST = cfg.address;
        PORT = toString cfg.port;
        LN_BACKEND_TYPE = "LND";
        ENABLE_ADVANCED_SETUP = "false";
        LND_ADDRESS = "${lndRpcAddress}:${toString lndRpcPort}";
        LND_CERT_FILE = lndCertPath;
        LND_MACAROON_FILE = "/run/lnd/albyhub.macaroon";
        RELAY = cfg.relay;
        AUTO_LINK_ALBY_ACCOUNT = "false";
        SEND_EVENTS_TO_ALBY = "false";
        LOG_TO_FILE = "false";
        HIDE_UPDATE_BANNER = "true";
      };

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        WorkingDirectory = cfg.dataDir;
        ExecStart = albyhubWrapper;
        Restart = "on-failure";
        RestartSec = "10s";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.dataDir ];
        ReadOnlyPaths = [ lndCertPath "/run/lnd" ];
      };
    };
  };
}
