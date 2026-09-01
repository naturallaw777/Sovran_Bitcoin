# Self-hosted LNURL-pay service (Lightning Addresses) backed by Alby Hub.
#
# Decoupled from Sovran_SystemsOS' `modules/nwc-wallets.nix`. The service is
# pure-stdlib Python (`packages/sovran-nwc`) and runs as the albyhub user.
#
# It serves, on 127.0.0.1:8181 by default:
#   GET /.well-known/lnurlp/{alias}
#   GET /lnurlp/{alias}/callback?amount=<msat>
#
# For public Lightning Addresses, point your webserver's
# `lightning-domain.example` at this port (proxy /.well-known/lnurlp and
# /lnurlp). The webserver/TLS is deliberately NOT handled by this flake.
{ config, lib, pkgs, ... }:

with lib;
let
  options.services.sovran-lnurl = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enable the Sovran LNURL-pay service: self-hosted Lightning Addresses
        (`alias@domain`) backed by NWC wallets managed through Alby Hub.
        Requires `services.albyhub.enable = true`.
      '';
    };

    package = mkOption {
      type = types.package;
      default = pkgs.sovran-bitcoin.nwc;
      defaultText = "pkgs.sovran-bitcoin.nwc";
      description = "The package providing the nwc-lnurl service.";
    };

    address = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Address to bind the LNURL service to. Keep this on loopback; use a reverse proxy for the public domain.";
    };

    port = mkOption {
      type = types.port;
      default = 8181;
      description = "Port to bind the LNURL service to.";
    };

    domain = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "pay.example.com";
      description = ''
        The public Lightning Address domain (the part after the `@`).
        Takes precedence over {option}`domainFile`.
      '';
    };

    domainFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/var/lib/secrets/lightning-domain";
      description = ''
        File containing the public Lightning Address domain, for setups that
        manage domains out-of-band (e.g. DDNS). Read at request time.
      '';
    };
  };

  lnurlCfg = config.services.sovran-lnurl;

  albyhub = config.services.albyhub;
  lndCfg = config.services.lnd;

  # Hardcoded in nwc_audit.py (AUDIT_LOG_PATH = "/var/log/sovran-nwc-audit.log").
  # The service runs as the albyhub user, so the file must exist and be owned
  # by that user before the first request, and must be re-mounted writable
  # inside the sandbox (ProtectSystem = "strict" makes the whole FS read-only).
  auditLogPath = "/var/log/sovran-nwc-audit.log";

  env = {
    NWC_LNURL_BIND_HOST = lnurlCfg.address;
    NWC_LNURL_PORT = toString lnurlCfg.port;
    NWC_ALBY_HUB_API_BASE = "http://${albyhub.address}:${toString albyhub.port}";
    NWC_LND_ADDRESS = "${lndCfg.rpcAddress}:${toString lndCfg.rpcPort}";
    NWC_LND_CERT_FILE = lndCfg.certPath;
    NWC_LND_MACAROON_FILE = "/run/lnd/albyhub.macaroon";
    NWC_RELAY = albyhub.relay;
  };
in {
  inherit options;

  config = mkIf lnurlCfg.enable {
    assertions = [
      {
        assertion = albyhub.enable;
        message = "The LNURL service requires services.albyhub.enable = true.";
      }
      {
        assertion = lnurlCfg.domain != null || lnurlCfg.domainFile != null;
        message = ''
          services.sovran-lnurl: set either `domain` (e.g. "pay.example.com")
          or `domainFile` — Lightning Addresses need a public domain.
        '';
      }
    ];

    # Create the audit log file up front, owned by the albyhub user, so
    # nwc_audit.py can append to it. Without this the first audit write fails
    # with "Errno 30: Read-only file system" and no audit trail is recorded.
    # NixOS runs tmpfiles at activation time, so the file exists immediately
    # after `nixos-rebuild switch` (no reboot needed).
    systemd.tmpfiles.rules = [
      "f ${auditLogPath} 0600 ${albyhub.user} ${albyhub.group} -"
    ];

    systemd.services.nwc-lnurl = {
      description = "Sovran LNURL service — self-hosted Lightning Addresses";
      wantedBy = [ "multi-user.target" ];
      after = [ "albyhub.service" ];
      wants = [ "albyhub.service" ];

      environment = env // {
        NWC_UNLOCK_PASSWORD_FILE = "${albyhub.dataDir}/unlock-password";
      } // (optionalAttrs (lnurlCfg.domain != null) {
        NWC_LNURL_DOMAIN = lnurlCfg.domain;
      }) // (optionalAttrs (lnurlCfg.domainFile != null) {
        NWC_LNURL_DOMAIN_FILE = toString lnurlCfg.domainFile;
      });

      serviceConfig = {
        Type = "simple";
        User = albyhub.user;
        Group = albyhub.group;
        ExecStart = "${lnurlCfg.package}/bin/nwc-lnurl";
        Restart = "on-failure";
        RestartSec = "10s";
        UMask = "0027";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadOnlyPaths = [
          lndCfg.certPath
          "/run/lnd"
          "${albyhub.dataDir}/unlock-password"
        ] ++ optional (lnurlCfg.domainFile != null) (toString lnurlCfg.domainFile);
        # Re-mount the audit log writable inside the sandbox; everything else
        # stays read-only (ProtectSystem = "strict").
        ReadWritePaths = [ auditLogPath ];
      };
    };

    # qrencode is needed for `nwc-wallet lnurl --qr` and `nwc-wallet create --qr`
    # to render terminal QR codes for Lightning Addresses.
    environment.systemPackages = [ pkgs.qrencode ];
  };
}

