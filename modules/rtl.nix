{ config, lib, pkgs, ... }:

with lib;
let
  options.services.rtl = {
    enable = mkEnableOption "RTL, a web interface for LND";

    address = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Address to listen for HTTP connections.";
    };

    port = mkOption {
      type = types.port;
      default = 3000;
      description = "Port to listen for HTTP connections.";
    };

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/rtl";
      description = "The data directory for RTL.";
    };

    nightTheme = mkOption {
      type = types.bool;
      default = false;
      description = "Enable night theme by default.";
    };

    extraCurrency = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "USD";
      description = ''
        Additional currency for displaying amounts.
        When set, Tor is disabled for the RTL service to allow currency rate fetching.
      '';
    };

    nodes = {
      lnd = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = "Enable LND node in RTL.";
        };
        loop = mkOption {
          type = types.bool;
          default = false;
          description = "Enable Lightning Loop integration (requires loopd).";
        };
      };
      clightning = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = "Enable Core Lightning node in RTL (not supported in Sovran).";
        };
      };
    };

    user = mkOption {
      type = types.str;
      default = "rtl";
      description = "The user as which to run RTL.";
    };

    group = mkOption {
      type = types.str;
      default = cfg.user;
      description = "The group as which to run RTL.";
    };

    package = mkOption {
      type = types.package;
      default = pkgs.sovran-bitcoin.rtl;
      defaultText = "pkgs.sovran-bitcoin.rtl";
      description = "The package providing RTL (vendored, pinned by the Sovran Bitcoin flake).";
    };

    tor = nbLib.tor;
  };

  cfg = config.services.rtl;
  nbLib = config.nix-bitcoin.lib;
  secretsDir = config.nix-bitcoin.secretsDir;

  runePath = "${cfg.dataDir}/CLN-Rune.env";

  rtlConfig = {
    multiPass = "@multiPass@";
    port = cfg.port;
    host = cfg.address;
    defaultNodeIndex = 1;
    dbDirectoryPath = cfg.dataDir;
    SSO = {
      rtlSSO = 0;
      rtlCookiePath = "";
      logoutRedirectLink = "";
    };
    nodes = optional cfg.nodes.lnd.enable ({
      index = 1;
      lnNode = "lnd";
      lnImplementation = "LND";
      authentication = {
        macaroonPath = "${cfg.dataDir}/macaroons";
        swapMacaroonPath = if cfg.nodes.lnd.loop then "${cfg.dataDir}/loop-macaroons" else "";
        boltzMacaroonPath = "";
      };
      settings = {
        userPersona = "OPERATOR";
        themeMode = if cfg.nightTheme then "NIGHT" else "DAY";
        themeColor = "PURPLE";
        channelBackupPath = "${cfg.dataDir}/backup";
        logLevel = "INFO";
        lnServerUrl = "https://${lnd.restAddress}:${toString lnd.restPort}";
        swapServerUrl = if cfg.nodes.lnd.loop then "https://127.0.0.1:8081" else "";
        boltzServerUrl = "";
        fiatConversion = cfg.extraCurrency != null;
        unannouncedChannels = true;
      } // optionalAttrs (cfg.extraCurrency != null) {
        currencyUnit = cfg.extraCurrency;
      };
    }) ++ optional cfg.nodes.clightning.enable {
      index = 2;
      lnNode = "clightning";
      lnImplementation = "CLN";
      authentication = {
        runePath = runePath;
      };
      settings = {
        userPersona = "OPERATOR";
        themeMode = if cfg.nightTheme then "NIGHT" else "DAY";
        themeColor = "PURPLE";
        logLevel = "INFO";
        fiatConversion = cfg.extraCurrency != null;
      } // optionalAttrs (cfg.extraCurrency != null) {
        currencyUnit = cfg.extraCurrency;
      };
    };
  };

  configFile = builtins.toFile "config" (builtins.toJSON rtlConfig);

  inherit (config.services)
    bitcoind
    lnd;

  lndLoopEnabled = cfg.nodes.lnd.enable && cfg.nodes.lnd.loop;
in {
  inherit options;

  config = mkIf cfg.enable {
    assertions = [
      { assertion = cfg.nodes.lnd.enable;
        message = ''
          RTL: At least one node must be enabled. Sovran supports LND only.
        '';
      }
      { assertion = !cfg.nodes.clightning.enable;
        message = ''
          RTL: Core Lightning (clightning) is not supported in Sovran. Use LND instead.
        '';
      }
    ];

    services.lnd.enable = mkIf cfg.nodes.lnd.enable true;

    systemd.tmpfiles.rules = [
      "d '${cfg.dataDir}' 0770 ${cfg.user} ${cfg.group} - -"
    ];

    services.rtl.tor.enforce = mkIf (cfg.extraCurrency != null) false;

    systemd.services.rtl = rec {
      wantedBy = [ "multi-user.target" ];
      wants = optional cfg.nodes.lnd.enable "lnd.service";
      after = wants ++ [ "nix-bitcoin-secrets.target" ];
      environment.RTL_CONFIG_PATH = cfg.dataDir;
      environment.DB_DIRECTORY_PATH = cfg.dataDir;
      serviceConfig = nbLib.defaultHardening // {
        ExecStartPre = [
          (nbLib.script "rtl-setup-config" ''
            <${configFile} sed "s|@multiPass@|$(cat ${secretsDir}/rtl-password)|" \
              > '${cfg.dataDir}/RTL-Config.json'
          '')
        ]
        ++ optional cfg.nodes.lnd.enable
          # The lnd admin macaroon is not readable by group `lnd`, so copy it
          (nbLib.rootScript "rtl-copy-macaroon" ''
            install --compare -m 640 -o ${cfg.user} -g ${cfg.group} -D ${lnd.networkDir}/admin.macaroon \
              '${cfg.dataDir}/macaroons/admin.macaroon'
          '');
        ExecStart = "${cfg.package}/bin/rtl";
        # Show "rtl" instead of "node" in the journal
        SyslogIdentifier = "rtl";
        User = cfg.user;
        Restart = "on-failure";
        RestartSec = "10s";
        ReadWritePaths = [ cfg.dataDir ];
      } // nbLib.allowedIPAddresses cfg.tor.enforce
        // nbLib.nodejs;
    };

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      extraGroups = optional lndLoopEnabled lnd.group;
    };
    users.groups.${cfg.group} = {};

    nix-bitcoin.secrets.rtl-password.user = cfg.user;
    nix-bitcoin.generateSecretsCmds.rtl = ''
      makePasswordSecret rtl-password
    '';
  };
}
