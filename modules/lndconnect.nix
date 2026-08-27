{ config, lib, pkgs, ... }:

# LND-only lndconnect wrapper. Restored to the fort-nix/nix-bitcoin contract
# after the LND-only rewrite shipped a Zeus QR that Zeus cannot use:
#   - unknown flags (--cert / --macaroon instead of --tlscertpath / --adminmacaroonpath)
#   - onion hostname read from /var/lib/tor/onion/free/lnd/hostname (does not exist)
#   - REST hidden service named "lnd", colliding with the LND P2P onion
#   - TLS cert embedded in the URI (localhost CN + QR too dense to scan)
#
# Zeus needs: lndconnect://<lnd-rest-onion>:8080?macaroon=<admin>  (no cert over Tor)

with lib;
let
  cfg = config.services.lnd;
  operatorName = config.nix-bitcoin.operator.name;
  nbLib = config.nix-bitcoin.lib;
  runAsUser = config.nix-bitcoin.runAsUserCmd;

  mkLndconnect = {
    name,
    shebang ? "#!${pkgs.stdenv.shell} -e",
    port,
    authSecretPath,
    enableOnion,
    onionService ? null,
    certPath ? null
  }:
  # lndconnect requires a --configfile argument, although it's unused
  # https://github.com/LN-Zap/lndconnect/issues/25
  lib.hiPrio (pkgs.writeScriptBin name ''
    ${shebang}
    url=$(
      ${getExe pkgs.lndconnect} --url \
        ${optionalString enableOnion "--host=$(cat ${config.nix-bitcoin.onionAddresses.dataDir}/${onionService})"} \
        --port=${toString port} \
        ${if enableOnion || certPath == null then "--nocert" else "--tlscertpath='${certPath}'"} \
        --adminmacaroonpath='${authSecretPath}' \
        --configfile=/dev/null "$@"
    )

    # If --url is in args
    if [[ " $* " =~ " --url " ]]; then
      echo "$url"
    else
      # UTF-8 QR is smaller than lndconnect's native output
      echo -n "$url" | ${getExe pkgs.qrencode} -t UTF8 -o -
    fi
  '');
in {
  options.services.lnd.lndconnect = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Add a `lndconnect` binary to the system environment which prints
        connection info for lnd clients (Zeus).
        See: https://github.com/LN-Zap/lndconnect

        Usage:
        ```bash
          # Print QR code
          lndconnect

          # Print URL
          lndconnect --url
        ```
      '';
    };
    onion = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Create an onion service for the lnd REST server,
        which is used by lndconnect / Zeus.
      '';
    };
  };

  config = mkIf (cfg.enable && cfg.lndconnect.enable) (mkMerge [
    {
      environment.systemPackages = [(
        mkLndconnect {
          name = "lndconnect";
          # Run as lnd user because the macaroon and cert are not group-readable
          shebang = "#!/usr/bin/env -S ${runAsUser} ${cfg.user} ${pkgs.bash}/bin/bash";
          enableOnion = cfg.lndconnect.onion;
          onionService = "${cfg.user}/lnd-rest";
          port = cfg.restPort;
          certPath = cfg.certPath;
          authSecretPath = "${cfg.networkDir}/admin.macaroon";
        }
      )];

      # LAN / clearnet Zeus needs REST on all interfaces. Tor-only stays on
      # the existing restAddress (loopback) and is reached via lnd-rest.
      services.lnd.restAddress = mkIf (!cfg.lndconnect.onion) "0.0.0.0";
    }

    (mkIf cfg.lndconnect.onion {
      services.tor = {
        enable = true;
        # Dedicated name — must not reuse onionServices.lnd (that's P2P :9735).
        relay.onionServices.lnd-rest = nbLib.mkOnionService {
          target.addr = nbLib.address cfg.restAddress;
          target.port = cfg.restPort;
          port = cfg.restPort;
        };
      };
      nix-bitcoin.onionAddresses.access = {
        ${cfg.user} = [ "lnd-rest" ];
        ${operatorName} = [ "lnd-rest" ];
      };
    })
  ]);
}
