# Config-level hardening assertions for bitcoind + nbxplorer + btcpayserver.
# Adapted from Sovran_SystemsOS' tests/bitcoin-btcpay-hardening.nix.
{ nixpkgs, overlay, system ? "x86_64-linux" }:

let
  lib = nixpkgs.lib;
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ overlay ];
    config.allowUnfree = true;
  };

  normalize = s:
    lib.replaceStrings [ "\n" "\\" "  " ] [ " " "" " " ] s;

  extractAfter = prefix: str:
    let
      match = builtins.match ".*${prefix} ([^ ]+).*" (normalize str);
    in
      if match == null then
        throw "Unable to extract ${prefix} from: ${normalize str}"
      else
        builtins.head match;

  extractFlagValue = flag: str:
    let
      match = builtins.match ".*${flag}=([^ ]+).*" (normalize str);
    in
      if match == null then
        throw "Unable to extract ${flag} from: ${normalize str}"
      else
        builtins.head match;

  config = (lib.nixosSystem {
    inherit system;
    modules = [
      { nixpkgs.hostPlatform = system; nixpkgs.overlays = [ overlay ]; }
      ../modules
      {
        nix-bitcoin.generateSecrets = true;
        nix-bitcoin.secretsDir = "/build/secrets";

        services.btcpayserver.enable = true;
        services.btcpayserver.lightningBackend = "lnd";
        services.nbxplorer.dataDir = "/build/nbxplorer";
        services.btcpayserver.dataDir = "/build/btcpayserver";
        services.lnd.dataDir = "/build/lnd";
        services.bitcoind.dataDir = "/build/bitcoind";
      }
    ];
  }).config;

  nbxplorerPreStart = config.systemd.services.nbxplorer.preStart;
  bitcoindPreStart = config.systemd.services.bitcoind.preStart;
  btcpayExecStart = config.systemd.services.btcpayserver.serviceConfig.ExecStart;
  btcpayWorkingDir = config.systemd.services.btcpayserver.serviceConfig.WorkingDirectory;

  nbxplorerConfigPath = extractAfter "install -m 600" nbxplorerPreStart;
  btcpayConfigPath = extractFlagValue "--conf" btcpayExecStart;

  nbxplorerConfig = builtins.readFile nbxplorerConfigPath;
  btcpayConfig = builtins.readFile btcpayConfigPath;
in
assert lib.assertMsg
  (config.users.users.${config.services.btcpayserver.user}.home == config.services.btcpayserver.dataDir)
  "btcpayserver user home must match btcpayserver dataDir";
assert lib.assertMsg
  (config.users.users.${config.services.nbxplorer.user}.home == config.services.nbxplorer.dataDir)
  "nbxplorer user home must match nbxplorer dataDir";
assert lib.assertMsg
  (config.nix-bitcoin.secrets.bitcoin-HMAC-btcpayserver.user == config.services.bitcoind.user)
  "bitcoin-HMAC-btcpayserver must be owned by bitcoind";
assert lib.assertMsg
  (config.nix-bitcoin.secrets.bitcoin-rpcpassword-btcpayserver.user == config.services.bitcoind.user)
  "bitcoin-rpcpassword-btcpayserver must be owned by bitcoind";
assert lib.assertMsg
  (config.nix-bitcoin.secrets.bitcoin-rpcpassword-btcpayserver.group == config.services.nbxplorer.group)
  "bitcoin-rpcpassword-btcpayserver must be group-readable by nbxplorer";
assert lib.assertMsg
  (!(lib.elem config.services.nbxplorer.group config.users.users.${config.services.btcpayserver.user}.extraGroups))
  "btcpayserver must not receive the nbxplorer group";
assert lib.assertMsg
  (lib.elem "nix-bitcoin-secrets.target" config.systemd.services.nbxplorer.after)
  "nbxplorer must wait for nix-bitcoin-secrets.target";
assert lib.assertMsg
  (config.systemd.services.nbxplorer.serviceConfig.MemoryDenyWriteExecute == false)
  "nbxplorer needs MemoryDenyWriteExecute = false";
assert lib.assertMsg
  (config.systemd.services.btcpayserver.serviceConfig.MemoryDenyWriteExecute == false)
  "btcpayserver needs MemoryDenyWriteExecute = false";
assert lib.assertMsg
  (lib.hasInfix "network=mainnet" nbxplorerConfig
    && lib.hasInfix "btcrpcuser=btcpayserver" nbxplorerConfig
    && lib.hasInfix "btcnodeendpoint=127.0.0.1:8335" nbxplorerConfig
    && lib.hasInfix "bind=127.0.0.1" nbxplorerConfig
    && lib.hasInfix "port=24444" nbxplorerConfig
    && lib.hasInfix "postgres=User ID=nbxplorer;Host=/run/postgresql;Database=nbxplorer" nbxplorerConfig)
  "nbxplorer base config must contain the expected non-secret settings";
assert lib.assertMsg
  (lib.hasInfix "btcexplorerurl=http://127.0.0.1:24444/" btcpayConfig
    && lib.hasInfix "btcexplorercookiefile=/build/nbxplorer/Main/.cookie" btcpayConfig)
  "btcpayserver config must contain btcexplorerurl and btcexplorercookiefile";
assert lib.assertMsg
  (lib.hasSuffix "/lib/btcpayserver" btcpayWorkingDir)
  "btcpayserver WorkingDirectory must end with /lib/btcpayserver";
assert lib.assertMsg
  (!lib.hasInfix "/build/btcpayserver/settings.config" btcpayExecStart
    && lib.hasInfix "--datadir='/build/btcpayserver'" btcpayExecStart)
  "btcpayserver must use a deterministic config file plus --datadir";
assert lib.assertMsg
  (lib.hasInfix "network=mainnet" btcpayConfig
    && lib.hasInfix "bind=127.0.0.1" btcpayConfig
    && lib.hasInfix "port=23000" btcpayConfig
    && lib.hasInfix "btcexplorerurl=http://127.0.0.1:24444/" btcpayConfig
    && lib.hasInfix "explorer.postgres=User ID=nbxplorer;Host=/run/postgresql;Database=nbxplorer" btcpayConfig
    && lib.hasInfix "postgres=User ID=btcpayserver;Host=/run/postgresql;Database=btcpayserver" btcpayConfig
    && lib.hasInfix "btclightning=type=lnd-rest;server=https://127.0.0.1:8080/;macaroonfilepath=/run/lnd/btcpayserver.macaroon;certfilepath=/build/secrets/lnd-cert" btcpayConfig)
  "btcpayserver config must preserve BTCPay, NBXplorer, database, and LND settings";
assert lib.assertMsg
  (lib.hasInfix "readValidatedRpcHmac()" bitcoindPreStart
    && lib.hasInfix ''if [[ ! -e "$hmacFile" ]]; then'' bitcoindPreStart
    && lib.hasInfix ''if [[ ! -r "$hmacFile" ]]; then'' bitcoindPreStart
    && lib.hasInfix ''if [[ -z "$hmacPayload" ]]; then'' bitcoindPreStart
    && lib.hasInfix ''^[[:xdigit:]]+\$[[:xdigit:]]+$'' bitcoindPreStart
    && lib.hasInfix "Bitcoin RPC HMAC file has invalid format" bitcoindPreStart
    && lib.hasInfix ''hmacPayload="$(readValidatedRpcHmac '/build/secrets/bitcoin-HMAC-btcpayserver')" || exit 1'' bitcoindPreStart)
  "bitcoind preStart must validate missing, unreadable, empty, and malformed HMAC files";
pkgs.runCommand "bitcoin-btcpay-hardening" {} ''
  mkdir -p /build/secrets /build/nbxplorer

  printf '%s' 'first-password' > /build/secrets/bitcoin-rpcpassword-btcpayserver
  bash -euo pipefail -c ${lib.escapeShellArg nbxplorerPreStart}

  test "$(stat -c '%a' /build/nbxplorer/settings.config)" = "600"
  test "$(grep -c '^btcrpcuser=' /build/nbxplorer/settings.config)" = "1"
  test "$(grep -c '^btcrpcpassword=' /build/nbxplorer/settings.config)" = "1"
  test "$(grep -c '^postgres=' /build/nbxplorer/settings.config)" = "1"

  printf '%s' 'rotated-password' > /build/secrets/bitcoin-rpcpassword-btcpayserver
  bash -euo pipefail -c ${lib.escapeShellArg nbxplorerPreStart}

  test "$(grep -c '^btcrpcuser=' /build/nbxplorer/settings.config)" = "1"
  test "$(grep -c '^btcrpcpassword=' /build/nbxplorer/settings.config)" = "1"
  test "$(grep -c '^postgres=' /build/nbxplorer/settings.config)" = "1"
  ! grep -q 'first-password' /build/nbxplorer/settings.config
  grep -q 'rotated-password' /build/nbxplorer/settings.config

  touch "$out"
''
