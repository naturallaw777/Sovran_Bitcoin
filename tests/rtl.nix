# Config-level assertions and a packaged RTL startup/login smoke test.
# The UI is served under /rtl/; `/` is redirected there in the package.
{ nixpkgs, overlay, system ? "x86_64-linux" }:

let
  lib = nixpkgs.lib;
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ overlay ];
    config.allowUnfree = true;
  };

  eval = features: extra:
    (lib.nixosSystem {
      inherit system;
      modules = [
        { nixpkgs.hostPlatform = system; nixpkgs.overlays = [ overlay ]; }
        ../modules
        ../tests/minimal-hardware.nix
        {
          nix-bitcoin.generateSecrets = true;
          nix-bitcoin.secretsDir = "/build/secrets";
          sovran-bitcoin = {
            enable = true;
            features = features;
          };
          services.bitcoind.dataDir = "/build/bitcoind";
          services.lnd.dataDir = "/build/lnd";
          system.stateVersion = "26.05";
        }
        extra
      ];
    }).config;

  cfg = eval { rtl = true; } {};

  json = cfg.services.rtl.configJson;
  node = builtins.head json.nodes;
  rtlPackage = cfg.services.rtl.package;
  # Simulate an older nixpkgs without building or downloading an old Node.
  fakeOldVersion = _: { version = "22.23.3"; __intentionallyOverridingVersion = true; };
  oldBuildNode = rtlPackage.nodejs.overrideAttrs fakeOldVersion;
  oldRuntimeNode = rtlPackage.nodejsRuntime.overrideAttrs fakeOldVersion;
  configTemplate = pkgs.writeText "rtl-test-config.json" (builtins.toJSON json);
in
assert lib.assertMsg cfg.services.rtl.enable
  "preset features.rtl must enable services.rtl";
assert lib.assertMsg (cfg.services.rtl.port == 3050)
  "preset must put RTL on 3050";
assert lib.assertMsg (cfg.services.rtl.address == "127.0.0.1")
  "RTL must bind loopback";
assert lib.assertMsg (cfg.systemd.services.rtl.environment.RTL_CONFIG_PATH == "/var/lib/rtl")
  "RTL_CONFIG_PATH must be the data dir";
assert lib.assertMsg (cfg.systemd.services.rtl.serviceConfig.WorkingDirectory == "/var/lib/rtl")
  "WorkingDirectory must be the data dir";
assert lib.assertMsg (json.host == "127.0.0.1" && json.port == 3050)
  "generated config must listen on 127.0.0.1:3050";
assert lib.assertMsg (json.trustedProxies == "127.0.0.1")
  "0.15.12 trustedProxies must be the loopback proxy hop";
assert lib.assertMsg (node ? authentication && !(node ? Authentication))
  "RTL v0.15.8+ schema requires lowercase authentication";
assert lib.assertMsg (node ? settings && !(node ? Settings))
  "RTL v0.15.8+ schema requires lowercase settings";
assert lib.assertMsg (node.lnImplementation == "LND")
  "Sovran RTL is LND-only";
assert lib.assertMsg (lib.hasPrefix "https://127.0.0.1:" node.settings.lnServerUrl)
  "lnServerUrl must target loopback LND REST, not 0.0.0.0";
assert lib.assertMsg (node.authentication.macaroonPath == "/var/lib/rtl/macaroons")
  "macaroonPath must be the copied-macaroon directory";
assert lib.assertMsg (!(node.authentication ? boltzMacaroonPath) && !(node.settings ? boltzServerUrl))
  "RTL v0.15.13 removed Boltz settings";
assert lib.assertMsg (lib.versionAtLeast rtlPackage.version "0.15.16")
  "the default RTL package must include the 0.15.16 security fixes";
assert lib.assertMsg (lib.versionAtLeast rtlPackage.nodejsRuntime.version "22.23.4")
  "RTL must use a Node.js runtime with the October 2026 security fixes";
assert lib.assertMsg (!(builtins.tryEval (rtlPackage.override { nodejs_22 = oldBuildNode; })).success)
  "RTL must reject an outdated Node.js build toolchain";
assert lib.assertMsg (!(builtins.tryEval (rtlPackage.override { nodejs-slim_22 = oldRuntimeNode; })).success)
  "RTL must reject an outdated Node.js runtime";
pkgs.runCommand "sovran-bitcoin-rtl" {
  nativeBuildInputs = [ pkgs.curl pkgs.jq ];
} ''
  set -euo pipefail
  state="$TMPDIR/rtl-state"
  mkdir -p "$state"/{logs,database,backup,macaroons}
  printf 'not-a-real-macaroon' > "$state/macaroons/admin.macaroon"
  # Avoid contacting a real LND instance during startup.
  : > "$state/backup/channel-all.bak"

  # Use the module's generated config, replacing only the password, port and
  # writable paths. Pick an available loopback port for non-sandboxed builders.
  port=$(${rtlPackage.nodejsRuntime}/bin/node -e '
    const s = require("net").createServer();
    s.listen(0, "127.0.0.1", () => { console.log(s.address().port); s.close(); });
  ')
  jq --arg dir "$state" --argjson port "$port" '
    .multiPass = "rtl-test-password"
    | .port = $port
    | .dbDirectoryPath = $dir
    | .nodes[0].authentication.macaroonPath = ($dir + "/macaroons")
    | .nodes[0].settings.channelBackupPath = ($dir + "/backup")
  ' ${configTemplate} > "$state/RTL-Config.json"

  RTL_CONFIG_PATH="$state" DB_DIRECTORY_PATH="$state" \
    ${rtlPackage}/bin/rtl > "$state/rtl.log" 2>&1 &
  rtlPid=$!
  cleanup() {
    status=$?
    trap - EXIT
    kill "$rtlPid" 2>/dev/null || true
    wait "$rtlPid" 2>/dev/null || true
    if [ "$status" -ne 0 ]; then cat "$state/rtl.log" >&2; fi
    exit "$status"
  }
  trap cleanup EXIT
  base="http://127.0.0.1:$port"

  # The patched root route must lead to the Angular base path.
  curl -fs --retry 20 --retry-connrefused --retry-delay 1 --retry-max-time 20 \
    -D "$state/root.headers" -o /dev/null "$base/"
  tr -d '\r' < "$state/root.headers" > "$state/root.clean"
  grep -Eq '^HTTP/[0-9.]+ 302 ' "$state/root.clean"
  grep -Eiq '^Location: /rtl/$' "$state/root.clean"

  # First visit must issue the session and CSRF cookies under /rtl.
  curl -fsS -c "$state/cookies" -D "$state/app.headers" \
    -o "$state/index.html" "$base/rtl/"
  tr -d '\r' < "$state/app.headers" > "$state/app.clean"
  grep -Fq '<base href="/rtl/">' "$state/index.html"
  grep -Eiq '^Set-Cookie: _csrf=[^;]+; Path=/rtl(;|$)' "$state/app.clean"
  grep -Eiq '^Set-Cookie: XSRF-TOKEN=[^;]+; Path=/rtl(;|$)' "$state/app.clean"
  grep -Eiq '^Set-Cookie: connect[.]sid=[^;]+; Path=/rtl(;|$)' "$state/app.clean"

  # Protected routes reject anonymous requests; login requires CSRF and works
  # with the module-generated config, even without an LND server running.
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$base/rtl/api/lnd/getinfo")
  test "$code" = 401
  passHash=$(printf 'rtl-test-password' | sha256sum | cut -d' ' -f1)
  login=$(jq -nc --arg password "$passHash" \
    '{authenticateWith: "PASSWORD", authenticationValue: $password}')
  code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' --data "$login" "$base/rtl/api/authenticate")
  test "$code" = 403
  csrf=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$state/cookies")
  test -n "$csrf"
  curl -fsS -b "$state/cookies" -c "$state/cookies" \
    -H 'Content-Type: application/json' -H "X-XSRF-TOKEN: $csrf" \
    --data "$login" "$base/rtl/api/authenticate" > "$state/login.json"
  jq -e '(.token | type) == "string" and (.token | length) > 0' "$state/login.json" > /dev/null
  curl -fsS -b "$state/cookies" -H 'Content-Type: application/json' \
    -H "X-XSRF-TOKEN: $csrf" --data '{}' "$base/rtl/api/authenticate/logout" \
    | jq -e '.loggedout == true' > /dev/null

  echo ok > "$out"
''
