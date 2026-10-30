# Changelog

All notable changes to Sovran_Bitcoin are documented here.

This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Updated vendored Mempool (`mempool-backend`, `mempool-frontend`) from `3.3.1`
  to `3.3.2` and aligned its build/runtime toolchain with upstream's Node.js 26
  bump (`nodejs_26` / `nodejs-slim_26`), allowing `mempool-frontend`'s
  `fetchNodeModules` to run strict `npm ci` without `--legacy-peer-deps`.
  Refreshed `mempool/mining-pool-logos` frontend assets (adding light-theme
  `.light.svg` variants and newer pool logos), refreshed context in
  `0001-allow-disabling-mining-pool-fetching.patch`, and set
  `NODE_OPTIONS="--max-old-space-size=4096"` during the localized Angular
  frontend build so <=4 GiB RAM builders with swap do not hit V8's default
  half-RAM heap cap.

## [1.1.2] - 2026-10-21

### Changed

- Refreshed the locked `nixpkgs` revision from `55bfb4d7` (2026-10-14) to
  `02c087f3` (2026-10-20), still tracking `nixos-unstable`. The refresh carries
  ~5,600 upstream commits, but every Nixpkgs-provided component of the stack
  resolves to the same version as in `1.1.1`:
  - `bitcoin`: `31.1`, `lnd`: `0.21.4-beta`, `lndinit`: `0.1.38-beta`,
    `electrs`: `0.12.0`, `btcpayserver`: `2.4.5`, `nbxplorer`: `2.6.17`,
    `tor`: `0.4.9.14` (unchanged; verified by diffing the package derivations
    at both revisions).
  - No Sovran module option, service default, or vendored package source
    changed in this release. The refresh updates only transitive/propagated
    inputs, so a rebuild is expected but no configuration migration is.
- Bumped the vendored `sovran-nwc` package from `2.0.0` to `2.0.1`, reflecting
  the payment-path fixes and the TLS context change below. The daemon now
  reports `sovran-nwc-2.0.1` from `GET /api/info`.
- Rewrote `README.md` in a tighter form and reordered the setup sections
  (quick start, node access, NWC wallets); content and options are unchanged.

### Fixed

- Fixed NWC spending failing with `Error Not Found` (HTTP 404) on LND 0.21+.
  LND 0.21 removed the deprecated payment RPCs and their REST routes —
  including `POST /v1/channels/transactions` (`lnrpc.SendPaymentSync`) — as
  announced in the 0.20 release notes ([lnd#10814](https://github.com/lightningnetwork/lnd/pull/10814)),
  so every `pay_invoice` request from a connected NWC client (Zeus, BitBanana,
  Alby, …) reached a REST route that no longer exists and died with LND's 404
  "Not Found" while `get_info`/`get_balance` kept working. `nwc_lnd.pay_invoice`
  now sends payments through `POST /v2/router/send` (`routerrpc.SendPaymentV2`),
  the supported endpoint since LND 0.11:
  - Sends `fee_limit_msat`/`amt_msat` as `SendPaymentRequest` fields
    (the old `fee_limit.fixed_msat` belongs to the removed `SendRequest`).
  - Streams only the terminal `lnrpc.Payment` update
    (`no_inflight_updates`), parsing the newline-delimited JSON body.
  - Reads `payment_preimage`/`payment_hash` as hex strings (the removed
    endpoint returned base64 bytes) and reports `fee_msat` as fees paid.
  - Maps `PaymentFailureReason` to readable NIP-47 `PAYMENT_FAILED` messages
    (e.g. "No route found to destination").
  - The `albyhub.macaroon` permissions (`offchain:read/write`) already cover
    `routerrpc.Router/SendPaymentV2`; no macaroon changes are needed.
- Added `tests/test_lnd_rest_pay.py` covering the `POST /v2/router/send`
  request shape, streaming-response parsing, hex preimage handling, failure
  reason mapping, and the removed-endpoint 404 regression.

- Fixed internal wallet-to-wallet payments returning a fabricated preimage
  (`sha256(payment_hash)`), which fails client-side verification (Zeus
  checks `sha256(preimage) == payment_hash` and rejects such payments).
  LND generates an invoice's preimage at creation (`lnrpc.LookupInvoice`
  returns `r_preimage` even while the invoice is OPEN), so the real
  preimage is now recorded when `make_invoice` runs and resolved from LND
  when a ledger row predates preimage storage. Both ledger rows carry it
  and `payment_sent`/`payment_received` notifications include it.
- Enabled `pay_keysend` (NWC-04) for spend-capable wallets (previously
  `RESTRICTED` even with the spend scope, breaking BitBanana's keysend
  button): spontaneous payments through `POST /v2/router/send` (`dest` =
  the 33-byte pubkey, `amt_msat`, keysend preimage in custom TLV
  `5482373484`, optional extra `tlv_records`). The `pay_invoice` spend
  scope now covers `pay_keysend`, so existing connections gain it without
  re-pairing; receive-only wallets stay `RESTRICTED`, and every keysend is
  still capped by wallet balance and monthly budget.
- Removed the deprecated `multi_pay_invoice`/`multi_pay_keysend` commands
  from the advertised methods (they were advertised via `get_info` but
  answered `NOT_IMPLEMENTED` — clients trusted the advertisement and then
  failed). They were dropped from NIP-47 and only exist as an Alby Hub
  legacy dialect; they now answer `NOT_IMPLEMENTED` explicitly and are no
  longer listed in `get_info`. Batch-payout tools that require them will
  fail fast instead of half-working. Unknown methods in general (e.g.
  `sign_message`) now answer `NOT_IMPLEMENTED` rather than `RESTRICTED`,
  distinguishing "not supported" from "this wallet may not use it".
- Added `tests/test_followups.py` (internal preimage verification incl.
  legacy ledger rows, `multi_pay_*`/unknown-method rejection,
  keysend success/restriction/budget, `get_info` advertisement) and
  keysend request-shape tests in `tests/test_lnd_rest_pay.py`. The NWC test
  suite is now 45 tests.

- Allow loopback IP traffic for `albyhub.service` while retaining nix-bitcoin's deny-by-default network hardening. The NWC daemon needs localhost access for its management API, LND REST, and Tor SOCKS proxy; without the allowlist, the service listened on `127.0.0.1:18080` but local clients timed out.
- Force clearnet NWC relay URLs through the configured Tor SOCKS proxy when Tor is enabled. The daemon's default `wss://relay.getalby.com` endpoints were otherwise dialed directly and blocked by `IPAddressDeny=any`, so pairing URIs were generated but the wallet service never received client requests.
- Fixed `nix flake check` failing to evaluate the `bitcoin-btcpay-hardening`
  check with `error: string '$confFile)' doesn't represent an absolute path`
  (`tests/bitcoin-btcpay-hardening.nix`). The check extracted the generated
  `bitcoin.conf` path with a greedy `builtins.match ".*cat ([^ ]+).*"` against
  `services.bitcoind.preStart`; since `modules/bitcoind.nix` also contains the
  `$(cat $confFile)` config-reinstall guard, the greedy match picked the *last*
  `cat` and returned the shell variable `$confFile)`, which `builtins.readFile`
  rejects. The extraction now anchors on the `/nix/store/` path that
  `cat ${configFile}` actually emits, and throws a readable error if it is ever
  absent. Test-harness only — no service, option or runtime change. This check
  had never evaluated, so no prior release exercised it.

### Security

- Cleared GitHub code scanning alert `py/insecure-protocol` (CWE-327) on
  `ssl.create_default_context()` in `packages/sovran-nwc/nwc_nostr.py`. Python's
  default context already floors at TLS 1.2, but the floor was implicit; both
  outbound TLS contexts (`wss://` NWC relays and the LND REST client) now set
  `minimum_version = ssl.TLSVersion.TLSv1_2` explicitly. Behaviour is unchanged
  on Python 3.10+ — this pins the guarantee in code instead of leaving it to the
  interpreter default, and makes the posture legible to static analysis.
  Certificate and hostname verification were already on (`PROTOCOL_TLS_CLIENT`,
  `CERT_REQUIRED`) and remain on. Added `tests/test_tls_posture.py` (4 tests) so
  a future edit cannot silently drop the protocol floor.

### Upgrade notes

- No configuration migration is required. Refresh the flake input on the host
  and rebuild:

  ```bash
  nix flake update sovran-bitcoin
  sudo nixos-rebuild switch --flake .#myhost
  ```

- The `nixpkgs` refresh triggers a rebuild of the stack, but resolves to the
  same package versions as `1.1.1`; if you pin `services.btcpayserver.package`
  or `services.nbxplorer.package` explicitly, those pins still win.
- Existing NWC pairings keep working: the `pay_invoice` spend scope now also
  covers `pay_keysend`, so clients such as BitBanana gain keysend without
  re-pairing, and no SQLite migration runs. Receive-only wallets stay
  `RESTRICTED` for spending, and every keysend is still capped by wallet
  balance and the monthly budget.

## [1.1.1] - 2026-10-18

### Changed

- Refreshed the locked `nixpkgs` revision from `c59305ba` to `55bfb4d7`
  (`nixos-unstable`), updating Nixpkgs-provided stack components:
  - `lnd`: `0.21.3-beta` → `0.21.4-beta`
  - `lndinit`: `0.1.22-beta` → `0.1.38-beta`
  - `electrs`: `0.11.0` → `0.12.0`
  - `btcpayserver`: `2.4.2` → `2.4.5`
  - `nbxplorer`: `2.6.10` → `2.6.17`
  - `tor`: `0.4.9.13` → `0.4.9.14`
- Updated the vendored Ride The Lightning (`rtl`) package from `0.15.12` to
  `0.15.13` and dropped the removed `boltzMacaroonPath` / `boltzServerUrl`
  fields from the generated `RTL-Config.json`.
- Replaced the external Go Alby Hub fork (`packages/albyhub`) with a Nix-native,
  pure-stdlib Python NWC wallet daemon (`nwc-daemon` in `packages/sovran-nwc`
  `2.0.0`):
  - Implements NIP-47 (`get_info`, `get_balance`, `make_invoice`,
    `lookup_invoice`, `list_transactions`, `pay_invoice`, `notifications`),
    BIP-340 Schnorr, NIP-04, NIP-44 v2, and RFC 6455 WebSocket relay
    connectivity (including `.onion` relays over Tor SOCKS5) with zero external
    Go/npm/pip dependencies.
  - Connects directly to LND's local REST API (`https://127.0.0.1:8080`) using a
    scoped macaroon (`info:read`, `offchain:read/write`, `invoices:read/write`)
    and always requests private route hints (`private = true`).
  - Enforces a least-privilege `invoice` token scope (`NWC_HUB_PERMISSION=invoice`)
    for `nwc-lnurl`, resolving the known security limitation where the public
    LNURL service previously required a full admin token.
  - Applies `nix-bitcoin` `defaultHardening` systemd sandboxing to the NWC
    service and adds declarative sub-wallet provisioning via
    `services.sovran-nwc.wallets` / `services.albyhub.wallets`.

### Fixed

- NWC wallets no longer refuse payments they can afford. Alby Hub gates a send
  on the isolated balance *and* on `maxAmountSat`, a cumulative send cap that
  never renews. `create_wallet` set that cap to the initial funding amount, but
  sats received afterwards raised only the balance — so a wallet holding 30,000
  sats rejected a 12,000 sat payment with `QUOTA_EXCEEDED`, "not enough budget
  remaining". An isolated wallet cannot spend more than it holds, so the cap was
  redundant and is no longer set; `--limit-sats` now only funds the wallet.
- `create_wallet` fetches the app after the funding transfer, so `create`
  reports the funded balance instead of `0`.

- Fixed `electrs.service` startup failure on `electrs 0.12.0` (`Error: An unknown argument '--daemon-p2p-addr=127.0.0.1:8335' was specified.`):
  - Removed the obsolete `--daemon-p2p-addr` CLI flag from `modules/electrs.nix` (dropped upstream in `electrs 0.12.0` when block indexing moved to `bindex`).
  - Added `services.bitcoind.rest` (`rest=1` in `bitcoin.conf`) and enabled it automatically when `services.electrs.enable = true`, as required by `electrs 0.12.0` (`bindex`) for `/rest/blockhashbyheight/`, `/rest/headers/`, `/rest/block/`, `/rest/spenttxouts/`, and `/rest/blockpart/`.
  - Added `submitpackage` to `modules/bitcoind-rpc-public-whitelist.nix` for `electrs 0.12.0` package broadcast support.
  - Added a `preStart` check in `modules/electrs.nix` to detect and remove pre-`0.12.0` (`FixedPrefix.8` / format v0) RocksDB directories so upgrades from `electrs 0.10.x`/`0.11.x` automatically reindex instead of panicking on `Unsupported DB format (0 < 1)`.
- Expanded `services.bitcoind.rpc.users.btcpayserver.rpcwhitelist` in `modules/btcpayserver.nix` to inherit `public.rpcwhitelist` (`validateaddress`, `testmempoolaccept`, `signrawtransactionwithkey`, `getblockfrompeer`, `getindexinfo`, etc.) plus NBXplorer/wallet methods (`generatetoaddress`, `signrawtransactionwithwallet`, `createwallet`, `loadwallet`, `importdescriptors`, etc.), resolving `bitcoind` RPC whitelist warnings during `nbxplorer` `ScanRPCCapabilitiesAsync` / `SupportTxIndex` / `EnsureWalletCreated` startup checks.

### Added

- `tests/test_send_cap.py`.

### Upgrade notes

- Wallets created before this fix keep their cap, and can refuse payments while
  holding plenty of sats. Clear every one of them in a single paste — `0` makes
  Alby Hub skip the cap check, leaving the balance as the only limit. It applies
  to the next payment; nothing restarts and no pairing URI changes. The script is
  idempotent and skips wallets that are already uncapped.

  ```bash
  TOKEN=$(curl -s -X POST http://127.0.0.1:18080/api/unlock \
    -H 'Content-Type: application/json' \
    -d "{\"unlockPassword\":\"$(sudo cat /var/lib/albyhub/unlock-password)\",\"permission\":\"full\"}" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

  for pk in $(curl -s "http://127.0.0.1:18080/api/apps?limit=100" \
      -H "Authorization: Bearer $TOKEN" \
      | python3 -c 'import sys,json;[print(a["appPubkey"]) for a in json.load(sys.stdin)["apps"] if a.get("isolated") and a.get("maxAmountSat")]'); do
    curl -s -o /dev/null -X PATCH "http://127.0.0.1:18080/api/apps/$pk" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d '{"maxAmountSat": 0}'
    echo "uncapped $pk"
  done
  ```

  `nwc-wallet list` also shows which wallets are affected: `spending_limit_sats`
  is the cap (`null` means uncapped) and `pubkey` is the `appPubkey` above.

  Alby Hub reserves `max(1%, 10 sats)` per payment, so the last ~1% of any
  wallet is not spendable in a single payment (30,000 sats tops out at 29,703).

## [1.1.0] - 2026-10-06

### Added

- Optional `services.lnd.lndconnect.grpcOnion` support, which publishes LND's
  gRPC listener through a dedicated Tor onion service and installs
  `lndconnect-grpc` for BitBanana-compatible QR/URI generation. The Sovran
  preset enables it by default while retaining the existing REST `lndconnect`
  command.

### Changed

- Expanded the README with direct Zeus and BitBanana LND setup, plus optional
  NWC wallet connections and the fixed, non-renewing `--limit-sats` send budget.

## [1.0.3] - 2026-10-01

### Changed

- Refreshed the locked `nixpkgs` revision from `44a91898` to `c59305ba`
  (`nixos-unstable`).
- Updated the Nixpkgs-provided Tor package from `0.4.9.12` to `0.4.9.13`.
- No Sovran module option/default or vendored application version changes.

### Upgrade notes

- No configuration migration is expected from this repo update. The refreshed
  Nixpkgs input may change transitive dependencies and trigger rebuilds.

## [1.0.2] - 2026-09-21

### Changed

- BTCPay Server and NBXplorer are now taken directly from the flake's `nixpkgs`
  input instead of a separately pinned `nixos-26.05` input. The unused
  `nixpkgs-stable` input has been dropped, and
  `services.btcpayserver.package` / `services.nbxplorer.package` now default to
  `pkgs.btcpayserver` / `pkgs.nbxplorer`. Set those options explicitly if you
  want to hold a specific build.
- The `overlays.default` / `overlays.sovran-bitcoin` overlay now provides only
  the Sovran packages (`rtl`, `mempool-backend`, `mempool-frontend`, `albyhub`,
  `nwc`); it no longer injects `btcpayserver` or `nbxplorer`.
- Updated the locked `nixpkgs` revision in `flake.lock`
  (`44a91898`, 2026-09-20).
- README, SECURITY.md and module comments updated to drop the pinned-package
  wording and the removed `nixosConfigurations.demo` output.

### Fixed

- Mempool frontend builds are non-interactive: Angular progress rendering is
  disabled (`--progress=false`) and the build runs with `CI=true TERM=dumb`,
  fixing the stalled-build loop that repeatedly emitted ANSI line-clear and
  cursor-up sequences to stderr.

### Removed

- The `nixosConfigurations.demo` flake output. The full-stack regtest demo is
  still evaluated by `checks.<system>.demo-system-eval`; to boot it as a VM,
  import `tests/demo.nix` from your own configuration.

## [1.0.1] - 2026-09-14

### Changed

- Updated Mempool from `3.2.1` to `3.3.1`.
- Updated pinned Nix packages and the flake lock file.

## [1.0.0]

- Initial tagged release.

[Unreleased]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.1.2...HEAD
[1.1.2]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.1.1...1.1.2
[1.1.1]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.3...1.1.0
[1.0.3]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.2...1.0.3
[1.0.2]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.1...1.0.2
[1.0.1]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/naturallaw777/Sovran_Bitcoin/releases/tag/1.0.0
