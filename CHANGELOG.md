# Changelog

All notable changes to Sovran_Bitcoin are documented here.

This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.1.0...HEAD
[1.1.0]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.3...1.1.0
[1.0.3]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.2...1.0.3
[1.0.2]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.1...1.0.2
[1.0.1]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/naturallaw777/Sovran_Bitcoin/releases/tag/1.0.0
