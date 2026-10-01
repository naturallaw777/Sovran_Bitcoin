# Changelog

All notable changes to Sovran_Bitcoin are documented here.

This project follows [Semantic Versioning](https://semver.org/).

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

[1.0.3]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.2...1.0.3
[1.0.2]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.1...1.0.2
[1.0.1]: https://github.com/naturallaw777/Sovran_Bitcoin/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/naturallaw777/Sovran_Bitcoin/releases/tag/1.0.0
