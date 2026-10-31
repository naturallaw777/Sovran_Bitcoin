# Sovran_Bitcoin

**An opinionated, Tor-first Bitcoin stack for NixOS.** This standalone flake packages the Bitcoin/Lightning engine of [Sovran SystemsOS](https://git.sovransystems.com/Sovran_Systems/Sovran_SystemsOS)—think “nix-bitcoin, with Sovran defaults.”

- LND only; Tor-proxied traffic and onion services by default.
- Strict nix-bitcoin systemd hardening; secrets are generated on first activation.
- Optional Zeus/BitBanana node access, NWC wallet connections, RTL, BTCPay, Mempool and Lightning Addresses.
- Services bind to loopback; exposing clearnet endpoints is up to your web server.

Vendored from [fort-nix/nix-bitcoin](https://github.com/fort-nix/nix-bitcoin) (MIT) and Sovran SystemsOS (AGPL-3.0); see `THIRD_PARTY_NOTICES.md`.

## Quick start

Add the flake and module to your NixOS configuration:

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sovran-bitcoin.url = "github:naturallaw777/Sovran_Bitcoin";
  };

  outputs = { self, nixpkgs, sovran-bitcoin }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [ sovran-bitcoin.nixosModules.default ./configuration.nix ];
    };
  };
}
```

```nix
# configuration.nix
{
  sovran-bitcoin = {
    enable = true;
    operatorName = "alice"; # gets bitcoin-cli, lncli and nodeinfo
  };
}
```

The default preset enables:

| Component | Default behavior |
| --- | --- |
| `bitcoind` | Mainnet, txindex, Tor proxy enforcement, onion P2P and bloom filters |
| `electrs` | Electrum server (e.g. Sparrow), with onion service |
| `lnd` | Tor-proxied Lightning node with public P2P onion |
| `lndconnect` | Zeus-ready QR/URI over the LND REST onion |
| `lndconnect-grpc` | BitBanana-ready QR/URI over a separate gRPC onion |
| Secrets | Generated on activation in `/etc/nix-bitcoin-secrets` |
| `nodeinfo` | Operator command for a full service/status report |

The gRPC onion forwards to LND's loopback listener (default `127.0.0.1:10009`); the API is not exposed on LAN or clearnet.

## Connect a wallet app

Use **direct LND access** for full node/channel management, **NWC** for a separate wallet-only connection with optional spending limits, or both.

### Direct LND: Zeus and BitBanana

| App | Command | Connection |
| --- | --- | --- |
| Zeus | `lndconnect` | REST over the `lnd-rest` onion (default port 8080) |
| BitBanana | `lndconnect-grpc` | gRPC over the `lnd-grpc` onion (default port 10009) |

Run the command on the node to show a QR; add `--url` to print the `lndconnect://` URI instead:

```sh
lndconnect             # Zeus QR
lndconnect-grpc        # BitBanana QR
lndconnect --url
lndconnect-grpc --url
```

Scan or paste the result into the app's node-connection screen. BitBanana detects the `.onion` address and connects over Tor; see its [connection guide](https://docs.bitbanana.app/setup/connect-a-lightning-node/).

**Security:** These connection strings contain LND's admin macaroon and grant broad node control. Treat them like passwords; never share them. For a non-preset LND configuration, enable the helpers and onion endpoints:

```nix
services.lnd.lndconnect = {
  enable = true;
  onion = true;
  grpcOnion = true;
};
```

### Optional NWC wallet connections

Enable `nwc` (also enabled by `lnurl`) to run Sovran's self-hosted Alby Hub wallet service. It has no web UI; manage it with `nwc-wallet`.

```nix
sovran-bitcoin.features.nwc = true;
```

Create a wallet connection from the CLI:

```sh
nwc-wallet create pocket-wallet pocket --limit-sats 5000
```

Or declare it in NixOS configuration (`services.sovran-nwc.wallets` or `services.albyhub.wallets`):

```nix
{
  sovran-bitcoin.features.nwc = true;
  services.sovran-nwc.wallets.pocket = {
    alias = "pocket";
    limitSats = 5000; # omit for receive-only
  };
}
```

Each wallet has an isolated connection. A limit caps lifetime spending; without `--limit-sats`/`limitSats`, it is receive-only. The CLI prints a `nostr+walletconnect://` pairing URI. For declared wallets it is stored, mode `0600`, at `/var/lib/albyhub/wallets/<alias>.pairing-uri`. Import it into the NWC connection flow in [Zeus](https://zeusln.com/blog/new-release-zeus-v0-10-0/) or [BitBanana](https://docs.bitbanana.app/setup/connect-a-hosted-wallet/nostr-wallet-connect-uri/). NWC is wallet access, not node management. Keep pairing URIs private.

Spend-capable wallets can pay invoices and send keysend (spontaneous) payments — e.g. BitBanana's keysend button; receive-only wallets cannot spend at all. Spending works with LND 0.21 and newer. Existing wallet connections keep working after upgrades: pairing URIs, balances and limits are preserved, and spend-capable wallets gain keysend automatically — no re-pairing or wallet recreation needed.

### `nwc-wallet` commands

| Command | Purpose |
| --- | --- |
| `nwc-wallet create <name> <alias> [--receive-only] [--limit-sats SATS] [--qr]` | Create a wallet connection; optionally show its QR. The receive-only and spending-limit options are alternatives. |
| `nwc-wallet list` | List managed wallets, including Lightning Addresses. |
| `nwc-wallet lnurl <alias> [--qr]` | Show the Lightning Address and bech32 LNURL; optionally show a terminal QR. |
| `nwc-wallet lnurl <alias> --address-only` | Print only the Lightning Address (e.g. for piping). |
| `nwc-wallet lnurl <alias> --lnurl-only` | Print only the bech32 LNURL string. |
| `nwc-wallet drain <wallet>` | Drain funds from a wallet. |
| `nwc-wallet delete <wallet>` | Drain, then delete a wallet. |
| `nwc-wallet rotate <wallet>` | Replace the NWC secret and revoke the old one. |
| `nwc-wallet address show <alias>` | Check whether a Lightning Address endpoint is publicly reachable. |
| `nwc-wallet health` | Check Alby Hub health. |

For `drain`, `delete` and `rotate`, `<wallet>` can be its name, alias, Lightning Address or ID from `nwc-wallet list`. `--qr` requires `qrencode` (included when `lnurl` is enabled).

## Optional services

Set features in your NixOS configuration:

```nix
sovran-bitcoin.features = {
  rtl = true;          # Ride The Lightning UI at 127.0.0.1:3050/rtl
  btcpayserver = true; # BTCPay + NBXplorer (Postgres), using LND
  mempool = true;      # Mempool explorer (MariaDB), UI at 127.0.0.1:60845
  nwc = true;          # Alby Hub/NWC; manage with nwc-wallet, no web UI
  lnurl = true;        # Lightning Addresses via NWC + LNURL
};
services.sovran-lnurl.domain = "pay.example.com"; # required for lnurl
```

Dependencies are automatic: BTCPay enables NBXplorer, Postgres and a least-privilege LND macaroon; LNURL enables NWC; Mempool enables Electrs and txindex. Features get onion services. The bitcoind wallet is disabled by default and re-enabled automatically for BTCPay/NBXplorer.

RTL requires Node.js 22.23.4 or newer in the 22.x series. The locked nixpkgs meets this requirement; when using the overlay with another nixpkgs, update that nixpkgs if it supplies an older Node version. RTL's block explorer is no longer editable in the UI; to override its default, set `systemd.services.rtl.environment.BLOCK_EXPLORER_URL` to a trusted, reachable endpoint consistent with your Tor policy.

## Networking and customization

The flake deliberately stops at loopback. Put your own web server (nginx, Caddy, etc.) in front for clearnet/TLS:

| Service | Local endpoint | Notes |
| --- | --- | --- |
| BTCPay | `http://127.0.0.1:23000` | Reverse proxy + TLS; see BTCPay docs for headers. |
| Mempool UI | `http://127.0.0.1:60845` | Reusable nginx snippets: `config.services.mempool.frontend.nginxConfig.{httpConfig,staticContent,proxyApi}`. |
| LNURL | `http://127.0.0.1:8181` | Proxy `/.well-known/lnurlp/*` and `/lnurlp/*` on your Lightning domain. |

The preset uses `mkDefault`, so standard nix-bitcoin options remain overridable. For example:

```nix
{ ... }: {
  services.bitcoind.prune = 10000;       # about 10 GB
  services.bitcoind.dbCache = 2000;
  services.bitcoind.dataDir = "/mnt/btc/bitcoind";
  services.lnd.extraConfig = "protocol.option-scid-alias=true"; # already default
  services.rtl.extraCurrency = "USD";    # relaxes Tor for RTL
  services.albyhub.relay = "wss://relay.example.com";
  services.sovran-lnurl.domainFile = "/var/lib/secrets/lightning-domain";
  services.mempool.frontend.settings.BASE_MODULE = "liquid";
  nix-bitcoin.onionServices.rtl.enable = false;
}
```

Disable a base service with its feature option, e.g. `sovran-bitcoin.features.electrs = false;` (Electrs is useful for Mempool and Sparrow).

## System tools

The operator gets `bitcoin-cli` and `lncli`; other installed tools are `nodeinfo`, `lndconnect`, `lndconnect-grpc` and `nwc-wallet` (available when NWC is enabled).

## Flake outputs

| Output | Contents |
| --- | --- |
| `nixosModules.default` (`.sovran-bitcoin`) | All modules and `sovran-bitcoin.*` options; applies the package overlay automatically. |
| `overlays.default` (`.sovran-bitcoin`) | Adds `pkgs.sovran-bitcoin.*` packages: RTL, Mempool, Alby Hub and NWC. |
| `packages.<system>.*` | `rtl`, `mempool-backend`, `mempool-frontend`, `albyhub`, `nwc`. |
| `checks.<system>.*` | Evaluation checks and BTCPay/bitcoind hardening test. |

To avoid automatic overlay application, import `./modules` in your wrapper and add `overlays.default` yourself.

## Secrets and backups

At activation, the one-shot `setup-secrets` service writes generated secrets to `/etc/nix-bitcoin-secrets` (`nix-bitcoin.secretsDir`), with per-service ownership. This includes LND certificates, RTL password, bitcoind RPC HMACs and macaroons.

**Back up this directory.** Losing it—or the LND seed at `~lnd data dir/lnd-seed-mnemonic` (mode `0600`)—can mean losing funds or access. To manage secrets yourself, set `nix-bitcoin.generateSecrets = false;` and review `modules/nix-bitcoin/secrets/secrets.nix`.

## Troubleshooting

### Sparrow fails with "Failed to subscribe to paths"

If Sparrow (or another Electrum wallet) aborts on load with
`Failed to subscribe to paths: [m/0/0-...]`, check the electrs journal:

```
journalctl -u electrs -f
```

A `Too many open files` error there points at the root cause: RocksDB keeps
one file descriptor per `.sst` file in the electrs index (thousands of files
on mainnet with electrs 0.12's bindex engine), but systemd's default soft
`LimitNOFILE` is 1024. Descriptor exhaustion makes
`blockchain.scripthash.subscribe` — the RPC call wallets use to load — fail.
The stack fixes this by setting
`systemd.services.electrs.serviceConfig.LimitNOFILE = 65536;`
(`modules/electrs.nix`). No reindex or other operator action is required; the
limit takes effect on the next electrs restart (or the next rebuild-and-switch,
which restarts the unit). Verify the soft limit actually applied with
`grep -i 'open files' /proc/$(systemctl show -p MainPID --value electrs)/limits`
(first column must read 65536 — `systemctl show -p LimitNOFILE` reports the
*hard* limit and can look correct even when the soft limit is the problem).

Note: `modules/nix-bitcoin/versioning.nix` is a stub in this vendored stack —
there is no `nix-bitcoin.configVersion` migration to run for this change.

## Differences from Sovran SystemsOS

- Data stays under `/var/lib`; no `/run/media/Second_Drive/...` paths.
- NWC/LNURL are plain systemd services, not tied to Sovran Hub. Configure the LNURL domain with `services.sovran-lnurl.domain` or `.domainFile`, not Hub's `/var/lib/domains/lightning`.
- No Hub firewall port 3051.
- `disablewallet` is enabled only when BTCPay is off (SystemsOS enables it unconditionally).
- The operator defaults to `operator`, not `free`.

## License

AGPL-3.0; see `LICENSE`. Vendored MIT-licensed portions are listed in `THIRD_PARTY_NOTICES.md`.
