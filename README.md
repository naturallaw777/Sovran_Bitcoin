# Sovran_Bitcoin

**An opinionated, Tor-first Bitcoin stack for NixOS.** A standalone flake packaging the Bitcoin/Lightning engine of [Sovran SystemsOS](https://git.sovransystems.com/Sovran_Systems/Sovran_SystemsOS) — “nix-bitcoin, with Sovran defaults.”

- LND only; Tor-proxied traffic and onion services by default.
- Strict nix-bitcoin systemd hardening; secrets are generated on first activation.
- Optional Zeus/BitBanana node access, NWC wallet connections, RTL, BTCPay, Mempool and Lightning Addresses.
- Services bind to loopback; exposing clearnet endpoints is up to your web server.

Vendored from [fort-nix/nix-bitcoin](https://github.com/fort-nix/nix-bitcoin) (MIT) and Sovran SystemsOS (AGPL-3.0); see `THIRD_PARTY_NOTICES.md`.

## Quick start

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

### NWC wallets

Enable `nwc` (also enabled by `lnurl`) to run a self-hosted Alby Hub with no web UI. Wallets can be created from the CLI or declared in configuration:

```nix
sovran-bitcoin.features.nwc = true;
```

```sh
nwc-wallet create pocket-wallet pocket --limit-sats 5000   # omit the limit for receive-only
```

```nix
services.sovran-nwc.wallets.pocket = {
  alias = "pocket";
  limitSats = 5000;   # omit for receive-only
};
```

Each wallet has an isolated connection, capped at a lifetime spending limit — or receive-only when no limit is set. The CLI prints a `nostr+walletconnect://` pairing URI; for declared wallets it is stored, mode `0600`, at `/var/lib/albyhub/wallets/<alias>.pairing-uri`. Import it into the NWC connection flow in [Zeus](https://zeusln.com/blog/new-release-zeus-v0-10-0/) or [BitBanana](https://docs.bitbanana.app/setup/connect-a-hosted-wallet/nostr-wallet-connect-uri/). NWC is wallet access, not node management — keep pairing URIs private.

Other commands: `list`, `lnurl`, `drain`, `delete`, `rotate`, `address show`, `health`; see `nwc-wallet <command> --help`. `drain`, `delete` and `rotate` accept a wallet's name, alias, Lightning Address or ID. `--qr` requires `qrencode`, which is included when `lnurl` is enabled.

## Optional services

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

RTL needs Node.js 22.23.4 or newer in the 22.x series, which the locked nixpkgs provides; if you pair the overlay with another nixpkgs, make sure it is new enough. RTL's block explorer is no longer editable in the UI — set `systemd.services.rtl.environment.BLOCK_EXPLORER_URL` to a trusted endpoint consistent with your Tor policy.

## Networking and customization

The flake deliberately stops at loopback. Put your own web server (nginx, Caddy, etc.) in front for clearnet/TLS:

| Service | Local endpoint | Notes |
| --- | --- | --- |
| BTCPay | `http://127.0.0.1:23000` | Reverse proxy + TLS; see BTCPay docs for headers. |
| Mempool UI | `http://127.0.0.1:60845` | Reusable nginx snippets: `config.services.mempool.frontend.nginxConfig.{httpConfig,staticContent,proxyApi}`. |
| LNURL | `http://127.0.0.1:8181` | Proxy `/.well-known/lnurlp/*` and `/lnurlp/*` on your Lightning domain. |

The preset uses `mkDefault`, so standard nix-bitcoin options remain overridable:

```nix
{
  services.bitcoind.prune = 10000;      # about 10 GB
  services.bitcoind.dataDir = "/mnt/btc/bitcoind";
  services.rtl.extraCurrency = "USD";
  nix-bitcoin.onionServices.rtl.enable = false;
}
```

Disable a base service with its feature option, e.g. `sovran-bitcoin.features.electrs = false;` (Electrs is useful for Mempool and Sparrow).

## Secrets and backups

At activation, the one-shot `setup-secrets` service writes generated secrets to `/etc/nix-bitcoin-secrets` (`nix-bitcoin.secretsDir`), with per-service ownership. This includes LND certificates, RTL password, bitcoind RPC HMACs and macaroons.

**Back up this directory.** Losing it — or the LND seed at `~lnd data dir/lnd-seed-mnemonic` (mode `0600`) — can mean losing funds or access. To manage secrets yourself, set `nix-bitcoin.generateSecrets = false;` and review `modules/nix-bitcoin/secrets/secrets.nix`.

## Flake outputs

| Output | Contents |
| --- | --- |
| `nixosModules.default` (`.sovran-bitcoin`) | All modules and `sovran-bitcoin.*` options; applies the package overlay automatically. |
| `overlays.default` (`.sovran-bitcoin`) | Adds `pkgs.sovran-bitcoin.*` packages: RTL, Mempool, Alby Hub and NWC. |
| `packages.<system>.*` | `rtl`, `mempool-backend`, `mempool-frontend`, `albyhub`, `nwc`. |

Use `overlays.default` on its own if you want the packages without the NixOS module.

## License

AGPL-3.0; see `LICENSE`. Vendored MIT-licensed portions are listed in `THIRD_PARTY_NOTICES.md`.
