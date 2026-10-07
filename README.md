# Sovran_Bitcoin

**An opinionated, Tor-first Bitcoin stack for NixOS** — the Bitcoin/Lightning
engine of [Sovran_SystemsOS](https://git.sovransystems.com/Sovran_Systems/Sovran_SystemsOS),
packaged as a standalone flake so any NixOS user can run it.

Think *"nix-bitcoin, but Sovran-opinionated"*:

- **LND only** — no clightning, no decision fatigue
- **Flexible mobile access** — full LND management in Zeus or BitBanana, or
  optional NWC wallet connections with app-specific spending limits
- **Tor-first** — proxied, enforced, with onion services for everything
- **Hardened** — every service runs with nix-bitcoin's strict systemd sandboxing
- **Vendored packages** — RTL, Mempool and Sovran's LND-only Alby Hub
  fork are built by this flake
- **Secrets handled for you** — RPC passwords, macaroons and TLS certs are
  generated on the host at activation (`nix-bitcoin.generateSecrets`)
- **No webserver opinions** — everything binds to loopback; clearnet is *your*
  webserver's job

Vendored from [fort-nix/nix-bitcoin](https://github.com/fort-nix/nix-bitcoin)
(MIT) and Sovran_SystemsOS (AGPL-3.0) — see `THIRD_PARTY_NOTICES.md`.

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
      modules = [
        sovran-bitcoin.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

```nix
# configuration.nix — the base node
{
  sovran-bitcoin = {
    enable = true;
    operatorName = "alice";  # your user, gets bitcoin-cli / lncli / nodeinfo
  };
}
```

That gives you, with zero further config:

| Component   | What you get                                                        |
|-------------|---------------------------------------------------------------------|
| `bitcoind`  | mainnet, txindex, Tor-proxied + enforced, onion P2P, bloom filters  |
| `electrs`   | Electrum server (for Sparrow etc.), onion service                   |
| `lnd`       | Lightning node, Tor-proxied, public P2P onion                       |
| `lndconnect` | `lndconnect` command printing a Zeus-ready QR over the REST onion    |
| `lndconnect-grpc` | `lndconnect-grpc` command printing a BitBanana-ready QR over a separate gRPC onion |
| secrets     | generated on first activation into `/etc/nix-bitcoin-secrets`       |
| `nodeinfo`  | run `nodeinfo` as the operator for a full status report             |

The default preset keeps the existing REST onion/QR (`lndconnect`) for Zeus and
adds a separate gRPC onion/QR (`lndconnect-grpc`) for BitBanana. The gRPC onion
forwards to LND's loopback listener (default `127.0.0.1:10009`); it does not
bind the gRPC API to the LAN or clearnet.

## Connect from Zeus or BitBanana

Choose direct LND access for full node and channel management, or use Nostr
Wallet Connect (NWC) for a separate wallet-only connection with tighter
permissions and an optional spending cap. You can use either mode, or both.

### Direct LND access

The default preset includes two scan-to-connect options:

| App | Command | Connection |
| --- | --- | --- |
| Zeus | `lndconnect` | REST over the `lnd-rest` Tor onion (default port 8080) |
| BitBanana | `lndconnect-grpc` | gRPC over the `lnd-grpc` Tor onion (default port 10009) |

Run the matching command on the node to print its QR code. Add `--url` to print
the `lndconnect://` URI instead:

```bash
lndconnect          # Zeus
lndconnect-grpc     # BitBanana
lndconnect --url
lndconnect-grpc --url
```

Scan the QR or paste the URI into the app's node-connection screen. BitBanana
recognizes the `.onion` address and connects over Tor. The gRPC onion forwards
to LND's loopback listener; the preset does not bind that API to the LAN or
clearnet. See the [BitBanana connection guide](https://docs.bitbanana.app/setup/connect-a-lightning-node/).

**Direct-access security:** these URIs contain LND's admin macaroon, which
provides broad node control. Treat each QR/URI like a password; never post or
share them.

If configuring LND without the Sovran preset, enable the helpers and Tor
endpoints with:

```nix
services.lnd.lndconnect = {
  enable = true;
  onion = true;
  grpcOnion = true;
};
```

### Optional NWC wallet access

Enable `nwc` to run Sovran's self-hosted Alby Hub wallet service
(`lnurl = true` also enables it):

```nix
{
  sovran-bitcoin.features.nwc = true;
}
```

Create a separate connection for each app:

```bash
nwc-wallet create pocket-wallet pocket --limit-sats 5000
```

This creates an isolated wallet connection holding 5,000 sats — all it can ever
spend. Without `--limit-sats`, new connections are receive-only.
The command prints a `pairing_uri` beginning with `nostr+walletconnect://`;
copy it into the NWC wallet-connection flow in [Zeus](https://zeusln.com/blog/new-release-zeus-v0-10-0/)
or [BitBanana](https://docs.bitbanana.app/setup/connect-a-hosted-wallet/nostr-wallet-connect-uri/).

NWC is wallet access, not node management — use direct LND access above for
channels and peers. Pairing URIs are credentials: keep them private.

## Adding services

```nix
{
  sovran-bitcoin.features = {
    rtl = true;          # Ride The Lightning (LND web UI) at http://127.0.0.1:3050/rtl
    btcpayserver = true; # BTCPay + NBXplorer (Postgres), LND backend
    mempool = true;      # Mempool explorer (MariaDB), UI on 127.0.0.1:60845
    nwc = true;          # NWC via Alby Hub (no web UI; manage with nwc-wallet)
    lnurl = true;        # self-hosted Lightning Addresses via NWC + LNURL
  };

  # lnurl needs to know the public Lightning Address domain:
  services.sovran-lnurl.domain = "pay.example.com";
}
```

Dependencies are wired for you: `btcpayserver` enables NBXplorer, Postgres and
an LND macaroon with a least-privilege permission set; `lnurl` implies `nwc`;
`mempool` enables `electrs` and `txindex`. Each feature also gets an onion
service. The bitcoind wallet is disabled by default and re-enabled
automatically when `btcpayserver` is on (NBXplorer needs it).

## Clearnet is yours

The flake deliberately stops at loopback. For full clearnet operation, put
your own webserver (nginx, Caddy, …) in front:

| Service     | Local endpoint            | Notes                                          |
|-------------|---------------------------|------------------------------------------------|
| BTCPay      | `http://127.0.0.1:23000`  | reverse-proxy + TLS; see BTCPay docs for headers |
| Mempool UI  | `http://127.0.0.1:60845`  | nginx snippets are exposed (see below)          |
| LNURL       | `http://127.0.0.1:8181`   | proxy `/.well-known/lnurlp/*` and `/lnurlp/*` of your Lightning domain |

Mempool ships reusable nginx snippets for public hosting — build on
`config.services.mempool.frontend.nginxConfig.{httpConfig,staticContent,proxyApi}`.

## Plain options underneath

The preset only sets defaults (`mkDefault`). Everything stays overridable
through the regular, nix-bitcoin-style options:

```nix
{ ... }: {
  services.bitcoind.prune = 10000;       # prune to ~10 GB
  services.bitcoind.dbCache = 2000;
  services.bitcoind.dataDir = "/mnt/btc/bitcoind";
  services.lnd.extraConfig = "protocol.option-scid-alias=true"; # already default
  services.rtl.extraCurrency = "USD";    # fiat display (relaxes Tor for RTL)
  services.albyhub.relay = "wss://relay.example.com";  # sovereign Nostr relay
  services.sovran-lnurl.domainFile = "/var/lib/secrets/lightning-domain";
  services.mempool.frontend.settings.BASE_MODULE = "liquid";
  nix-bitcoin.onionServices.rtl.enable = false;
}
```

Disable a piece of the base stack:

```nix
{ ... }: {
  sovran-bitcoin.features.electrs = false; # you probably want it for mempool/Sparrow
}
```

## Tools on the system

- `bitcoin-cli`, `lncli` — as the operator user
- `nodeinfo` — service/onion status report
- `lndconnect` — REST QR / URI for Zeus and other LND REST clients
- `lndconnect-grpc` — gRPC QR / URI for BitBanana and other gRPC clients
- `nwc-wallet` — manage NWC wallets from the CLI
  (Sovran's Alby Hub fork has **no web UI**; this CLI is the operator
  interface. Env is baked in when `nwc` is enabled.)

  | Subcommand | What it does |
  |---|---|
  | `nwc-wallet create <name> <alias> [--receive-only | --limit-sats SATS] [--qr]` | Create an isolated NWC connection. Receive-only by default; `--limit-sats` funds it with that many sats. The pairing URI is shown once. `--qr` prints a Lightning Address QR, not the pairing URI. |
  | `nwc-wallet list` | List all managed wallets (includes Lightning Address). |
  | `nwc-wallet lnurl <alias> [--qr]` | Show the Lightning Address, bech32 LNURL, and optionally a terminal QR code for receiving payments. |
  | `nwc-wallet lnurl <alias> --address-only` | Print only the Lightning Address (e.g. for piping). |
  | `nwc-wallet lnurl <alias> --lnurl-only` | Print only the bech32 LNURL string. |
  | `nwc-wallet drain <wallet>` | Drain funds from a wallet. |
  | `nwc-wallet delete <wallet>` | Drain, then delete a wallet. |
  | `nwc-wallet rotate <wallet>` | Generate a new NWC connection secret (old one is revoked). |
  | `nwc-wallet address show <alias>` | Test if a Lightning Address endpoint is publicly reachable. |
  | `nwc-wallet health` | Check Alby Hub health. |

  For `drain`, `delete` and `rotate`, `<wallet>` may be the name, alias,
  Lightning Address or id from `nwc-wallet list`. `--qr` renders a QR in the
  terminal (requires `qrencode`, included when `lnurl` is enabled).

## Flake outputs

| Output | What |
|--------|------|
| `nixosModules.default` (`.sovran-bitcoin`) | all modules + `sovran-bitcoin.*` options, auto-applies the package overlay |
| `overlays.default` (`.sovran-bitcoin`) | adds `pkgs.sovran-bitcoin.*` (rtl, mempool, albyhub and nwc) |
| `packages.<system>.*` | `rtl`, `mempool-backend`, `mempool-frontend`, `albyhub`, `nwc` |
| `checks.<system>.*` | evaluation checks + the BTCPay/bitcoind hardening test |

If you don't want the overlay auto-applied, import `./modules` from this repo
in your own wrapper and add `overlays.default` yourself.

## Secrets

Secrets are generated on the host into `/etc/nix-bitcoin-secrets`
(`nix-bitcoin.secretsDir`) by the one-shot `setup-secrets` service at
activation, with per-service ownership (lnd certs, RTL password, bitcoind RPC
HMACs, macaroons). **Back this directory up** — losing the LND wallet seed
(`~lnd data dir/lnd-seed-mnemonic`, `0600`) or the secrets dir means losing
funds/access. To manage secrets yourself, set `nix-bitcoin.generateSecrets =
false;` and study the vendored `modules/nix-bitcoin/secrets/secrets.nix`.

## Deviations from Sovran_SystemsOS (on purpose)

- No `/run/media/Second_Drive/...` data dirs — everything under `/var/lib`
- No Sovran Hub coupling: NWC/LNURL run as plain `systemd` units, and the
  LNURL domain is an option (`services.sovran-lnurl.domain` / `.domainFile`)
  instead of the Hub's `/var/lib/domains/lightning`
- No firewall port 3051 (that was the Hub)
- `disablewallet` is only enabled when BTCPay is *off* (the OS enables it
  unconditionally)
- Operator user defaults to `operator` instead of `free`

## License

AGPL-3.0 (see `LICENSE`), with vendored MIT-licensed portions from
nix-bitcoin (`THIRD_PARTY_NOTICES.md`).
