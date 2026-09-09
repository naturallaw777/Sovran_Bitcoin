# Sovran_Bitcoin

**An opinionated, Tor-first Bitcoin stack for NixOS** — the Bitcoin/Lightning
engine of [Sovran_SystemsOS](https://git.sovransystems.com/Sovran_Systems/Sovran_SystemsOS),
packaged as a standalone flake so any NixOS user can run it.

Think *"nix-bitcoin, but Sovran-opinionated"*:

- **LND only** — no clightning, no decision fatigue
- **Tor-first** — proxied, enforced, with onion services for everything
- **Hardened** — every service runs with nix-bitcoin's strict systemd sandboxing
- **Vendored, pinned packages** — RTL, Mempool and Sovran's LND-only Alby Hub
  fork are built by this flake; BTCPay Server / NBXplorer are pinned to
  `nixos-26.05`
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
| `lndconnect`| `lndconnect` command printing a Zeus-ready QR over the REST onion    |
| secrets     | generated on first activation into `/etc/nix-bitcoin-secrets`       |
| `nodeinfo`  | run `nodeinfo` as the operator for a full status report             |

## Adding services

```nix
{
  sovran-bitcoin.features = {
    rtl = true;          # Ride The Lightning (LND web UI) on 127.0.0.1:3050
    btcpayserver = true; # BTCPay + NBXplorer (Postgres), LND backend
    mempool = true;      # Mempool explorer (MariaDB), UI on 127.0.0.1:60845
    nwc = true;          # Alby Hub (Sovran LND-only fork) on 127.0.0.1:18080
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
| RTL         | `http://127.0.0.1:3050`   | password in `/etc/nix-bitcoin-secrets/rtl-password` |
| Alby Hub UI | `http://127.0.0.1:18080`  | keep private — SSH tunnel or onion recommended  |
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
- `lndconnect` — QR / URI for Zeus & other LND connect apps
- `nwc-wallet` — manage NWC wallets from the CLI
  (talks to Alby Hub; exported with the right env when `nwc` is enabled)

  | Subcommand | What it does |
  |---|---|
  | `nwc-wallet create <name> <alias> [--qr]` | Create a wallet, print the Lightning Address and pairing URI (shown once). Pass `--qr` to also render a QR code in the terminal. |
  | `nwc-wallet list` | List all managed wallets (includes Lightning Address). |
  | `nwc-wallet lnurl <alias> [--qr]` | Show the Lightning Address, bech32 LNURL, and optionally a terminal QR code for receiving payments. |
  | `nwc-wallet lnurl <alias> --address-only` | Print only the Lightning Address (e.g. for piping). |
  | `nwc-wallet lnurl <alias> --lnurl-only` | Print only the bech32 LNURL string. |
  | `nwc-wallet drain <wallet>` | Drain funds from a wallet. `<wallet>` may be its **name**, alias, Lightning Address or id, as printed by `nwc-wallet list`. |
  | `nwc-wallet delete <wallet>` | Drain, then delete a wallet. `<wallet>` may be its **name**, alias, Lightning Address or id, as printed by `nwc-wallet list`. |
  | `nwc-wallet rotate <wallet>` | Generate a new NWC connection secret (old one is revoked). `<wallet>` accepts the same identifiers as `delete`. |
  | `nwc-wallet address show <alias>` | Test if a Lightning Address endpoint is publicly reachable. |
  | `nwc-wallet health` | Check Alby Hub health. |

  The `--qr` flag on `create` and `lnurl` renders a scannable QR code directly
  in the terminal (requires `qrencode`, which is included when `lnurl` is
  enabled via the NixOS module).

## Flake outputs

| Output | What |
|--------|------|
| `nixosModules.default` (`.sovran-bitcoin`) | all modules + `sovran-bitcoin.*` options, auto-applies the package overlay |
| `overlays.default` (`.sovran-bitcoin`) | adds `pkgs.sovran-bitcoin.*` (rtl, mempool, albyhub, nwc, pinned btcpayserver/nbxplorer) |
| `packages.<system>.*` | `rtl`, `mempool-backend`, `mempool-frontend`, `albyhub`, `nwc` |
| `nixosConfigurations.demo` | regtest VM with everything enabled — `nix run .#nixosConfigurations.demo.config.system.build.vm` |
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
