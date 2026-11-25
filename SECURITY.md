# Security Policy — Sovran\_Bitcoin

**Project:** `naturallaw777/Sovran_Bitcoin` — an opinionated, Tor-first Bitcoin & Lightning
stack for NixOS (bitcoind, electrs, LND, BTCPay Server, RTL, Mempool, Sovran NWC / Alby Hub, LNURL).
**Maintainer contact:** <support@sovransystems.com>

---

## 1. Scope

**In scope:** the NixOS modules, the flake, and the `sovran-nwc` Python tooling in this
repository — i.e. how the stack is configured, exposed, and sandboxed.

**Out of scope (report upstream):** vulnerabilities in the applications themselves (bitcoind,
LND, electrs, BTCPay Server / NBXplorer, RTL, Mempool, Alby Hub). Keeping the `flake.lock` pins
current is the operator's job.

**Supported:** NixOS hosts built from this flake's `nixosModules.default` with the documented
preset defaults. If you rebind a service, disable an onion service, or replace the hardening
profile, you own that delta and should re-read §2.1 — the exposure changes.

---

## 2. Trust model

The defaults try to hold three properties:

- **Loopback by default.** Every service binds `127.0.0.1`. Only two things are ever reachable
  from off-box: an onion service published by this flake, or a clearnet reverse proxy you add
  yourself (§2.1).
- **The onion address is a capability, not a credential.** A Tor v3 address is unguessable but
  it is not authentication. Whoever learns it reaches the port; the service's own credential is
  the second and only real gate. This is why an onion vhost is not a shortcut for a missing
  password.
- **Blast radius is limited at the OS and LND layers.** Units run under nix-bitcoin's strict
  systemd profile (`ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet=""`,
  `SystemCallFilter`, `IPAddressDeny=any` + local allow-list). LND access is by per-service
  macaroons: BTCPay and `sovran-nwc` are scoped, while **RTL and the `lndconnect` helpers hold the
  admin macaroon**. Secrets are generated on the host into `/etc/nix-bitcoin-secrets`
  (`0600`/`0440`) and never enter the repo or the Nix store.

### 2.1 Clearnet exposure

Two services are **clearnet-facing** by design: **BTCPay Server** and **LNURL**. Both are
functions that only work if arbitrary internet clients can reach them, so both must sit behind
your own TLS-terminating reverse proxy. Everything else in this stack is loopback-only and, if
reachable at all, reachable as a Tor onion service.

| Clearnet-facing | Loopback bind | Why it must be public |
| --- | --- | --- |
| `btcpayserver` (`features.btcpayserver`) | `127.0.0.1:23000` | Customers open checkout and pay; the server also needs to reach the public Lightning/Bitcoin network |
| `sovran-lnurl` (`features.lnurl`) | `127.0.0.1:8181` | Wallets resolve `alias@yourdomain` and fetch the callback from anywhere |

The flake deliberately provides no proxy or TLS for either — that is the operator's boundary.
Both services are otherwise identical in posture: the strict nix-bitcoin systemd profile,
`defaultHardening`, and a scoped LND macaroon rather than admin.

**Everything else is loopback-only**, on the default configuration:

- **Node and indexer:** bitcoind (P2P `:8333`, RPC `:8332`), electrs (Electrum `:50001`),
  LND (P2P `:9735`, gRPC `:10009`, REST `:8080`). None of these are clearnet-reachable and none
  should ever be — publish them as onion services if you need remote access.
- **Operator interfaces:** RTL (`:3050`), Mempool frontend (`:60845`), the `sovran-nwc`
  management API (`:18080`, no web UI). Keep these on loopback or onion, never on a
  clearnet vhost.
- **Neither BTCPay nor LNURL gets a preset onion service.** If you want them reachable over Tor
  instead of clearnet, that is a deviation you add and must then document, because it removes
  the "clearnet only" property this section relies on.

Two boundaries are worth stating plainly because they are easy to misread as network controls:

- **LNURL's guard is a credential, not a network path.** It holds an invoice-scoped daemon
  token (alias discovery and minting incoming BOLT11 invoices only; wallet creation, deletion,
  drain, and transfer answer `HTTP 403`), so a compromise of the clearnet-facing unit cannot
  reach the ledger.
- **BTCPay's guard is BTCPay's own authentication.** Its LND macaroon is scoped, but the web UI
  is a full admin surface for your store. Treat the clearnet vhost as an internet-facing
  application, not a payments endpoint that happens to be exposed.

---

## 3. Operator responsibilities

1. **Back up secrets.** `/etc/nix-bitcoin-secrets`, the LND seed
   (`/var/lib/lnd/lnd-seed-mnemonic`), and `/var/lib/albyhub`. Losing them can mean losing funds
   or access. After a suspected compromise: rotate the NWC unlock password and re-issue every
   pairing URI with `nwc-wallet rotate`.
2. **Connection URIs are credentials.** `lndconnect` / `lndconnect-grpc` embed the LND admin
   macaroon; NWC pairing URIs embed the wallet secret. Do not post, screenshot, or log them. If
   you set `lndconnect.onion = false` for a LAN client, the build fails closed unless
   `networking.firewall` is enabled and the LND REST port explicitly allowed.
3. **The reverse proxy on the two clearnet vhosts.** BTCPay and LNURL both need one. Terminate
   TLS, set a trustworthy `X-Forwarded-For` (the LNURL service keys its rate limits on the last
   hop), and enforce request-size and rate limits there. Never expose `:23000` or `:8181`
   directly, and never put `:18080` or the bitcoind RPC port on a clearnet vhost at all.
4. **Firewall** any host that binds a service off loopback.
5. Keep `nix-bitcoin.security.dbusHideProcessInformation = true` (preset default) so unit
   command lines are not readable by unprivileged local users.

---

## 4. Reporting a vulnerability

Report privately — do **not** open a public issue or PR: <support@sovransystems.com>. PGP
available on request.

Include a description, affected file(s)/commit, reproduction steps, and impact. For
`sovran-nwc` / LNURL issues, state the deployment (reverse proxy in front? onion only? mTLS?
which token scopes?).

- We acknowledge within **72 hours** and give a remediation timeline within **7 days** for
  confirmed issues.
- Please allow at least **30 days** before public disclosure.
- Reporters are credited in the advisory / changelog with their permission.
- We will not pursue legal action against researchers acting in good faith under this policy.

---

## 5. Known limitations

- **LNURL rate limiting is per-process and in-memory** (`NWC_LNURL_RATE_LIMIT_*`, defaults
  30 req/min/IP and 10 req/min/alias). It resets on restart and does not coordinate across
  instances — it is an abuse control, not a security boundary. Use proxy-side limits too.
- **Alias discovery is an existence oracle by design:** `/.well-known/lnurlp/<alias>` answers
  200 vs 404. Public Lightning Addresses are inherently enumerable; prefer unguessable aliases.
- **The `sovran-nwc` audit log** (`/var/log/sovran-nwc-audit.log`) is append-only and rotated weekly
  by a logrotate configuration installed by the NixOS module (12-week retention, compressed).
  Logrotate is auto-enabled when `services.albyhub.enable = true`.
- **The two clearnet vhosts are the whole attack surface for remote attackers.** Nothing in
  this flake rate-limits or authenticates at the edge for you: BTCPay relies on its own login,
  LNURL on its invoice-scoped token. Put both behind a proxy that does TLS, limits, and
  logging, and monitor them.
- Upstream application CVEs are out of scope here; stay current with `flake.lock`.
