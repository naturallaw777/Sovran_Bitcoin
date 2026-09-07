# Security Policy — Sovran_Bitcoin

**Project:** `naturallaw777/Sovran_Bitcoin` — an opinionated, Tor-first Bitcoin & Lightning
stack for NixOS (bitcoind, electrs, LND, BTCPay Server, RTL, Mempool, Alby Hub/NWC, LNURL).
**Maintainer contact:** <support@sovransystems.com>

---

## 1. Scope

This policy covers the NixOS **modules, flake, and the `sovran-nwc` Python tooling** in this
repository — i.e. how the stack is configured and sandboxed.

**Out of scope (report upstream):** vulnerabilities in the *upstream* applications themselves
(bitcoind, lnd, electrs, BTCPay Server / NBXplorer, RTL, Mempool, Alby Hub). For those, follow the
respective project's security process and keep your pinned `nixpkgs` / `nixpkgs-stable` revisions
current (see `flake.lock`).

Supported configurations: NixOS hosts built from this flake's `nixosModules.default` with the
documented Tor-first defaults.

---

## 2. Security model / threat model

The stack is designed around a few principles:

- **Tor-first, loopback-by-default.** Every web service binds `127.0.0.1`; clearnet is *your*
  reverse proxy's job. Public reachability is via Tor onion services first.
- **Least privilege at the OS layer.** Services run under nix-bitcoin's strict systemd profile
  (`ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet=""`, `SystemCallFilter`,
  `IPAddressDeny=any` + local allow-list, etc.) and with individually scoped LND macaroons and
  read-only bitcoind RPC users.
- **Secrets generated on the host**, written with `0600`/`0440` into `/etc/nix-bitcoin-secrets`,
  never committed to the repo or the Nix store.

**What the operator is responsible for:**
- Backing up `/etc/nix-bitcoin-secrets` **and** the LND seed (`/var/lib/lnd/lnd-seed-mnemonic`) and
  Alby Hub data dir. Loss = loss of funds/access.
- A correctly configured reverse proxy (TLS, request size limits, real `X-Forwarded-For`) in front
  of any service intentionally exposed.
- Enabling the host firewall before exposing any admin endpoint on a non-loopback interface.

---

## 3. Reporting a vulnerability

Please report security issues **privately** — do **not** open a public issue or PR for them.

- **Email:** <support@sovransystems.com>
- **PGP:** attach your public key or request ours; encrypted mail is welcome but not required.
- **Include:** a description, affected file(s)/commit, steps to reproduce, and impact. For the
  `sovran-nwc` services, note the deployment (reverse proxy in front? `lndconnect.onion` setting?).
- **Response time:** we aim to acknowledge within **72 hours** and provide a remediation timeline
  within **7 days** for confirmed issues.
- **Coordinated disclosure:** please give us a reasonable window (≥ 30 days) to ship a fix before
  public disclosure. We will credit reporters (with their permission) in the advisory / changelog.

We will not pursue legal action against researchers acting in good faith under this policy.

---

## 4. Hardening guidance for operators

These reflect the defaults and the remediations from the security audit
(`security-audit-fixes.patch`):

1. **Keep admin UIs off the clearnet.** Alby Hub (`127.0.0.1:18080`), RTL (`127.0.0.1:3050`),
   BTCPay (`127.0.0.1:23000`), and the LNURL service (`127.0.0.1:8181`) are loopback-only by
   design. Expose them only through an authenticated, TLS-terminating reverse proxy, preferably over
   their Tor onion services. **Never** open port `8181` directly to the internet.
2. **LNURL (`sovran-lnurl`)** is the only internet-adjacent component. Apply the audit patch that
   adds `nbLib.defaultHardening` + loopback-only egress to the `nwc-lnurl` unit, and keep it behind
   a proxy that (a) enforces TLS, (b) sets a trustworthy `X-Forwarded-For`, and (c) adds its own
   rate limiting. The service uses a **full Alby Hub token** (Alby Hub's unlock tokens are binary
   `full`/`read`), so the unit must stay sandboxed and loopback-only — this is a known least-privilege
   limitation, not a regression.
3. **`lndconnect`** — prefer `services.lnd.lndconnect.onion = true` (the preset default). If you set
   `onion = false` for LAN Zeus, you **must** enable `networking.firewall` and allow the LND REST
   port; otherwise the build fails closed (the audit patch enforces this).
4. **Firewall:** enable `networking.firewall` on any host that exposes a service beyond loopback.
5. **Secrets:** back up `/etc/nix-bitcoin-secrets`, the LND seed, and `/var/lib/albyhub`. Rotate the
   Alby Hub unlock password and re-issue NWC pairing URIs (`nwc-wallet rotate`) if a host is
   compromised.
6. **`nwc-wallet drain`/`delete`:** run only when the hub is healthy. The drain no longer grants the
   isolated app `pay_invoice` — the patched Alby Hub performs the internal transfer authorized by the
   manager's full token without requiring the source app to hold that scope. This requires the hub
   `sovran` branch patch that lets internal `Transfer` skip the source-app `pay_invoice` check.
7. **Keep `nix-bitcoin.security.dbusHideProcessInformation = true`** (set by the preset) so service
   command lines are not readable by unprivileged local users.

---

## 5. Known limitations

- The LNURL service requires a full Alby Hub token (Alby Hub token model constraint); containment
  relies on the systemd sandbox + loopback binding. Tracked as a least-privilege item.
- LNURL rate limiting is per-process and in-memory; it is a best-effort abuse control, not a
  substitute for a fronting proxy's limits.
- Upstream application CVEs are out of scope here; stay current with `flake.lock` pins.

---

## 6. Recognition

We thank security researchers who disclose responsibly. With permission, reporters are credited in
advisories and the changelog.

Contact: <support@sovransystems.com>
