"""Sovran NWC Daemon — pure-stdlib LND-only Nostr Wallet Connect (NIP-47) server.

Replaces the external Go Alby Hub fork with a self-contained, auditable,
Nix-native Python daemon using only the Python 3 standard library:
  - SQLite (`sqlite3`) with WAL mode and atomic `BEGIN IMMEDIATE` sub-wallet ledger
  - Direct LND REST (`nwc_lnd.py`) with `private=True` route hints
  - Pure-stdlib BIP-340 Schnorr, NIP-04, NIP-44 v2, and WebSocket relay client (`nwc_nostr.py`)
  - Loopback management API (`127.0.0.1:18080`) with least-privilege token scopes:
      * `full`    — wallet creation, transfers, drain, delete (`nwc-wallet` CLI)
      * `invoice` — alias lookup and incoming invoice creation only (`nwc-lnurl` service)
      * `read`    — read-only inspection
    Scopes are bound to *credentials*, not to what a caller requests: the
    unlock password may mint any scope, while a scoped credential (e.g. the
    invoice-only secret held by `nwc-lnurl`) can only mint its own.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import sqlite3
import threading
import time
import urllib.parse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import nwc_audit as _audit_mod
from . import nwc_lnd as _lnd_mod
from . import nwc_nostr as _nostr_mod

logger = logging.getLogger(__name__)

# ── Method / Scope mapping (NIP-47) ───────────────────────────────

SCOPE_TO_NIP47_METHODS = {
    "get_info": ["get_info"],
    "get_balance": ["get_balance"],
    "make_invoice": ["make_invoice"],
    "lookup_invoice": ["lookup_invoice"],
    # `lookup_payment` (NWC-09) reconciles a single payment record; it is
    # granted both to history readers and to spenders reconciling their own
    # payments after a timeout or missed notification.
    "list_transactions": ["list_transactions", "lookup_payment"],
    # The spend scope covers every way to send: invoice payments and
    # keysend (NWC-04). The deprecated multi_pay_* commands are deliberately
    # not offered — they were removed from NIP-47 and only exist as an
    # Alby Hub legacy dialect.
    "pay_invoice": ["pay_invoice", "pay_keysend", "lookup_payment"],
    # NWC-13: budget visibility is a permission of its own, independent of
    # `get_balance` (a connection may see its allowance, not the balance).
    "get_budget": ["get_budget"],
}

# Every method this daemon knows how to handle, in any scope. Anything else
# is answered NOT_IMPLEMENTED (rather than RESTRICTED, which would claim the
# method exists but this wallet may not use it).
ALL_KNOWN_NIP47_METHODS = frozenset(
    m for methods in SCOPE_TO_NIP47_METHODS.values() for m in methods
)


def scopes_to_nip47_methods(scopes: list[str]) -> list[str]:
    methods: list[str] = []
    for scope in scopes:
        for m in SCOPE_TO_NIP47_METHODS.get(scope, []):
            if m not in methods:
                methods.append(m)
    return methods


# Optional NWC extension specs (https://github.com/nostr-wallet-connect/nwc)
# that this daemon actually implements. Advertised in the `extensions` tag
# of the 13194 info event (NIP-47) and in the `extensions` array of the
# `get_info` result, so clients can discover support without guessing.
def scopes_to_nwc_extensions(scopes: list[str]) -> list[str]:
    methods = set(scopes_to_nip47_methods(scopes))
    out: list[str] = []
    if "notifications" in scopes:
        out.append("02")  # NWC-02 notifications
    if "pay_keysend" in methods:
        out.append("04")  # NWC-04 keysend payments
    if "list_transactions" in methods:
        out.append("05")  # NWC-05 transaction history
    if "lookup_payment" in methods:
        out.append("09")  # NWC-09 payment lookup
    if "get_budget" in methods:
        out.append("13")  # NWC-13 connection budgets
    return sorted(out)


# ── Request validation limits ─────────────────────────────────────
#
# A NIP-47 request is unauthenticated beyond its Schnorr signature: anybody
# who holds a pairing URI secret can sign one, and a relay operator can replay
# any signed request it has ever seen. These limits bound how far the daemon
# trusts that event.
REQUEST_MAX_AGE_SEC = int(os.environ.get("NWC_REQUEST_MAX_AGE", "600"))
REQUEST_MAX_FUTURE_SKEW_SEC = int(os.environ.get("NWC_REQUEST_MAX_FUTURE_SKEW", "300"))
# Per-connection request budget (NIP-47 `RATE_LIMITED`).
NIP47_RATE_LIMIT_PER_MIN = int(os.environ.get("NWC_NIP47_RATE_LIMIT", "60"))
# Upper bound on a client-requested invoice expiry (seconds).
MAX_INVOICE_EXPIRY_SEC = int(os.environ.get("NWC_MAX_INVOICE_EXPIRY", "604800"))
# Bound on API/NIP-47 page sizes so one caller cannot force an unbounded scan.
MAX_PAGE_SIZE = 500
# Keep extension methods out of the `get_info.methods` array (and out of the
# method list in the 13194 info event). NWC-09/NWC-13 ask for these to be
# advertised, but the rust-nostr client library used by BitBanana <= 1.1.x
# (nostr-sdk 0.43) deserializes methods into a *closed* enum: one unknown name
# makes the whole get_info response fail to parse, so the app reports a broken
# connection even though the daemon works. Such clients discover these
# extensions through the `extensions` tag instead. Set
# NWC_ADVERTISE_EXTENSION_METHODS=1 to advertise them again once those clients
# are gone; the methods themselves keep working either way.
ADVERTISE_EXTENSION_METHODS = os.environ.get(
    "NWC_ADVERTISE_EXTENSION_METHODS", "0"
).strip().lower() in ("1", "true", "yes", "on")

# Extension methods withheld from the advertisement unless the opt-in is set.
# Only names that post-date the widely deployed closed-enum clients belong
# here; core NIP-47 methods are always advertised.
EXTENSION_ONLY_METHODS = frozenset({"lookup_payment", "get_budget"})


def advertised_methods(methods: list[str] | set[str]) -> list[str]:
    """Methods safe to put on the wire for every deployed NWC client."""
    names = set(methods)
    if not ADVERTISE_EXTENSION_METHODS:
        names -= EXTENSION_ONLY_METHODS
    return sorted(names)


def compressed_pubkey(hex_key: str) -> str:
    """Return the 33-byte SEC compressed form of a 32-byte x-only key.

    NIP-47 leaves the curve encoding of `get_info.pubkey` to the wallet, but
    rust-nostr 0.43 (the NWC stack in BitBanana <= 1.1.x) types the field as
    `secp256k1::PublicKey`, which only accepts a 33-byte compressed key. A
    64-char x-only key makes the whole response fail to deserialize
    (`CantDeserializeResponse`), which the app reports as a failed connection.
    `get_info.pubkey` is the wallet's *own* key (a Nostr pubkey), so `02` is
    the canonical, unambiguous prefix. Keys that are already 33 bytes (or
    anything else) are returned unchanged.
    """
    key = str(hex_key or "").strip().lower()
    if len(key) == 64:
        try:
            bytes.fromhex(key)
        except ValueError:
            return hex_key
        return "02" + key
    return hex_key


# Cap on simultaneously-pending incoming invoices per wallet. Every pending
# ledger row is also an OPEN invoice in LND's invoice table (a node-global,
# ~1000-entry resource shared with RTL/BTCPay), so an uncapped wallet (or the
# public LNURL path) could exhaust it. Expired invoices stop counting as soon
# as the watcher sweeps them. `0` disables the cap.
MAX_PENDING_INVOICES_PER_WALLET = int(os.environ.get("NWC_MAX_PENDING_INVOICES", "200"))


def _as_int(value: Any, default: int | None = None) -> int | None:
    """Coerce a client-supplied value to int, or return *default* when invalid.

    JSON-RPC params are attacker-controlled: a string like "abc" or a float
    must produce a NIP-47 error, never an unhandled ValueError.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip(), 10)
        except (TypeError, ValueError):
            return default
    return default


def _strict_int(qs: dict[str, list[str]], key: str, default: int, lo: int, hi: int) -> int:
    """Parse a query-string integer strictly (400 instead of silent default).

    Operator-facing endpoints should reject `?limit=abc` so a broken script is
    visible, rather than quietly serving a default page.
    """
    raw = (qs.get(key) or [None])[0]
    if raw is None or raw == "":
        return max(lo, min(default, hi))
    parsed = _as_int(raw, None)
    if parsed is None:
        raise ValueError(f"{key} must be an integer")
    if not (lo <= parsed <= hi):
        raise ValueError(f"{key} must be between {lo} and {hi}")
    return parsed


def _bounded(value: Any, default: int, lo: int, hi: int) -> int:
    parsed = _as_int(value, default)
    if parsed is None:
        parsed = default
    return max(lo, min(int(parsed), hi))


BUDGET_PERIODS = ("daily", "weekly", "monthly", "yearly", "never")


def _budget_period_window(
    period: str, now_ts: int
) -> tuple[int | None, int | None]:
    """`(period_start, renews_at)` in UTC for a budget renewal period.

    Budgets reset at UTC calendar boundaries: midnight (daily), Monday
    00:00 (weekly), the 1st (monthly), Jan 1 (yearly). `never` — and any
    unrecognised value, defensively — has no window: usage counts all-time
    and there is no renewal timestamp.
    """
    import datetime as _dt

    p = (period or "never").strip().lower()
    if p not in BUDGET_PERIODS or p == "never":
        return None, None
    now = _dt.datetime.fromtimestamp(int(now_ts), tz=_dt.timezone.utc)
    if p == "daily":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        nxt = start + _dt.timedelta(days=1)
    elif p == "weekly":
        start = (now - _dt.timedelta(days=now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        nxt = start + _dt.timedelta(days=7)
    elif p == "monthly":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        nxt = (
            start.replace(year=start.year + 1, month=1)
            if start.month == 12
            else start.replace(month=start.month + 1)
        )
    else:  # yearly
        start = now.replace(
            month=1, day=1, hour=0, minute=0, second=0, microsecond=0
        )
        nxt = start.replace(year=start.year + 1)
    return int(start.timestamp()), int(nxt.timestamp())


# ── SQLite Sub-Wallet Ledger Store ────────────────────────────────


class NwcStoreError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class NwcStore:
    """Thread-safe SQLite store for isolated NWC sub-wallets and transactions."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA busy_timeout=5000;")
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS sovran_apps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    app_pubkey TEXT NOT NULL UNIQUE,
                    wallet_privkey TEXT NOT NULL,
                    wallet_pubkey TEXT NOT NULL UNIQUE,
                    isolated INTEGER NOT NULL DEFAULT 1,
                    balance_msat INTEGER NOT NULL DEFAULT 0,
                    max_amount_sat INTEGER NOT NULL DEFAULT 0,
                    budget_renewal TEXT NOT NULL DEFAULT 'never',
                    scopes_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sovran_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    amount_msat INTEGER NOT NULL DEFAULT 0,
                    fees_paid_msat INTEGER NOT NULL DEFAULT 0,
                    fee_reserve_msat INTEGER NOT NULL DEFAULT 0,
                    payment_hash TEXT NOT NULL DEFAULT '',
                    invoice TEXT NOT NULL DEFAULT '',
                    preimage TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    description_hash TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    settled_at INTEGER,
                    FOREIGN KEY (app_id) REFERENCES sovran_apps(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_sovran_tx_app_id
                    ON sovran_transactions(app_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_sovran_tx_payment_hash
                    ON sovran_transactions(payment_hash);
                CREATE INDEX IF NOT EXISTS idx_sovran_tx_state
                    ON sovran_transactions(state);

                CREATE TABLE IF NOT EXISTS sovran_processed_events (
                    event_id TEXT PRIMARY KEY,
                    processed_at INTEGER NOT NULL
                );
                """
            )

    def _row_to_app_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        app_id = int(row["id"])
        cur = self._conn.execute(
            "SELECT COUNT(*) AS cnt FROM sovran_transactions WHERE app_id = ? AND state = 'pending'",
            (app_id,),
        )
        pending_cnt = int(cur.fetchone()["cnt"])
        try:
            scopes = json.loads(row["scopes_json"])
        except Exception:
            scopes = []
        try:
            metadata = json.loads(row["metadata_json"])
        except Exception:
            metadata = {}
        return {
            "id": app_id,
            "name": row["name"],
            "isolated": bool(row["isolated"]),
            "appPubkey": row["app_pubkey"],
            "nostrPubkey": row["app_pubkey"],
            "walletPubkey": row["wallet_pubkey"],
            "balanceMsat": int(row["balance_msat"]),
            "maxAmountSat": int(row["max_amount_sat"]),
            "budgetRenewal": row["budget_renewal"],
            "scopes": scopes,
            "metadata": metadata,
            "createdAt": row["created_at"],
            "pendingTransactionsCount": pending_cnt,
        }

    def list_apps(self, limit: int = 100, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        with self._lock:
            total = int(
                self._conn.execute("SELECT COUNT(*) AS cnt FROM sovran_apps").fetchone()["cnt"]
            )
            rows = self._conn.execute(
                "SELECT * FROM sovran_apps ORDER BY id ASC LIMIT ? OFFSET ?",
                (int(limit), int(offset)),
            ).fetchall()
            return [self._row_to_app_dict(r) for r in rows], total

    def get_all_active_apps_internal(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM sovran_apps ORDER BY id ASC").fetchall()
            out = []
            for r in rows:
                d = self._row_to_app_dict(r)
                d["wallet_privkey"] = r["wallet_privkey"]
                out.append(d)
            return out

    def get_app(self, app_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sovran_apps WHERE id = ?", (int(app_id),)
            ).fetchone()
            return self._row_to_app_dict(row) if row else None

    def known_wallet_pubkeys(self) -> set[str]:
        """Return every wallet pubkey this daemon serves (for a cheap pre-filter)."""
        with self._lock:
            rows = self._conn.execute("SELECT wallet_pubkey FROM sovran_apps").fetchall()
        return {str(r["wallet_pubkey"]).lower() for r in rows}

    def get_app_internal_by_pubkeys(
        self, client_pubkey: str, wallet_pubkey: str | None = None
    ) -> dict[str, Any] | None:
        with self._lock:
            if wallet_pubkey:
                row = self._conn.execute(
                    "SELECT * FROM sovran_apps WHERE app_pubkey = ? AND wallet_pubkey = ?",
                    (client_pubkey.lower(), wallet_pubkey.lower()),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT * FROM sovran_apps WHERE app_pubkey = ?",
                    (client_pubkey.lower(),),
                ).fetchone()
            if not row:
                return None
            d = self._row_to_app_dict(row)
            d["wallet_privkey"] = row["wallet_privkey"]
            return d

    def create_app(
        self,
        name: str,
        scopes: list[str],
        isolated: bool,
        max_amount_sat: int,
        budget_renewal: str,
        metadata: dict[str, Any],
        relays: list[str],
    ) -> dict[str, Any]:
        if not name or not str(name).strip():
            raise NwcStoreError("invalid_name", "App name is required", 400)

        client_priv = secrets.token_bytes(32)
        client_pub_hex = _nostr_mod.pubkey_from_privkey(client_priv).hex()

        wallet_priv = secrets.token_bytes(32)
        wallet_pub_hex = _nostr_mod.pubkey_from_privkey(wallet_priv).hex()

        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    """
                    INSERT INTO sovran_apps (
                        name, app_pubkey, wallet_privkey, wallet_pubkey,
                        isolated, balance_msat, max_amount_sat, budget_renewal,
                        scopes_json, metadata_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(name).strip(),
                        client_pub_hex,
                        wallet_priv.hex(),
                        wallet_pub_hex,
                        1 if isolated else 0,
                        int(max_amount_sat or 0),
                        str(budget_renewal or "never"),
                        json.dumps(list(scopes)),
                        json.dumps(metadata or {}),
                        created_at,
                    ),
                )
                app_id = int(cur.lastrowid)
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

            row = self._conn.execute(
                "SELECT * FROM sovran_apps WHERE id = ?", (app_id,)
            ).fetchone()
            app_dict = self._row_to_app_dict(row)

        relay_parts = [
            f"relay={urllib.parse.quote(r.strip(), safe='')}"
            for r in relays
            if r.strip()
        ]
        if not relay_parts:
            relay_parts = ["relay=wss%3A%2F%2Frelay.getalby.com"]
        query = "&".join(relay_parts + [f"secret={client_priv.hex()}"])
        pairing_uri = f"nostr+walletconnect://{wallet_pub_hex}?{query}"

        result = dict(app_dict)
        result["pairingUri"] = pairing_uri
        result["wallet_privkey"] = wallet_priv.hex()
        return result

    def delete_app_by_pubkey(self, app_pubkey: str) -> bool:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    "DELETE FROM sovran_apps WHERE lower(app_pubkey) = ?",
                    (app_pubkey.strip().lower(),),
                )
                deleted = cur.rowcount > 0
                cur.execute("COMMIT")
                return deleted
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def total_allocated_msat(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(balance_msat), 0) AS total FROM sovran_apps WHERE isolated = 1"
            ).fetchone()
            return int(row["total"])

    def transfer(
        self,
        from_app_id: int | None,
        to_app_id: int | None,
        amount_msat: int,
        description: str = "",
    ) -> dict[str, Any]:
        if amount_msat <= 0:
            raise NwcStoreError("invalid_amount", "Transfer amount must be positive", 400)
        if from_app_id is None and to_app_id is None:
            raise NwcStoreError("invalid_transfer", "Must specify fromAppId or toAppId", 400)

        now = int(time.time())
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                if from_app_id is not None:
                    src = cur.execute(
                        "SELECT id, balance_msat FROM sovran_apps WHERE id = ?",
                        (int(from_app_id),),
                    ).fetchone()
                    if src is None:
                        raise NwcStoreError("not_found", "Source app not found", 404)
                    if int(src["balance_msat"]) < amount_msat:
                        raise NwcStoreError(
                            "insufficient_balance",
                            "Source wallet has insufficient balance",
                            400,
                        )
                    cur.execute(
                        "UPDATE sovran_apps SET balance_msat = balance_msat - ? WHERE id = ?",
                        (int(amount_msat), int(from_app_id)),
                    )
                    cur.execute(
                        """
                        INSERT INTO sovran_transactions (
                            app_id, type, state, amount_msat, fees_paid_msat,
                            description, created_at, settled_at
                        ) VALUES (?, 'outgoing', 'settled', ?, 0, ?, ?, ?)
                        """,
                        (int(from_app_id), int(amount_msat), description or "Internal transfer", now, now),
                    )

                if to_app_id is not None:
                    dst = cur.execute(
                        "SELECT id FROM sovran_apps WHERE id = ?",
                        (int(to_app_id),),
                    ).fetchone()
                    if dst is None:
                        raise NwcStoreError("not_found", "Destination app not found", 404)
                    cur.execute(
                        "UPDATE sovran_apps SET balance_msat = balance_msat + ? WHERE id = ?",
                        (int(amount_msat), int(to_app_id)),
                    )
                    cur.execute(
                        """
                        INSERT INTO sovran_transactions (
                            app_id, type, state, amount_msat, fees_paid_msat,
                            description, created_at, settled_at
                        ) VALUES (?, 'incoming', 'settled', ?, 0, ?, ?, ?)
                        """,
                        (int(to_app_id), int(amount_msat), description or "Internal transfer", now, now),
                    )

                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

        return {"ok": True, "amountMsat": int(amount_msat)}

    def record_incoming_invoice(
        self,
        app_id: int,
        payment_hash: str,
        invoice: str,
        amount_msat: int,
        description: str,
        description_hash: str,
        created_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        with self._lock:
            app = self.get_app(app_id)
            if app is None:
                raise NwcStoreError("not_found", "Target app not found", 404)
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                # Race-proof backstop for the per-wallet pending cap (the
                # daemon pre-checks before creating the LND invoice, so this
                # only fires when two creators race past the pre-check).
                if MAX_PENDING_INVOICES_PER_WALLET > 0:
                    pending_count = int(
                        cur.execute(
                            """
                            SELECT COUNT(*) AS n FROM sovran_transactions
                            WHERE app_id = ? AND type = 'incoming' AND state = 'pending'
                            """,
                            (int(app_id),),
                        ).fetchone()["n"]
                    )
                    if pending_count >= MAX_PENDING_INVOICES_PER_WALLET:
                        raise NwcStoreError(
                            "QUOTA_EXCEEDED",
                            "Too many pending invoices for this wallet; "
                            "wait for some to settle or expire",
                            429,
                        )
                cur.execute(
                    """
                    INSERT INTO sovran_transactions (
                        app_id, type, state, amount_msat, fees_paid_msat,
                        payment_hash, invoice, description, description_hash,
                        created_at, expires_at
                    ) VALUES (?, 'incoming', 'pending', ?, 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(app_id),
                        int(amount_msat),
                        payment_hash.lower(),
                        invoice,
                        description or "",
                        description_hash.lower(),
                        int(created_at),
                        int(expires_at),
                    ),
                )
                tx_id = int(cur.lastrowid)
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
            row = self._conn.execute(
                "SELECT * FROM sovran_transactions WHERE id = ?", (tx_id,)
            ).fetchone()
            return self._row_to_tx_dict(row)

    def settle_incoming_by_payment_hash(
        self,
        payment_hash: str,
        amount_msat: int | None = None,
        preimage: str = "",
        settled_at: int | None = None,
    ) -> tuple[dict[str, Any] | None, bool]:
        """Mark a pending incoming invoice as settled and credit the sub-wallet.

        Returns `(tx_dict, newly_settled)`.
        """
        ph = payment_hash.strip().lower()
        now = int(settled_at or time.time())
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE payment_hash = ? AND type = 'incoming'
                    ORDER BY id DESC LIMIT 1
                    """,
                    (ph,),
                ).fetchone()
                if row is None:
                    cur.execute("COMMIT")
                    return None, False
                if row["state"] == "settled":
                    cur.execute("COMMIT")
                    return self._row_to_tx_dict(row), False

                credit_msat = int(amount_msat if amount_msat is not None else row["amount_msat"])
                cur.execute(
                    """
                    UPDATE sovran_transactions
                    SET state = 'settled',
                        amount_msat = ?,
                        preimage = CASE WHEN ? != '' THEN ? ELSE preimage END,
                        settled_at = ?
                    WHERE id = ?
                    """,
                    (credit_msat, preimage.lower(), preimage.lower(), now, int(row["id"])),
                )
                cur.execute(
                    "UPDATE sovran_apps SET balance_msat = balance_msat + ? WHERE id = ?",
                    (credit_msat, int(row["app_id"])),
                )
                cur.execute("COMMIT")
                updated = self._conn.execute(
                    "SELECT * FROM sovran_transactions WHERE id = ?", (int(row["id"]),)
                ).fetchone()
                return self._row_to_tx_dict(updated), True
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def list_pending_incoming(self, app_id: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if app_id is not None:
                rows = self._conn.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE app_id = ? AND type = 'incoming' AND state = 'pending' AND payment_hash != ''
                    """,
                    (int(app_id),),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE type = 'incoming' AND state = 'pending' AND payment_hash != ''
                    """
                ).fetchall()
            return [self._row_to_tx_dict(r) for r in rows]

    def pending_incoming_count(self, app_id: int) -> int:
        """Number of pending (unsettled, unexpired) incoming invoices a wallet holds."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS n FROM sovran_transactions
                WHERE app_id = ? AND type = 'incoming' AND state = 'pending'
                """,
                (int(app_id),),
            ).fetchone()
            return int(row["n"])

    def close_incoming_by_payment_hash(
        self, payment_hash: str, state: str = "expired"
    ) -> dict[str, Any] | None:
        """Transition a *pending* incoming invoice to a terminal closed state.

        Only `pending -> expired` happens here (invoice expiry, or LND-side
        cancellation). Settlement has its own path
        (`settle_incoming_by_payment_hash`) because it moves money; a row that
        already settled is never closed by this method, so a settle racing the
        expiry sweep always wins. Returns the updated row, or None when the
        invoice was not pending.
        """
        if state not in ("expired", "failed"):
            raise ValueError(f"invalid closed state: {state}")
        ph = payment_hash.strip().lower()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE payment_hash = ? AND type = 'incoming' AND state = 'pending'
                    ORDER BY id DESC LIMIT 1
                    """,
                    (ph,),
                ).fetchone()
                if row is None:
                    cur.execute("COMMIT")
                    return None
                cur.execute(
                    "UPDATE sovran_transactions SET state = ? WHERE id = ?",
                    (state, int(row["id"])),
                )
                cur.execute("COMMIT")
                updated = self._conn.execute(
                    "SELECT * FROM sovran_transactions WHERE id = ?", (int(row["id"]),)
                ).fetchone()
                return self._row_to_tx_dict(updated)
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def find_tx_for_app(
        self, app_id: int, payment_hash: str = "", invoice: str = ""
    ) -> dict[str, Any] | None:
        with self._lock:
            if payment_hash:
                row = self._conn.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE app_id = ? AND payment_hash = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (int(app_id), payment_hash.strip().lower()),
                ).fetchone()
            elif invoice:
                row = self._conn.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE app_id = ? AND invoice = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (int(app_id), invoice.strip()),
                ).fetchone()
            else:
                return None
            return self._row_to_tx_dict(row) if row else None

    def set_preimage_for_hash(self, payment_hash: str, preimage: str) -> int:
        """Record the real payment preimage on every ledger row with this hash.

        Used when an internal self-payment settles an invoice whose stored
        preimage is missing (e.g. rows created before preimages were kept).
        """
        ph = payment_hash.strip().lower()
        pre = preimage.strip().lower()
        if not ph or not pre:
            return 0
        with self._lock:
            cur = self._conn.execute(
                "UPDATE sovran_transactions SET preimage = ? WHERE payment_hash = ?",
                (pre, ph),
            )
            return int(cur.rowcount or 0)

    def list_transactions(
        self,
        app_id: int | None = None,
        limit: int = 50,
        offset: int = 0,
        tx_type: str | None = None,
        unpaid: bool = False,
        from_ts: int | None = None,
        until_ts: int | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if app_id is not None:
            clauses.append("app_id = ?")
            params.append(int(app_id))
        if tx_type in ("incoming", "outgoing"):
            clauses.append("type = ?")
            params.append(tx_type)
        if not unpaid:
            # NIP-47 / NWC-05: settled transactions only unless `unpaid` is set.
            clauses.append("state = 'settled'")
        if from_ts is not None:
            clauses.append("created_at >= ?")
            params.append(int(from_ts))
        if until_ts is not None:
            clauses.append("created_at <= ?")
            params.append(int(until_ts))

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            total = int(
                self._conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM sovran_transactions {where}",
                    tuple(params),
                ).fetchone()["cnt"]
            )
            rows = self._conn.execute(
                f"SELECT * FROM sovran_transactions {where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                tuple(params) + (int(limit), int(offset)),
            ).fetchall()
            return [self._row_to_tx_dict(r) for r in rows], total

    def reserve_outgoing_payment(
        self,
        app_id: int,
        amount_msat: int,
        fee_reserve_msat: int,
        payment_hash: str,
        invoice: str,
        description: str,
        description_hash: str,
    ) -> tuple[int, int | None]:
        """Atomically reserve funds for an outgoing payment or settle internally if self-payment.

        Returns `(outgoing_tx_id, internal_settled_payee_app_id)`.
        """
        now = int(time.time())
        ph = payment_hash.strip().lower()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                app = cur.execute(
                    "SELECT * FROM sovran_apps WHERE id = ?", (int(app_id),)
                ).fetchone()
                if app is None:
                    raise NwcStoreError("NOT_FOUND", "Wallet not found", 404)

                # Check if this invoice is a pending incoming invoice on this same node
                internal_inc = None
                if ph:
                    internal_inc = cur.execute(
                        """
                        SELECT * FROM sovran_transactions
                        WHERE payment_hash = ? AND type = 'incoming' AND state = 'pending'
                        ORDER BY id DESC LIMIT 1
                        """,
                        (ph,),
                    ).fetchone()

                if internal_inc is not None:
                    # Internal self-payment: 0 fee reserve required
                    if int(app["balance_msat"]) < amount_msat:
                        raise NwcStoreError(
                            "INSUFFICIENT_BALANCE",
                            "The wallet does not have enough balance to make this payment",
                            400,
                        )
                    self._check_budget_locked(cur, app, amount_msat)
                    payee_app_id = int(internal_inc["app_id"])
                    cur.execute(
                        "UPDATE sovran_apps SET balance_msat = balance_msat - ? WHERE id = ?",
                        (int(amount_msat), int(app_id)),
                    )
                    cur.execute(
                        "UPDATE sovran_apps SET balance_msat = balance_msat + ? WHERE id = ?",
                        (int(amount_msat), payee_app_id),
                    )
                    cur.execute(
                        """
                        UPDATE sovran_transactions
                        SET state = 'settled', amount_msat = ?, settled_at = ?
                        WHERE id = ?
                        """,
                        (int(amount_msat), now, int(internal_inc["id"])),
                    )
                    cur.execute(
                        """
                        INSERT INTO sovran_transactions (
                            app_id, type, state, amount_msat, fees_paid_msat, fee_reserve_msat,
                            payment_hash, invoice, preimage, description, description_hash,
                            created_at, settled_at
                        ) VALUES (?, 'outgoing', 'settled', ?, 0, 0, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            int(app_id),
                            int(amount_msat),
                            ph,
                            invoice,
                            # Real preimage only — never fabricate one. The
                            # caller resolves it from LND when missing so the
                            # value is verifiable (sha256(preimage) == hash).
                            internal_inc["preimage"] or "",
                            description,
                            description_hash,
                            now,
                            now,
                        ),
                    )
                    out_id = int(cur.lastrowid)
                    cur.execute("COMMIT")
                    return out_id, payee_app_id

                # External Lightning payment: reserve amount + fee_reserve
                total_reserve = int(amount_msat) + int(fee_reserve_msat)
                if int(app["balance_msat"]) < total_reserve:
                    raise NwcStoreError(
                        "INSUFFICIENT_BALANCE",
                        "The wallet does not have enough balance to make this payment (including fee reserve)",
                        400,
                    )
                self._check_budget_locked(cur, app, total_reserve)

                cur.execute(
                    "UPDATE sovran_apps SET balance_msat = balance_msat - ? WHERE id = ?",
                    (total_reserve, int(app_id)),
                )
                cur.execute(
                    """
                    INSERT INTO sovran_transactions (
                        app_id, type, state, amount_msat, fees_paid_msat, fee_reserve_msat,
                        payment_hash, invoice, description, description_hash, created_at
                    ) VALUES (?, 'outgoing', 'pending', ?, 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(app_id),
                        int(amount_msat),
                        int(fee_reserve_msat),
                        ph,
                        invoice,
                        description,
                        description_hash,
                        now,
                    ),
                )
                out_id = int(cur.lastrowid)
                cur.execute("COMMIT")
                return out_id, None
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def budget_used_msat(self, app_id: int, since: int | None = None) -> int:
        """Outgoing msat counting against the budget (settled + in-flight).

        This is exactly the figure budget enforcement uses, so `get_budget`
        can never disagree with the gate that refuses payments.
        """
        with self._lock:
            if since is not None:
                row = self._conn.execute(
                    """
                    SELECT COALESCE(SUM(amount_msat + fees_paid_msat + fee_reserve_msat), 0) AS used
                    FROM sovran_transactions
                    WHERE app_id = ? AND type = 'outgoing' AND state IN ('settled', 'pending')
                      AND created_at >= ?
                    """,
                    (int(app_id), int(since)),
                ).fetchone()
            else:
                row = self._conn.execute(
                    """
                    SELECT COALESCE(SUM(amount_msat + fees_paid_msat + fee_reserve_msat), 0) AS used
                    FROM sovran_transactions
                    WHERE app_id = ? AND type = 'outgoing' AND state IN ('settled', 'pending')
                    """,
                    (int(app_id),),
                ).fetchone()
            return int(row["used"])

    def _check_budget_locked(
        self, cur: sqlite3.Cursor, app_row: sqlite3.Row, needed_msat: int
    ) -> None:
        max_sat = int(app_row["max_amount_sat"] or 0)
        if max_sat <= 0:
            return
        max_msat = max_sat * 1000
        since, _renews = _budget_period_window(
            str(app_row["budget_renewal"] or "never"), int(time.time())
        )
        if since is not None:
            spent_row = cur.execute(
                """
                SELECT COALESCE(SUM(amount_msat + fees_paid_msat + fee_reserve_msat), 0) AS used
                FROM sovran_transactions
                WHERE app_id = ? AND type = 'outgoing' AND state IN ('settled', 'pending')
                  AND created_at >= ?
                """,
                (int(app_row["id"]), since),
            ).fetchone()
        else:
            spent_row = cur.execute(
                """
                SELECT COALESCE(SUM(amount_msat + fees_paid_msat + fee_reserve_msat), 0) AS used
                FROM sovran_transactions
                WHERE app_id = ? AND type = 'outgoing' AND state IN ('settled', 'pending')
                """,
                (int(app_row["id"]),),
            ).fetchone()
        used_msat = int(spent_row["used"])
        if used_msat + needed_msat > max_msat:
            raise NwcStoreError(
                "QUOTA_EXCEEDED",
                "The wallet does not have enough budget remaining to make this payment",
                400,
            )

    def finalize_outgoing_payment(
        self,
        tx_id: int,
        succeeded: bool,
        preimage: str = "",
        fees_paid_msat: int = 0,
    ) -> dict[str, Any]:
        now = int(time.time())
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                tx = cur.execute(
                    "SELECT * FROM sovran_transactions WHERE id = ?", (int(tx_id),)
                ).fetchone()
                if tx is None:
                    raise NwcStoreError("NOT_FOUND", "Transaction not found", 404)
                if tx["state"] != "pending":
                    cur.execute("COMMIT")
                    return self._row_to_tx_dict(tx)

                app_id = int(tx["app_id"])
                amount_msat = int(tx["amount_msat"])
                fee_reserve = int(tx["fee_reserve_msat"])

                if succeeded:
                    actual_fee = max(0, int(fees_paid_msat))
                    refund = max(0, fee_reserve - actual_fee)
                    if refund > 0:
                        cur.execute(
                            "UPDATE sovran_apps SET balance_msat = balance_msat + ? WHERE id = ?",
                            (refund, app_id),
                        )
                    cur.execute(
                        """
                        UPDATE sovran_transactions
                        SET state = 'settled',
                            fees_paid_msat = ?,
                            fee_reserve_msat = 0,
                            preimage = ?,
                            settled_at = ?
                        WHERE id = ?
                        """,
                        (actual_fee, preimage.lower(), now, int(tx_id)),
                    )
                else:
                    full_refund = amount_msat + fee_reserve
                    cur.execute(
                        "UPDATE sovran_apps SET balance_msat = balance_msat + ? WHERE id = ?",
                        (full_refund, app_id),
                    )
                    cur.execute(
                        """
                        UPDATE sovran_transactions
                        SET state = 'failed', fee_reserve_msat = 0
                        WHERE id = ?
                        """,
                        (int(tx_id),),
                    )

                cur.execute("COMMIT")
                updated = self._conn.execute(
                    "SELECT * FROM sovran_transactions WHERE id = ?", (int(tx_id),)
                ).fetchone()
                return self._row_to_tx_dict(updated)
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def mark_event_processed(self, event_id: str) -> bool:
        """Return True if event_id is new and now recorded; False if already processed."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                existing = cur.execute(
                    "SELECT 1 FROM sovran_processed_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing:
                    cur.execute("COMMIT")
                    return False
                cur.execute(
                    "INSERT INTO sovran_processed_events (event_id, processed_at) VALUES (?, ?)",
                    (event_id, int(time.time())),
                )
                cur.execute("COMMIT")
                return True
            except Exception:
                cur.execute("ROLLBACK")
                return False

    @staticmethod
    def _row_to_tx_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "appId": int(row["app_id"]),
            "type": row["type"],
            "state": row["state"],
            "amountMsat": int(row["amount_msat"]),
            "amount": int(row["amount_msat"]),
            "feesPaid": int(row["fees_paid_msat"]),
            "paymentHash": row["payment_hash"],
            "payment_hash": row["payment_hash"],
            "invoice": row["invoice"],
            "preimage": row["preimage"],
            "description": row["description"],
            "descriptionHash": row["description_hash"],
            "description_hash": row["description_hash"],
            "createdAt": int(row["created_at"]),
            "created_at": int(row["created_at"]),
            "expiresAt": int(row["expires_at"]) if row["expires_at"] else None,
            "expires_at": int(row["expires_at"]) if row["expires_at"] else None,
            "settledAt": int(row["settled_at"]) if row["settled_at"] else None,
            "settled_at": int(row["settled_at"]) if row["settled_at"] else None,
            "metadata": {},
        }

    def find_txs_by_selector(
        self,
        app_id: int,
        transaction_id: str | None = None,
        payment_hash: str = "",
        invoice: str = "",
    ) -> list[dict[str, Any]]:
        """All ledger rows of one wallet matching a NWC-09 lookup selector.

        Selectors only ever match rows belonging to `app_id`: a lookup must
        never reveal whether another wallet's record exists. Multiple rows
        can legitimately share a payment hash (an app paying its own
        invoice creates an outgoing *and* an incoming row), so callers get
        the full list and decide (NWC-09: `MULTIPLE_MATCHES`).
        """
        with self._lock:
            if transaction_id is not None:
                rows = self._conn.execute(
                    "SELECT * FROM sovran_transactions WHERE app_id = ? AND id = ?",
                    (int(app_id), int(transaction_id)),
                ).fetchall()
            elif payment_hash:
                rows = self._conn.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE app_id = ? AND payment_hash = ? ORDER BY id ASC
                    """,
                    (int(app_id), payment_hash.strip().lower()),
                ).fetchall()
            elif invoice:
                rows = self._conn.execute(
                    """
                    SELECT * FROM sovran_transactions
                    WHERE app_id = ? AND invoice = ? ORDER BY id ASC
                    """,
                    (int(app_id), invoice.strip()),
                ).fetchall()
            else:
                return []
            return [self._row_to_tx_dict(r) for r in rows]

    @staticmethod
    def to_nip47_tx(tx: dict[str, Any]) -> dict[str, Any]:
        return {
            # NWC-09: stable wallet-scoped id, identical across methods.
            "transaction_id": str(tx["id"]) if tx.get("id") is not None else None,
            "type": tx["type"],
            "state": tx["state"],
            "invoice": tx["invoice"],
            "description": tx["description"],
            "description_hash": tx["description_hash"],
            "preimage": tx["preimage"],
            "payment_hash": tx["payment_hash"],
            "amount": int(tx["amountMsat"]),
            "fees_paid": int(tx["feesPaid"]),
            "created_at": int(tx["created_at"]),
            "expires_at": tx["expires_at"],
            "settled_at": tx["settled_at"],
            "metadata": {},
        }

    @staticmethod
    def to_nip47_payment_record(tx: dict[str, Any]) -> dict[str, Any]:
        """NWC-09 common payment-record envelope for a ledger row (bolt11)."""
        payment_hash = str(tx.get("paymentHash") or tx.get("payment_hash") or "").lower()
        details: dict[str, Any] = {"payment_hash": payment_hash}
        if tx.get("invoice"):
            details["invoice"] = tx["invoice"]
        preimage = str(tx.get("preimage") or "").lower()
        # NWC-09: never disclose a preimage that does not hash to the
        # payment hash (defends against stale/fabricated ledger values).
        if preimage and payment_hash:
            try:
                if hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == payment_hash:
                    details["preimage"] = preimage
            except ValueError:
                pass
        if tx.get("description"):
            details["description"] = tx["description"]
        if tx.get("description_hash"):
            details["description_hash"] = tx["description_hash"]
        record: dict[str, Any] = {
            "transaction_id": str(tx["id"]) if tx.get("id") is not None else None,
            "type": tx["type"],
            "state": tx["state"],
            "payment_type": "bolt11",
            "amount": int(tx["amountMsat"]),
            "fees_paid": int(tx["feesPaid"]),
            "created_at": int(tx["created_at"]),
            "metadata": {},
            "details": details,
        }
        if tx.get("expires_at"):
            record["expires_at"] = int(tx["expires_at"])
        if tx.get("settled_at"):
            record["settled_at"] = int(tx["settled_at"])
        return record


# ── Main Sovran NWC Engine (NIP-47 + REST API + Relay Worker) ─────


class SovranNwcDaemon:
    """Self-hosted LND-only NWC server + local management API."""

    def __init__(
        self,
        store: NwcStore,
        lnd: _lnd_mod.LndRestClient,
        unlock_password: str,
        relays: list[str] | None = None,
        tor_socks_proxy: str | None = None,
        scoped_passwords: dict[str, str] | None = None,
    ) -> None:
        self.store = store
        self.lnd = lnd
        self._unlock_password = unlock_password
        # Scoped credentials: permission -> password for credentials that must
        # never be able to mint anything above their own scope (e.g. the
        # invoice-only secret the internet-facing LNURL service holds). The
        # permission a token gets is decided by *which secret was presented*,
        # never by what the caller asks for. A scoped entry identical to the
        # unlock password is dropped: it would silently be a second full
        # credential, which is exactly the confusion this split exists to kill.
        self._scoped_passwords: dict[str, str] = {}
        for perm, pw in (scoped_passwords or {}).items():
            perm_norm = str(perm).strip().lower()
            secret = str(pw or "").strip()
            if perm_norm not in ("invoice", "read") or not secret:
                continue
            if hmac.compare_digest(
                secret.encode("utf-8"), (unlock_password or "").strip().encode("utf-8")
            ):
                logger.warning(
                    "Ignoring scoped '%s' credential: identical to the unlock password",
                    perm_norm,
                )
                continue
            self._scoped_passwords[perm_norm] = secret
        self.relays = [
            r.strip()
            for r in (relays or ["wss://relay.getalby.com", "wss://relay2.getalby.com"])
            if r.strip()
        ]
        self.tor_socks_proxy = tor_socks_proxy
        self._tokens_lock = threading.Lock()
        # token_str -> permission ("full" | "read" | "invoice")
        self._tokens: dict[str, str] = {}
        self._stop_event = threading.Event()
        self._relay_conns_lock = threading.Lock()
        self._relay_conns: list[_nostr_mod.WebSocketConnection] = []
        self._rate_limit_lock = threading.Lock()
        self._rate_limit: dict[int, deque[float]] = {}
        self._pubkey_cache_lock = threading.Lock()
        self._pubkey_cache: set[str] | None = None
        self._pubkey_cache_at = 0.0

    # ── Token authentication & authorization ───────────────────────

    def issue_token(self, password: str, permission: str = "full") -> str:
        token, _granted, _kind = self._issue_token(password, permission)
        return token

    def _issue_token(
        self, password: str, permission: str = "full"
    ) -> tuple[str, str, str]:
        """Mint a bearer token; returns `(token, granted_permission, credential)`.

        The presented password decides the ceiling: the unlock password may
        mint any scope (including deliberately lesser ones, e.g. a read-only
        token for monitoring), while a scoped credential may mint *only* its
        own scope — asking for anything else is a 403, not a silent clamp, so
        a misconfigured least-privilege client fails loudly instead of
        quietly running with different authority than its operator intended.
        """
        presented = (password or "").strip().encode("utf-8")
        ceiling: str | None = None
        credential = ""
        if self._unlock_password and hmac.compare_digest(
            presented, self._unlock_password.strip().encode("utf-8")
        ):
            ceiling, credential = "full", "unlock"
        else:
            for perm, secret in self._scoped_passwords.items():
                if hmac.compare_digest(presented, secret.encode("utf-8")):
                    ceiling, credential = perm, f"scoped:{perm}"
                    break
        if ceiling is None:
            raise NwcStoreError("unauthorized", "Invalid unlock password", 401)

        requested = (permission or "").strip().lower()
        if requested not in ("full", "read", "invoice"):
            requested = ceiling
        if ceiling != "full" and requested != ceiling:
            raise NwcStoreError(
                "forbidden",
                f"This credential can only issue '{ceiling}' tokens, not '{requested}'",
                403,
            )
        token = secrets.token_urlsafe(32)
        with self._tokens_lock:
            self._tokens[token] = requested
        _audit_mod.audit_log(
            "api_token_issued", permission=requested, credential=credential
        )
        return token, requested, credential

    def verify_token(self, auth_header: str | None, required: set[str]) -> str:
        if not auth_header or not auth_header.startswith("Bearer "):
            raise NwcStoreError("unauthorized", "Missing Bearer token", 401)
        token = auth_header[len("Bearer ") :].strip()
        with self._tokens_lock:
            perm = self._tokens.get(token)
        if perm is None:
            raise NwcStoreError("unauthorized", "Invalid or expired Bearer token", 401)
        if perm not in required:
            raise NwcStoreError(
                "forbidden",
                f"Token with '{perm}' permission cannot access this endpoint",
                403,
            )
        return perm

    # ── Pending invoice reconciliation against LND ─────────────────

    def _ensure_pending_capacity(self, app_id: int) -> None:
        """Refuse new invoices once a wallet holds the pending cap.

        Checked *before* the LND invoice is created so a refused request does
        not leave an orphan OPEN invoice in LND's node-global invoice table.
        `NwcStore.record_incoming_invoice` re-checks atomically as a backstop.
        """
        if MAX_PENDING_INVOICES_PER_WALLET <= 0:
            return
        if self.store.pending_incoming_count(app_id) >= MAX_PENDING_INVOICES_PER_WALLET:
            raise NwcStoreError(
                "QUOTA_EXCEEDED",
                "Too many pending invoices for this wallet; "
                "wait for some to settle or expire",
                429,
            )

    def _lnd_invoice_states(
        self, payment_hashes: list[str]
    ) -> dict[str, dict[str, Any]]:
        """Current LND state for many invoices, batched where possible.

        Prefers paginated `ListInvoices` (a constant number of REST calls per
        sweep, independent of how many ledger rows are pending) and falls
        back to one `LookupInvoice` per hash for clients without it. Hashes
        LND does not report are simply absent from the result — callers treat
        them as "unknown this round" and retry on the next sweep.
        """
        wanted = {h.strip().lower() for h in payment_hashes if h}
        if not wanted:
            return {}
        list_fn = getattr(self.lnd, "list_invoices", None)
        if callable(list_fn):
            try:
                found: dict[str, dict[str, Any]] = {}
                offset = 0
                # 50 pages x 200 = 10k invoices of headroom; Sovran nodes
                # sit far below LND's practical invoice-table size.
                for _ in range(50):
                    page = list_fn(
                        num_max_invoices=200, index_offset=offset, pending_only=False
                    )
                    invoices = page.get("invoices") or []
                    for inv in invoices:
                        ph = str(inv.get("payment_hash") or "").lower()
                        if ph in wanted:
                            found[ph] = inv
                    if len(found) >= len(wanted):
                        break
                    last = int(page.get("last_index_offset") or 0)
                    if not invoices or last <= offset:
                        break
                    offset = last
                return found
            except _lnd_mod.LndError:
                pass  # fall through to per-hash lookups
        found = {}
        for ph in wanted:
            try:
                found[ph] = self.lnd.lookup_invoice(ph)
            except _lnd_mod.LndError:
                continue
        return found

    def _cancel_lnd_invoice(self, payment_hash: str, reason: str, app_id: int) -> bool:
        """Best-effort LND invoice cancellation; returns True on success.

        Cancellation is what makes closing an invoice in the ledger safe: a
        canceled invoice can never settle later, so no payment can land on
        the node uncredited to a sub-wallet after we stop watching it.
        """
        cancel_fn = getattr(self.lnd, "cancel_invoice", None)
        if not callable(cancel_fn):
            return False
        try:
            cancel_fn(payment_hash)
        except _lnd_mod.LndError as exc:
            logger.warning(
                "Failed to cancel LND invoice %s (%s): %s", payment_hash, reason, exc
            )
            return False
        _audit_mod.audit_log(
            "nwc_invoice_canceled",
            app_id=app_id,
            payment_hash=payment_hash,
            reason=reason,
        )
        return True

    def reconcile_pending_invoices(self, app_id: int | None = None) -> None:
        pending = self.store.list_pending_incoming(app_id=app_id)
        if not pending:
            return
        states = self._lnd_invoice_states(
            [str(tx.get("paymentHash") or "") for tx in pending]
        )
        now = int(time.time())
        for tx in pending:
            ph = tx.get("paymentHash") or ""
            if not ph:
                continue
            lnd_inv = states.get(ph)
            if lnd_inv is None:
                # Unknown this round (LND unreachable or not reporting it):
                # leave the row pending and retry next sweep rather than
                # guessing — expiring on a guess could orphan a real payment.
                continue
            if lnd_inv["state"] == "settled":
                settled_tx, newly_settled = self.store.settle_incoming_by_payment_hash(
                    ph,
                    amount_msat=lnd_inv["amount_msat"],
                    preimage=lnd_inv["preimage"],
                    settled_at=lnd_inv["settled_at"],
                )
                if newly_settled and settled_tx:
                    self._emit_notification(
                        int(settled_tx["appId"]), "payment_received", settled_tx
                    )
                continue
            if lnd_inv["state"] == "failed":
                # Canceled (or otherwise closed) on the LND side.
                closed = self.store.close_incoming_by_payment_hash(ph, "expired")
                if closed:
                    _audit_mod.audit_log(
                        "nwc_invoice_expired",
                        app_id=int(tx["appId"]),
                        payment_hash=ph,
                        reason="lnd_canceled",
                    )
                continue
            # Still OPEN in LND: expire only once the BOLT11 expiry has
            # passed, and cancel on LND *first* so the invoice can never
            # settle after we stop watching it. If the cancel fails (e.g. a
            # payment is racing us), leave the row pending; the next sweep
            # will see the settled state and credit it.
            expires_at = tx.get("expires_at") or lnd_inv.get("expires_at") or 0
            if expires_at and now >= int(expires_at):
                if self._cancel_lnd_invoice(ph, "expired", int(tx["appId"])):
                    closed = self.store.close_incoming_by_payment_hash(ph, "expired")
                    if closed:
                        _audit_mod.audit_log(
                            "nwc_invoice_expired",
                            app_id=int(tx["appId"]),
                            payment_hash=ph,
                            reason="expired",
                        )

    # ── NIP-47 Request Processor ───────────────────────────────────

    def process_nip47_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Verify, decrypt, execute, and build response event(s) for a kind 23194 request."""
        if int(event.get("kind", 0)) != 23194:
            return []

        event_id = str(event["id"]).lower()
        client_pubkey = str(event["pubkey"]).lower()

        # Cheap pre-filter BEFORE the expensive part: a wallet pubkey is public
        # (it is in every 13194 info event), so anybody can publish kind-23194
        # events tagged with it. Pure-Python Schnorr verification costs ~5 ms,
        # so a flood of junk events would block this relay's read loop and
        # starve real requests. Drop anything not addressed to a wallet we
        # serve without touching the signature.
        p_tags = [
            str(t[1]).lower()
            for t in (event.get("tags") or [])
            if isinstance(t, list) and len(t) >= 2 and str(t[0]) == "p"
        ]
        known_pubkeys = self._known_wallet_pubkeys()
        matched = [pk for pk in p_tags if pk in known_pubkeys]
        if not matched:
            logger.debug("Dropping NIP-47 event %s for unknown wallet", event_id)
            return []
        wallet_pubkey = matched[0]

        if not _nostr_mod.verify_event(event):
            logger.warning("Rejected NIP-47 event with invalid signature")
            return []

        app = self.store.get_app_internal_by_pubkeys(client_pubkey, wallet_pubkey)
        if app is None:
            return []

        # ── Replay / staleness guards ─────────────────────────────
        # NIP-47: a request carrying an `expiration` tag that has passed "should
        # be ignored". Independently, refuse events whose created_at is outside
        # a small window so a relay (or anyone who captured a signed request)
        # cannot execute a months-old event with a fresh-looking signature.
        now = int(time.time())
        raw_created_at = _as_int(event.get("created_at"), 0) or 0
        if (
            raw_created_at <= 0
            or now - raw_created_at > REQUEST_MAX_AGE_SEC
            or raw_created_at - now > REQUEST_MAX_FUTURE_SKEW_SEC
        ):
            logger.warning(
                "Ignoring stale/out-of-window NIP-47 request %s (created_at=%s)",
                event_id,
                raw_created_at,
            )
            return []
        for tag in event.get("tags") or []:
            if isinstance(tag, list) and len(tag) >= 2 and str(tag[0]).lower() == "expiration":
                expires_at = _as_int(tag[1], 0) or 0
                if expires_at and now >= expires_at:
                    logger.info("Ignoring expired NIP-47 request %s", event_id)
                    return []

        # ── Encryption negotiation (NIP-47 "Encryption") ──────────
        scheme = self._request_encryption(event)
        if scheme is None:
            logger.warning("Rejecting NIP-47 request %s: unsupported encryption", event_id)
            return [
                self._build_nip47_response_event(
                    app["wallet_privkey"],
                    client_pubkey,
                    event_id,
                    {
                        "result_type": "error",
                        "error": {
                            "code": "UNSUPPORTED_ENCRYPTION",
                            "message": "This wallet supports nip44_v2 and nip04 only",
                        },
                    },
                    True,
                )
            ]
        use_nip44 = scheme == "nip44_v2"

        # ── Per-connection request budget ─────────────────────────
        if self._rate_limited(int(app["id"])):
            logger.warning("Rate-limiting NIP-47 requests for wallet %s", app["id"])
            return [
                self._build_nip47_response_event(
                    app["wallet_privkey"],
                    client_pubkey,
                    event_id,
                    {
                        "result_type": "error",
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many requests; retry in a few seconds",
                        },
                    },
                    use_nip44,
                )
            ]

        if not self.store.mark_event_processed(event_id):
            return []

        wallet_priv_bytes = bytes.fromhex(app["wallet_privkey"])
        client_pub_bytes = bytes.fromhex(client_pubkey)
        content = str(event.get("content") or "")

        try:
            if use_nip44:
                plaintext = _nostr_mod.nip44_decrypt(
                    content, wallet_priv_bytes, client_pub_bytes
                )
            else:
                plaintext = _nostr_mod.nip04_decrypt(
                    content, wallet_priv_bytes, client_pub_bytes
                )
            req_obj = json.loads(plaintext)
        except Exception:
            resp_payload = {
                "result_type": "error",
                "error": {
                    "code": "OTHER",
                    "message": "Failed to decrypt or parse NIP-47 request",
                },
            }
            return [
                self._build_nip47_response_event(
                    app["wallet_privkey"],
                    client_pubkey,
                    event_id,
                    resp_payload,
                    use_nip44,
                )
            ]

        method = str(req_obj.get("method") or "")
        params = req_obj.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        # Never let an unexpected exception (a malformed numeric param, an LND
        # response we did not model, …) escape into the relay worker: that
        # drops the WebSocket connection, sends no response, and leaves the
        # request marked as processed so no retry can ever succeed.
        try:
            resp_payload = self.handle_nip47_method(app, method, params)
        except Exception:  # noqa: BLE001 - defensive boundary
            logger.exception(
                "Unhandled error while executing NIP-47 method %r for wallet %s",
                method,
                app["id"],
            )
            resp_payload = {
                "result_type": method or "unknown",
                "error": {"code": "INTERNAL", "message": "Request could not be processed"},
            }
        return [
            self._build_nip47_response_event(
                app["wallet_privkey"],
                client_pubkey,
                event_id,
                resp_payload,
                use_nip44,
            )
        ]

    def _known_wallet_pubkeys(self) -> set[str]:
        """Cached set of wallet pubkeys (short TTL; invalidated on app changes)."""
        now = time.monotonic()
        with self._pubkey_cache_lock:
            if self._pubkey_cache is not None and now - self._pubkey_cache_at < 5.0:
                return self._pubkey_cache
        keys = self.store.known_wallet_pubkeys()
        with self._pubkey_cache_lock:
            self._pubkey_cache = keys
            self._pubkey_cache_at = time.monotonic()
        return keys

    @staticmethod
    def _request_encryption(event: dict[str, Any]) -> str | None:
        """Return ``"nip44_v2"``/``"nip04"`` for a request, or None if unsupported.

        NIP-47 negotiates encryption with an `encryption` tag on every request;
        the tag is authoritative. Only tag-less requests fall back to the
        legacy heuristic (a NIP-04 payload always carries `?iv=`).
        """
        content = str(event.get("content") or "")
        for tag in event.get("tags") or []:
            if (
                isinstance(tag, list)
                and len(tag) >= 2
                and str(tag[0]).lower() == "encryption"
            ):
                value = str(tag[1]).strip().lower()
                if value in ("nip44_v2", "nip44"):
                    return "nip44_v2"
                if value == "nip04":
                    return "nip04"
                return None
        return "nip44_v2" if "?iv=" not in content else "nip04"

    def _rate_limited(self, app_id: int) -> bool:
        """Return True when *app_id* has exceeded its per-minute request budget."""
        if NIP47_RATE_LIMIT_PER_MIN <= 0:
            return False
        now = time.monotonic()
        cutoff = now - 60.0
        with self._rate_limit_lock:
            bucket = self._rate_limit.setdefault(int(app_id), deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= NIP47_RATE_LIMIT_PER_MIN:
                return True
            bucket.append(now)
            # Opportunistic cleanup so the map cannot grow without bound.
            if len(self._rate_limit) > 256:
                for key in [k for k, v in self._rate_limit.items() if not v or v[-1] < cutoff]:
                    self._rate_limit.pop(key, None)
            return False

    def _build_nip47_response_event(
        self,
        wallet_privkey_hex: str,
        client_pubkey_hex: str,
        request_event_id: str,
        payload: dict[str, Any],
        use_nip44: bool,
    ) -> dict[str, Any]:
        plaintext = json.dumps(payload, separators=(",", ":"))
        w_priv = bytes.fromhex(wallet_privkey_hex)
        c_pub = bytes.fromhex(client_pubkey_hex)
        if use_nip44:
            encrypted = _nostr_mod.nip44_encrypt(plaintext, w_priv, c_pub)
        else:
            encrypted = _nostr_mod.nip04_encrypt(plaintext, w_priv, c_pub)
        return _nostr_mod.make_event(
            wallet_privkey_hex,
            kind=23195,
            content=encrypted,
            tags=[["p", client_pubkey_hex], ["e", request_event_id]],
        )

    def build_nip47_info_event(self, app: dict[str, Any]) -> dict[str, Any]:
        scopes = app.get("scopes") or []
        methods = scopes_to_nip47_methods(scopes)
        extensions = scopes_to_nwc_extensions(scopes)
        tags = [
            ["encryption", "nip44_v2 nip04"],
            ["p", app["appPubkey"]],
        ]
        if extensions:
            tags.append(["extensions", " ".join(extensions)])
        if "notifications" in scopes:
            tags.append(["notifications", "payment_received payment_sent"])
        return _nostr_mod.make_event(
            app["wallet_privkey"],
            kind=13194,
            content=" ".join(advertised_methods(methods)),
            tags=tags,
        )

    def handle_nip47_method(
        self, app: dict[str, Any], method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        app_id = int(app["id"])

        if method not in ALL_KNOWN_NIP47_METHODS:
            return {
                "result_type": method or "unknown",
                "error": {
                    "code": "NOT_IMPLEMENTED",
                    "message": f"Method '{method}' is not supported by this wallet",
                },
            }

        scopes = set(app.get("scopes") or [])
        allowed_methods = set(scopes_to_nip47_methods(list(scopes)))

        if method not in allowed_methods:
            return {
                "result_type": method or "unknown",
                "error": {
                    "code": "RESTRICTED",
                    "message": f"This wallet does not have permission for '{method}'",
                },
            }

        try:
            if method == "get_info":
                info = self.lnd.get_info()
                return {
                    "result_type": "get_info",
                    "result": {
                        "alias": app.get("name") or info["alias"],
                        "color": info["color"],
                        # Per NIP-47 this is the *wallet service* pubkey for this
                        # connection, not the LND node identity key: handing the
                        # node pubkey to every connected app leaks node identity
                        # and links the node to the app's payment history.
                        "pubkey": compressed_pubkey(
                            app.get("walletPubkey") or info["pubkey"]
                        ),
                        "network": info["network"],
                        "block_height": info["block_height"],
                        "block_hash": info["block_hash"],
                        "methods": advertised_methods(allowed_methods),
                        "extensions": scopes_to_nwc_extensions(list(scopes)),
                        "notifications": (
                            ["payment_received", "payment_sent"]
                            if "notifications" in scopes
                            else []
                        ),
                    },
                }

            if method == "get_balance":
                self.reconcile_pending_invoices(app_id=app_id)
                fresh_app = self.store.get_app(app_id)
                bal_msat = int((fresh_app or app).get("balanceMsat", 0))
                return {
                    "result_type": "get_balance",
                    "result": {"balance": bal_msat},
                }

            if method == "make_invoice":
                amount_msat = _as_int(params.get("amount"), 0) or 0
                if amount_msat <= 0:
                    return {
                        "result_type": "make_invoice",
                        "error": {"code": "OTHER", "message": "Amount must be positive"},
                    }
                desc = str(params.get("description") or "")
                desc_hash = str(params.get("description_hash") or "")
                # Refuse before touching LND once the wallet holds the
                # pending cap (checked again atomically by the store).
                self._ensure_pending_capacity(app_id)
                # Client-chosen expiry is bounded: an unbounded (`expiry`=2**31)
                # invoice would sit OPEN in LND's invoice table indefinitely.
                expiry = _bounded(params.get("expiry"), 3600, 1, MAX_INVOICE_EXPIRY_SEC)
                inv = self.lnd.create_invoice(
                    amount_msat=amount_msat,
                    memo=desc,
                    expiry=expiry,
                    description_hash_hex=desc_hash or None,
                    private=True,
                )
                tx = self.store.record_incoming_invoice(
                    app_id=app_id,
                    payment_hash=inv["payment_hash"],
                    invoice=inv["invoice"],
                    amount_msat=amount_msat,
                    description=desc,
                    description_hash=desc_hash,
                    created_at=inv["created_at"],
                    expires_at=inv["expires_at"],
                )
                # LND generates the preimage when the invoice is created
                # (lnrpc.LookupInvoice returns r_preimage even while OPEN), so
                # record it now: an internal wallet-to-wallet payment of this
                # invoice can then settle instantly with a verifiable preimage.
                try:
                    preimage = str(
                        self.lnd.lookup_invoice(inv["payment_hash"]).get("preimage") or ""
                    )
                except _lnd_mod.LndError:
                    preimage = ""
                if preimage:
                    self.store.set_preimage_for_hash(inv["payment_hash"], preimage)
                _audit_mod.audit_log(
                    "nwc_invoice_created",
                    app_id=app_id,
                    alias=app.get("name"),
                    amount_msat=amount_msat,
                    payment_hash=inv["payment_hash"],
                    expiry=expiry,
                )
                return {
                    "result_type": "make_invoice",
                    "result": self.store.to_nip47_tx(tx),
                }

            if method == "lookup_invoice":
                ph = str(params.get("payment_hash") or "").strip().lower()
                bolt11 = str(params.get("invoice") or "").strip()
                if not ph and bolt11:
                    decoded = self.lnd.decode_payreq(bolt11)
                    ph = decoded["payment_hash"]
                self.reconcile_pending_invoices(app_id=app_id)
                tx = self.store.find_tx_for_app(app_id, payment_hash=ph, invoice=bolt11)
                if tx is None:
                    return {
                        "result_type": "lookup_invoice",
                        "error": {"code": "NOT_FOUND", "message": "Invoice not found"},
                    }
                return {
                    "result_type": "lookup_invoice",
                    "result": self.store.to_nip47_tx(tx),
                }

            if method == "list_transactions":
                self.reconcile_pending_invoices(app_id=app_id)
                txs, _ = self.store.list_transactions(
                    app_id=app_id,
                    limit=_bounded(params.get("limit"), 50, 1, MAX_PAGE_SIZE),
                    offset=_bounded(params.get("offset"), 0, 0, 2**31 - 1),
                    tx_type=params.get("type"),
                    unpaid=bool(params.get("unpaid", False)),
                    from_ts=params.get("from"),
                    until_ts=params.get("until"),
                )
                return {
                    "result_type": "list_transactions",
                    "result": {
                        "transactions": [self.store.to_nip47_tx(t) for t in txs]
                    },
                }

            if method == "get_budget":
                # NWC-13: empty result means "no budget configured" — clients
                # must be able to tell that apart from a zero budget.
                fresh_app = self.store.get_app(app_id) or app
                total_sat = int(fresh_app.get("maxAmountSat") or 0)
                if total_sat <= 0:
                    return {"result_type": "get_budget", "result": {}}
                period = str(fresh_app.get("budgetRenewal") or "never").lower()
                if period not in BUDGET_PERIODS:
                    period = "never"
                since, renews_at = _budget_period_window(period, int(time.time()))
                result: dict[str, Any] = {
                    "used_budget": self.store.budget_used_msat(app_id, since=since),
                    "total_budget": total_sat * 1000,
                    "renewal_period": period,
                }
                if renews_at is not None:
                    result["renews_at"] = renews_at
                return {"result_type": "get_budget", "result": result}

            if method == "lookup_payment":
                return self._lookup_payment_payload(app, params)

            if method == "pay_invoice":
                return self._pay_invoice_payload(app, params)

            if method == "pay_keysend":
                return self._pay_keysend_payload(app, params)

        except NwcStoreError as exc:
            return {
                "result_type": method,
                "error": {"code": exc.code, "message": str(exc)},
            }
        except _lnd_mod.LndError as exc:
            return {
                "result_type": method,
                "error": {"code": "INTERNAL", "message": str(exc)},
            }

        return {
            "result_type": method,
            "error": {"code": "NOT_IMPLEMENTED", "message": f"Method {method} not implemented"},
        }

    # ── Payment handlers ───────────────────────────────────────────

    def _lookup_payment_payload(
        self, app: dict[str, Any], params: dict[str, Any]
    ) -> dict[str, Any]:
        """NWC-09 `lookup_payment`: reconcile one payment record by selector.

        Supported selectors: `transaction_id`, and the BOLT11-compatible
        top-level `payment_hash` / `invoice` (also inside a `lookup` object
        when `payment_type` is `bolt11`). Other payment types are refused
        with UNSUPPORTED_PAYMENT_TYPE rather than guessed at.
        """

        def err(code: str, message: str) -> dict[str, Any]:
            return {
                "result_type": "lookup_payment",
                "error": {"code": code, "message": message},
            }

        app_id = int(app["id"])
        payment_type = str(params.get("payment_type") or "").strip().lower()
        if payment_type and payment_type != "bolt11":
            return err(
                "UNSUPPORTED_PAYMENT_TYPE",
                f"Payment type '{payment_type}' is not supported",
            )

        transaction_id = params.get("transaction_id")
        payment_hash = str(params.get("payment_hash") or "").strip().lower()
        invoice = str(params.get("invoice") or "").strip()
        lookup = params.get("lookup")
        if isinstance(lookup, dict):
            payment_hash = payment_hash or str(
                lookup.get("payment_hash") or ""
            ).strip().lower()
            invoice = invoice or str(lookup.get("invoice") or "").strip()
            if transaction_id is None:
                transaction_id = lookup.get("transaction_id")

        if transaction_id is None and not payment_hash and not invoice:
            return err(
                "BAD_REQUEST",
                "One of transaction_id, payment_hash, or invoice is required",
            )

        self.reconcile_pending_invoices(app_id=app_id)

        if transaction_id is not None:
            tx_id_int = _as_int(transaction_id, None)
            if tx_id_int is None:
                return err("BAD_REQUEST", "transaction_id is invalid")
            matches = self.store.find_txs_by_selector(
                app_id, transaction_id=str(tx_id_int)
            )
        elif payment_hash and invoice:
            by_hash = self.store.find_txs_by_selector(
                app_id, payment_hash=payment_hash
            )
            by_invoice = self.store.find_txs_by_selector(app_id, invoice=invoice)
            if not by_hash and not by_invoice:
                return err("NOT_FOUND", "Payment not found")
            ids_hash = {int(t["id"]) for t in by_hash}
            ids_invoice = {int(t["id"]) for t in by_invoice}
            # Both selectors were given, so both must agree on the record(s);
            # any disagreement is a client error, not a guessable lookup.
            if ids_hash != ids_invoice:
                return err(
                    "BAD_REQUEST", "payment_hash and invoice identify different payments"
                )
            matches = by_hash
        elif payment_hash:
            matches = self.store.find_txs_by_selector(
                app_id, payment_hash=payment_hash
            )
        else:
            matches = self.store.find_txs_by_selector(app_id, invoice=invoice)

        if not matches:
            return err("NOT_FOUND", "Payment not found")
        if len(matches) > 1:
            return err(
                "MULTIPLE_MATCHES",
                "Selector matches multiple payments; retry with transaction_id",
            )
        return {
            "result_type": "lookup_payment",
            "result": self.store.to_nip47_payment_record(matches[0]),
        }

    def _pay_invoice_payload(
        self, app: dict[str, Any], params: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a single `pay_invoice` request and build its response payload."""
        app_id = int(app["id"])
        bolt11 = str(params.get("invoice") or "").strip()
        if not bolt11:
            return {
                "result_type": "pay_invoice",
                "error": {"code": "OTHER", "message": "Missing invoice"},
            }
        decoded = self.lnd.decode_payreq(bolt11)
        override_amt = _as_int(params.get("amount"), 0) or None
        amount_msat = int(decoded["amount_msat"] or override_amt or 0)
        if amount_msat <= 0:
            return {
                "result_type": "pay_invoice",
                "error": {
                    "code": "OTHER",
                    "message": "Zero-amount invoice requires an explicit amount",
                },
            }
        fee_reserve_msat = max(10_000, (amount_msat + 99) // 100)
        tx_id, internal_payee_id = self.store.reserve_outgoing_payment(
            app_id=app_id,
            amount_msat=amount_msat,
            fee_reserve_msat=fee_reserve_msat,
            payment_hash=decoded["payment_hash"],
            invoice=bolt11,
            description=decoded["description"],
            description_hash=decoded["description_hash"],
        )
        if internal_payee_id is not None:
            return self._finish_internal_payment(
                app_id, internal_payee_id, decoded["payment_hash"]
            )

        try:
            pay_res = self.lnd.pay_invoice(
                bolt11,
                fee_limit_msat=fee_reserve_msat,
                amount_msat=override_amt if decoded["amount_msat"] == 0 else None,
            )
        except _lnd_mod.LndError as exc:
            self.store.finalize_outgoing_payment(tx_id, succeeded=False)
            _audit_mod.audit_log(
                "nwc_payment_failed",
                app_id=app_id,
                alias=app.get("name"),
                amount_msat=amount_msat,
                payment_hash=decoded["payment_hash"],
                reason=str(exc),
            )
            return {
                "result_type": "pay_invoice",
                "error": {"code": "PAYMENT_FAILED", "message": str(exc)},
            }

        settled_tx = self.store.finalize_outgoing_payment(
            tx_id,
            succeeded=True,
            preimage=pay_res["preimage"],
            fees_paid_msat=pay_res["fees_paid_msat"],
        )
        self._emit_notification(app_id, "payment_sent", settled_tx)
        _audit_mod.audit_log(
            "nwc_payment_sent",
            app_id=app_id,
            alias=app.get("name"),
            amount_msat=amount_msat,
            fees_paid_msat=pay_res["fees_paid_msat"],
            payment_hash=decoded["payment_hash"],
        )
        return {
            "result_type": "pay_invoice",
            "result": {
                "preimage": pay_res["preimage"],
                "fees_paid": pay_res["fees_paid_msat"],
            },
        }

    def _pay_keysend_payload(
        self, app: dict[str, Any], params: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a single `pay_keysend` request (NWC-04) and build its payload."""
        app_id = int(app["id"])
        pubkey = str(params.get("pubkey") or "").strip().lower()
        amount_msat = _as_int(params.get("amount"), 0) or 0
        preimage_hex = str(params.get("preimage") or "").strip().lower()
        tlv_records = params.get("tlv_records")
        tlv_records = list(tlv_records) if isinstance(tlv_records, list) else []

        if not pubkey or len(pubkey) != 66:
            return {
                "result_type": "pay_keysend",
                "error": {"code": "OTHER", "message": "Missing or invalid pubkey"},
            }
        try:
            bytes.fromhex(pubkey)
        except ValueError:
            return {
                "result_type": "pay_keysend",
                "error": {"code": "OTHER", "message": "Missing or invalid pubkey"},
            }
        if amount_msat <= 0:
            return {
                "result_type": "pay_keysend",
                "error": {"code": "OTHER", "message": "Amount must be positive"},
            }

        # Fix the keysend preimage up front so the ledger's payment hash
        # (sha256(preimage)) matches the payment LND actually sends.
        if preimage_hex:
            try:
                bytes.fromhex(preimage_hex)
            except ValueError:
                return {
                    "result_type": "pay_keysend",
                    "error": {"code": "OTHER", "message": "Invalid preimage"},
                }
        else:
            for rec in tlv_records:
                if isinstance(rec, dict) and int(rec.get("type") or 0) == 5482373484:
                    candidate = str(rec.get("value") or "").strip().lower()
                    try:
                        if len(bytes.fromhex(candidate)) == 32:
                            preimage_hex = candidate
                    except ValueError:
                        pass
                    break
        if not preimage_hex:
            preimage_hex = secrets.token_bytes(32).hex()
        if len(preimage_hex) != 64:
            return {
                "result_type": "pay_keysend",
                "error": {"code": "OTHER", "message": "Invalid preimage"},
            }
        payment_hash = hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()

        fee_reserve_msat = max(10_000, (amount_msat + 99) // 100)
        tx_id, internal_payee_id = self.store.reserve_outgoing_payment(
            app_id=app_id,
            amount_msat=amount_msat,
            fee_reserve_msat=fee_reserve_msat,
            payment_hash=payment_hash,
            invoice="",
            description=f"Keysend to {pubkey[:16]}…",
            description_hash="",
        )
        if internal_payee_id is not None:
            payload = self._finish_internal_payment(
                app_id, internal_payee_id, payment_hash
            )
            payload["result_type"] = "pay_keysend"
            return payload

        try:
            pay_res = self.lnd.pay_keysend(
                dest_pubkey_hex=pubkey,
                amount_msat=amount_msat,
                fee_limit_msat=fee_reserve_msat,
                preimage_hex=preimage_hex,
                tlv_records=tlv_records,
            )
        except _lnd_mod.LndError as exc:
            self.store.finalize_outgoing_payment(tx_id, succeeded=False)
            return {
                "result_type": "pay_keysend",
                "error": {"code": "PAYMENT_FAILED", "message": str(exc)},
            }

        settled_tx = self.store.finalize_outgoing_payment(
            tx_id,
            succeeded=True,
            preimage=pay_res["preimage"],
            fees_paid_msat=pay_res["fees_paid_msat"],
        )
        self._emit_notification(app_id, "payment_sent", settled_tx)
        _audit_mod.audit_log(
            "nwc_keysend_sent",
            app_id=app_id,
            alias=app.get("name"),
            amount_msat=amount_msat,
            fees_paid_msat=pay_res["fees_paid_msat"],
            dest=pubkey,
            payment_hash=payment_hash,
        )
        return {
            "result_type": "pay_keysend",
            "result": {
                "preimage": pay_res["preimage"],
                "fees_paid": pay_res["fees_paid_msat"],
            },
        }

    def _finish_internal_payment(
        self, app_id: int, internal_payee_id: int, payment_hash: str
    ) -> dict[str, Any]:
        """Complete a wallet-to-wallet settlement with a verifiable preimage.

        The preimage is taken from the incoming ledger record; when missing it
        is resolved from LND (the invoice was created on this node, so LND
        knows its preimage even before external settlement) and recorded on
        both ledger rows. Nothing is ever fabricated: clients verify
        sha256(preimage) == payment_hash.
        """
        tx = self.store.find_tx_for_app(app_id, payment_hash=payment_hash)
        preimage = (tx or {}).get("preimage") or ""
        if not preimage:
            try:
                preimage = str(
                    self.lnd.lookup_invoice(payment_hash).get("preimage") or ""
                ).lower()
            except _lnd_mod.LndError:
                preimage = ""
            if preimage:
                self.store.set_preimage_for_hash(payment_hash, preimage)
        if tx:
            tx = dict(tx)
            if preimage:
                tx["preimage"] = preimage
            self._emit_notification(app_id, "payment_sent", tx)
        inc_tx = self.store.find_tx_for_app(
            internal_payee_id, payment_hash=payment_hash
        )
        if inc_tx:
            inc_tx = dict(inc_tx)
            if preimage:
                inc_tx["preimage"] = preimage
            self._emit_notification(internal_payee_id, "payment_received", inc_tx)
            # The ledger has settled this invoice internally, but the LND
            # invoice is still OPEN: anyone holding the bolt11 could pay it
            # externally and the funds would land on the node credited to
            # nobody (the ledger row is already settled, so reconciliation
            # would never credit a second time). Cancel it on LND so it can
            # never settle again. Best-effort: the internal settlement above
            # stands either way, and a failed cancel is logged + audited.
            self._cancel_lnd_invoice(
                payment_hash, "internal_settlement", internal_payee_id
            )
        return {
            "result_type": "pay_invoice",
            "result": {"preimage": preimage, "fees_paid": 0},
        }

    # ── Notifications & Relay Worker ───────────────────────────────

    def _emit_notification(
        self, app_id: int, notification_type: str, tx: dict[str, Any]
    ) -> None:
        apps = [
            a
            for a in self.store.get_all_active_apps_internal()
            if int(a["id"]) == int(app_id)
        ]
        if not apps:
            return
        app = apps[0]
        if "notifications" not in (app.get("scopes") or []):
            return
        body = json.dumps(
            {
                "notification_type": notification_type,
                "notification": self.store.to_nip47_tx(tx),
            },
            separators=(",", ":"),
        )
        w_priv = bytes.fromhex(app["wallet_privkey"])
        c_pub = bytes.fromhex(app["appPubkey"])
        try:
            ev_nip44 = _nostr_mod.make_event(
                app["wallet_privkey"],
                kind=23197,
                content=_nostr_mod.nip44_encrypt(body, w_priv, c_pub),
                tags=[["p", app["appPubkey"]]],
            )
            ev_nip04 = _nostr_mod.make_event(
                app["wallet_privkey"],
                kind=23196,
                content=_nostr_mod.nip04_encrypt(body, w_priv, c_pub),
                tags=[["p", app["appPubkey"]]],
            )
            self._broadcast_events([ev_nip44, ev_nip04])
        except Exception as exc:
            logger.debug("Failed to emit NIP-47 notification: %s", exc)

    def _broadcast_events(self, events: list[dict[str, Any]]) -> None:
        with self._relay_conns_lock:
            conns = list(self._relay_conns)
        for conn in conns:
            for ev in events:
                try:
                    conn.send_json(["EVENT", ev])
                except Exception:
                    pass

    def _nip42_authenticate(
        self, conn: _nostr_mod.WebSocketConnection, relay_url: str, challenge: Any
    ) -> bool:
        """Answer a NIP-42 `AUTH` challenge with a kind-22242 event.

        The connection authenticates as the first (oldest) wallet: a relay
        connection carries one AUTH identity, so relays that restrict reads
        to the authenticated pubkey will only serve that wallet on this
        connection. Public relays (the default) merely require *an*
        authenticated key. Returns True when an AUTH event was sent.
        """
        if not isinstance(challenge, str) or not challenge or len(challenge) > 1024:
            return False
        apps = self.store.get_all_active_apps_internal()
        if not apps:
            return False
        app = apps[0]
        try:
            auth_event = _nostr_mod.make_event(
                app["wallet_privkey"],
                kind=22242,
                content="",
                tags=[["relay", relay_url], ["challenge", challenge]],
            )
            conn.send_json(["AUTH", auth_event])
        except Exception as exc:
            logger.debug("NIP-42 auth to %s failed: %s", relay_url, exc)
            return False
        logger.debug(
            "NIP-42 authenticated to %s as wallet %s", relay_url, app["walletPubkey"]
        )
        return True

    def _relay_loop(self, relay_url: str) -> None:
        backoff = 2.0
        while not self._stop_event.is_set():
            conn = _nostr_mod.WebSocketConnection(
                relay_url, timeout=20.0, socks5_proxy=self.tor_socks_proxy
            )
            try:
                conn.connect()
                with self._relay_conns_lock:
                    self._relay_conns.append(conn)
                backoff = 2.0
                self._sync_relay_subscriptions(conn)

                while not self._stop_event.is_set():
                    msg = conn.recv_message()
                    if msg is None:
                        break
                    try:
                        frame = json.loads(msg)
                    except Exception:
                        continue
                    if not isinstance(frame, list) or not frame:
                        continue
                    if frame[0] == "AUTH" and len(frame) >= 2:
                        # NIP-42: prove wallet-key ownership, then re-issue
                        # the subscription (the original REQ was sent before
                        # authentication and may have been refused).
                        if self._nip42_authenticate(conn, relay_url, frame[1]):
                            self._sync_relay_subscriptions(conn)
                        continue
                    if frame[0] == "CLOSED":
                        # e.g. "auth-required: ..." — the relay will follow
                        # with an AUTH challenge, handled above. Log so an
                        # operator can see why a relay serves no requests.
                        logger.info(
                            "Relay %s closed subscription %s: %s",
                            relay_url,
                            frame[1] if len(frame) > 1 else "",
                            frame[2] if len(frame) > 2 else "",
                        )
                        continue
                    if (
                        len(frame) >= 3
                        and frame[0] == "EVENT"
                        and isinstance(frame[2], dict)
                    ):
                        responses = self.process_nip47_event(frame[2])
                        for resp_ev in responses:
                            conn.send_json(["EVENT", resp_ev])
            except Exception as exc:
                logger.debug("Relay %s disconnected: %s", relay_url, exc)
            finally:
                with self._relay_conns_lock:
                    if conn in self._relay_conns:
                        self._relay_conns.remove(conn)
                conn.close()
            self._stop_event.wait(backoff)
            backoff = min(backoff * 1.5, 30.0)

    def _sync_relay_subscriptions(self, conn: _nostr_mod.WebSocketConnection) -> None:
        apps = self.store.get_all_active_apps_internal()
        wallet_pubkeys = [a["walletPubkey"] for a in apps if a.get("walletPubkey")]
        for app in apps:
            try:
                info_ev = self.build_nip47_info_event(app)
                conn.send_json(["EVENT", info_ev])
            except Exception:
                pass
        if wallet_pubkeys:
            conn.send_json(
                [
                    "REQ",
                    "sovran-nwc-sub",
                    {
                        "kinds": [23194],
                        "#p": wallet_pubkeys,
                        "since": int(time.time()) - 120,
                    },
                ]
            )

    def refresh_all_relays(self) -> None:
        with self._pubkey_cache_lock:
            self._pubkey_cache = None
        with self._relay_conns_lock:
            conns = list(self._relay_conns)
        for conn in conns:
            try:
                self._sync_relay_subscriptions(conn)
            except Exception:
                pass

    def _invoice_watcher_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.reconcile_pending_invoices()
            except Exception:
                pass
            self._stop_event.wait(3.0)

    def start_background_workers(self) -> None:
        threading.Thread(
            target=self._invoice_watcher_loop,
            name="nwc-invoice-watcher",
            daemon=True,
        ).start()
        for relay_url in self.relays:
            threading.Thread(
                target=self._relay_loop,
                args=(relay_url,),
                name=f"nwc-relay-{relay_url}",
                daemon=True,
            ).start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._relay_conns_lock:
            conns = list(self._relay_conns)
            self._relay_conns.clear()
        for c in conns:
            c.close()

    # ── HTTP Management API Dispatch ───────────────────────────────

    def handle_http(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: dict[str, Any] | None,
    ) -> tuple[int, Any]:
        parsed = urllib.parse.urlparse(path)
        route = parsed.path.rstrip("/") or "/"
        qs = urllib.parse.parse_qs(parsed.query)
        auth = headers.get("Authorization") or headers.get("authorization")

        try:
            # Unauthenticated status & auth endpoints
            if route == "/api/info" and method == "GET":
                return 200, {
                    "setupCompleted": True,
                    "running": True,
                    "unlocked": True,
                    "backendType": "LND",
                    "version": "sovran-nwc-2.2.2",
                }

            if route == "/api/setup" and method == "POST":
                return 200, {"ok": True}

            if route in ("/api/unlock", "/api/start") and method == "POST":
                pw = str((body or {}).get("unlockPassword") or "")
                perm = str((body or {}).get("permission") or "full")
                token, granted, _kind = self._issue_token(pw, permission=perm)
                # Report the permission actually granted (decided by which
                # credential was presented), not the one the caller asked for.
                return 200, {"token": token, "permission": granted}

            # Health / node status (allowed for full, read, invoice)
            if route == "/api/node/status" and method == "GET":
                self.verify_token(auth, {"full", "read", "invoice"})
                try:
                    info = self.lnd.get_info()
                    ready = bool(info.get("pubkey"))
                except _lnd_mod.LndError:
                    ready = False
                return 200, {"isReady": ready, "running": ready, "online": ready}

            # List apps (allowed for full, read, invoice)
            if route == "/api/apps" and method == "GET":
                perm = self.verify_token(auth, {"full", "read", "invoice"})
                limit = _strict_int(qs, "limit", 100, 1, MAX_PAGE_SIZE)
                offset = _strict_int(qs, "offset", 0, 0, 2**31 - 1)
                if perm != "invoice":
                    self.reconcile_pending_invoices()
                apps, total = self.store.list_apps(limit=limit, offset=offset)
                if perm == "invoice":
                    # Least-privilege view for nwc-lnurl: only alias & bounds, no balances or keys
                    sanitized = [
                        {
                            "id": a["id"],
                            "isolated": a["isolated"],
                            "metadata": a["metadata"],
                        }
                        for a in apps
                    ]
                    return 200, {"apps": sanitized, "totalCount": total}
                return 200, {"apps": apps, "totalCount": total}

            # Create app (full only)
            if route == "/api/apps" and method == "POST":
                self.verify_token(auth, {"full"})
                payload = body or {}
                created = self.store.create_app(
                    name=str(payload.get("name") or ""),
                    scopes=list(payload.get("scopes") or []),
                    isolated=bool(payload.get("isolated", True)),
                    max_amount_sat=int(payload.get("maxAmountSat") or 0),
                    budget_renewal=str(payload.get("budgetRenewal") or "never"),
                    metadata=dict(payload.get("metadata") or {}),
                    relays=self.relays,
                )
                created.pop("wallet_privkey", None)
                _audit_mod.audit_log(
                    "nwc_wallet_created",
                    wallet_id=created.get("id"),
                    name=created.get("name"),
                    scopes=created.get("scopes"),
                )
                self.refresh_all_relays()
                return 200, created

            # Get single app (full, read)
            if route.startswith("/api/v2/apps/") and method == "GET":
                self.verify_token(auth, {"full", "read"})
                app_id = int(route.rsplit("/", 1)[-1])
                self.reconcile_pending_invoices(app_id=app_id)
                app = self.store.get_app(app_id)
                if app is None:
                    return 404, {"error": "App not found"}
                return 200, app

            # Delete app by pubkey (full only)
            if route.startswith("/api/apps/") and method == "DELETE":
                self.verify_token(auth, {"full"})
                pubkey = urllib.parse.unquote(route.split("/api/apps/", 1)[1])
                deleted = self.store.delete_app_by_pubkey(pubkey)
                if not deleted:
                    return 404, {"error": "App not found"}
                _audit_mod.audit_log("nwc_wallet_deleted", app_pubkey=pubkey)
                self.refresh_all_relays()
                return 200, {"ok": True}

            # Internal transfers (full only)
            if route == "/api/transfers" and method == "POST":
                self.verify_token(auth, {"full"})
                payload = body or {}
                amt_msat = payload.get("amountMsat")
                if amt_msat is None:
                    amt_msat = int(payload.get("amountSat") or 0) * 1000
                amt_msat = int(amt_msat)
                from_id = (
                    int(payload["fromAppId"])
                    if payload.get("fromAppId") is not None
                    else None
                )
                to_id = (
                    int(payload["toAppId"])
                    if payload.get("toAppId") is not None
                    else None
                )
                desc = str(payload.get("description") or "")

                # When funding from node primary wallet, verify channel liquidity backs all isolated sub-wallets
                if from_id is None and to_id is not None:
                    try:
                        node_local_msat = self.lnd.get_channel_balance_msat()
                        allocated_msat = self.store.total_allocated_msat()
                        if node_local_msat > 0 and allocated_msat + amt_msat > node_local_msat:
                            return 400, {
                                "error": "Insufficient node channel liquidity to fund sub-wallet"
                            }
                    except _lnd_mod.LndError:
                        pass

                res = self.store.transfer(
                    from_app_id=from_id,
                    to_app_id=to_id,
                    amount_msat=amt_msat,
                    description=desc,
                )
                return 200, res

            # Issue invoice attributed to an isolated app (allowed for full & invoice)
            if route == "/api/invoices" and method == "POST":
                self.verify_token(auth, {"full", "invoice"})
                payload = body or {}
                amt_msat = int(payload.get("amountMsat") or 0)
                to_app_id = int(payload.get("toAppId") or 0)
                desc = str(payload.get("description") or "")
                if amt_msat <= 0 or to_app_id <= 0:
                    return 400, {"error": "amountMsat and toAppId are required"}
                app = self.store.get_app(to_app_id)
                if app is None:
                    return 404, {"error": "Target app not found"}
                self._ensure_pending_capacity(to_app_id)

                inv = self.lnd.create_invoice(
                    amount_msat=amt_msat,
                    memo=desc,
                    expiry=3600,
                    private=True,
                )
                self.store.record_incoming_invoice(
                    app_id=to_app_id,
                    payment_hash=inv["payment_hash"],
                    invoice=inv["invoice"],
                    amount_msat=amt_msat,
                    description=desc,
                    description_hash="",
                    created_at=inv["created_at"],
                    expires_at=inv["expires_at"],
                )
                return 200, {
                    "invoice": inv["invoice"],
                    "paymentHash": inv["payment_hash"],
                    "appId": to_app_id,
                }

            # List transactions (full, read)
            if route == "/api/transactions" and method == "GET":
                self.verify_token(auth, {"full", "read"})
                app_id = (
                    int(qs["appId"][0]) if qs.get("appId") else None
                )
                if app_id is not None:
                    self.reconcile_pending_invoices(app_id=app_id)
                limit = _strict_int(qs, "limit", 100, 1, MAX_PAGE_SIZE)
                offset = _strict_int(qs, "offset", 0, 0, 2**31 - 1)
                # The operator view must include pending rows: `nwc-wallet
                # drain/delete` refuse to run while a payment is in flight and
                # detect that by looking for state == "pending" here.
                txs, total = self.store.list_transactions(
                    app_id=app_id, limit=limit, offset=offset, unpaid=True
                )
                return 200, {"transactions": txs, "totalCount": total}

            return 404, {"error": f"Not found: {method} {route}"}

        except NwcStoreError as exc:
            return exc.http_status, {"error": str(exc), "code": exc.code}
        except _lnd_mod.LndError as exc:
            return 502, {"error": str(exc), "code": exc.code}
        except (ValueError, TypeError):
            # A malformed query string or JSON field must be a 400, not an
            # unhandled exception inside the request handler.
            return 400, {"error": "Invalid request parameter", "code": "invalid_parameter"}
        except Exception:  # noqa: BLE001 - defensive boundary
            logger.exception("Unhandled management API error for %s %s", method, route)
            return 500, {"error": "Internal server error", "code": "internal"}


def make_http_server(
    host: str, port: int, daemon: SovranNwcDaemon
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            logger.debug("NWC-API %s " + fmt, self.address_string(), *args)

        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1024 * 1024:
                self._send(413, {"error": "Payload too large"})
                return
            raw = self.rfile.read(length) if length > 0 else b""
            body = None
            if raw:
                try:
                    body = json.loads(raw.decode("utf-8"))
                except Exception:
                    self._send(400, {"error": "Invalid JSON body"})
                    return
            hdrs = {k: v for k, v in self.headers.items()}
            status, resp_obj = daemon.handle_http(method, self.path, hdrs, body)
            self._send(status, resp_obj)

        def _send(self, status: int, payload: Any) -> None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def do_DELETE(self) -> None:  # noqa: N802
            self._dispatch("DELETE")

    return ThreadingHTTPServer((host, port), Handler)


def _read_secret_file(path: str) -> str:
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "18080"))
    work_dir = os.environ.get("WORK_DIR", "/var/lib/albyhub")
    db_path = os.environ.get("DATABASE_URI", os.path.join(work_dir, "nwc.db"))

    password = os.environ.get("AUTO_UNLOCK_PASSWORD", "").strip()
    if not password:
        pw_file = os.environ.get(
            "NWC_UNLOCK_PASSWORD_FILE", os.path.join(work_dir, "unlock-password")
        )
        password = _read_secret_file(pw_file)
    if not password:
        raise RuntimeError(
            "Unlock password not configured (set AUTO_UNLOCK_PASSWORD or NWC_UNLOCK_PASSWORD_FILE)"
        )

    lnd_rest_url = os.environ.get("LND_REST_URL", "").strip()
    if not lnd_rest_url:
        lnd_rest_addr = os.environ.get("LND_REST_ADDRESS", "127.0.0.1:8080")
        lnd_rest_url = f"https://{lnd_rest_addr}"
    lnd_cert_file = os.environ.get(
        "LND_CERT_FILE", "/etc/nix-bitcoin-secrets/lnd-cert"
    )
    lnd_macaroon_file = os.environ.get(
        "LND_MACAROON_FILE", "/run/lnd/albyhub.macaroon"
    )

    relay_env = os.environ.get(
        "RELAY", "wss://relay.getalby.com,wss://relay2.getalby.com"
    )
    relays = [r.strip() for r in relay_env.split(",") if r.strip()]
    tor_proxy = os.environ.get("NWC_TOR_SOCKS_PROXY", "").strip() or None

    # Scoped credentials (optional): each file holds a secret that may only
    # ever mint tokens of its own scope, no matter what the caller requests.
    # The LNURL service gets the invoice-scoped file instead of the unlock
    # password, so compromising the internet-facing unit no longer yields
    # full ledger authority.
    scoped_passwords: dict[str, str] = {}
    for perm, env_var in (
        ("invoice", "NWC_INVOICE_PASSWORD_FILE"),
        ("read", "NWC_READ_PASSWORD_FILE"),
    ):
        scoped_path = os.environ.get(env_var, "").strip()
        if scoped_path:
            scoped_secret = _read_secret_file(scoped_path)
            if scoped_secret:
                scoped_passwords[perm] = scoped_secret
            else:
                logger.warning(
                    "%s=%s is set but unreadable/empty; scoped '%s' login disabled",
                    env_var,
                    scoped_path,
                    perm,
                )

    store = NwcStore(db_path)
    lnd = _lnd_mod.LndRestClient(
        rest_url=lnd_rest_url,
        cert_file=lnd_cert_file,
        macaroon_file=lnd_macaroon_file,
    )
    daemon = SovranNwcDaemon(
        store=store,
        lnd=lnd,
        unlock_password=password,
        relays=relays,
        tor_socks_proxy=tor_proxy,
        scoped_passwords=scoped_passwords,
    )
    daemon.start_background_workers()

    server = make_http_server(host, port, daemon)

    def _shutdown(signum: int, _frame: Any) -> None:
        logger.info("Shutting down Sovran NWC daemon (signal %s)...", signum)
        daemon.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("Sovran NWC daemon listening on http://%s:%d", host, port)
    server.serve_forever()


if __name__ == "__main__":
    main()
