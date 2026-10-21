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
    "list_transactions": ["list_transactions"],
    # The spend scope covers every way to send: invoice payments and
    # keysend (NWC-04). The deprecated multi_pay_* commands are deliberately
    # not offered — they were removed from NIP-47 and only exist as an
    # Alby Hub legacy dialect.
    "pay_invoice": ["pay_invoice", "pay_keysend"],
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
            # By default NIP-47 list_transactions returns settled transactions unless unpaid=True
            pass
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

    def _check_budget_locked(
        self, cur: sqlite3.Cursor, app_row: sqlite3.Row, needed_msat: int
    ) -> None:
        max_sat = int(app_row["max_amount_sat"] or 0)
        if max_sat <= 0:
            return
        max_msat = max_sat * 1000
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

    @staticmethod
    def to_nip47_tx(tx: dict[str, Any]) -> dict[str, Any]:
        return {
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
    ) -> None:
        self.store = store
        self.lnd = lnd
        self._unlock_password = unlock_password
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

    # ── Token authentication & authorization ───────────────────────

    def issue_token(self, password: str, permission: str = "full") -> str:
        if not self._unlock_password or not hmac.compare_digest(
            password.strip().encode("utf-8"),
            self._unlock_password.strip().encode("utf-8"),
        ):
            raise NwcStoreError("unauthorized", "Invalid unlock password", 401)
        perm = permission.strip().lower() if permission else "full"
        if perm not in ("full", "read", "invoice"):
            perm = "full"
        token = secrets.token_urlsafe(32)
        with self._tokens_lock:
            self._tokens[token] = perm
        return token

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

    def reconcile_pending_invoices(self, app_id: int | None = None) -> None:
        pending = self.store.list_pending_incoming(app_id=app_id)
        for tx in pending:
            ph = tx.get("paymentHash") or ""
            if not ph:
                continue
            try:
                lnd_inv = self.lnd.lookup_invoice(ph)
            except _lnd_mod.LndError:
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

    # ── NIP-47 Request Processor ───────────────────────────────────

    def process_nip47_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Verify, decrypt, execute, and build response event(s) for a kind 23194 request."""
        if int(event.get("kind", 0)) != 23194:
            return []
        if not _nostr_mod.verify_event(event):
            logger.warning("Rejected NIP-47 event with invalid signature")
            return []

        event_id = str(event["id"]).lower()
        client_pubkey = str(event["pubkey"]).lower()
        p_tags = [
            t[1].lower()
            for t in (event.get("tags") or [])
            if isinstance(t, list) and len(t) >= 2 and t[0] == "p"
        ]
        wallet_pubkey = p_tags[0] if p_tags else None
        app = self.store.get_app_internal_by_pubkeys(client_pubkey, wallet_pubkey)
        if app is None:
            return []

        if not self.store.mark_event_processed(event_id):
            return []

        wallet_priv_bytes = bytes.fromhex(app["wallet_privkey"])
        client_pub_bytes = bytes.fromhex(client_pubkey)

        # Detect NIP-44 v2 vs NIP-04
        enc_tags = [
            t[1]
            for t in (event.get("tags") or [])
            if isinstance(t, list) and len(t) >= 2 and t[0] == "encryption"
        ]
        content = str(event.get("content") or "")
        use_nip44 = ("nip44_v2" in enc_tags) or ("?iv=" not in content)

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
        resp_payload = self.handle_nip47_method(app, method, params)
        return [
            self._build_nip47_response_event(
                app["wallet_privkey"],
                client_pubkey,
                event_id,
                resp_payload,
                use_nip44,
            )
        ]

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
        tags = [
            ["encryption", "nip44_v2 nip04"],
            ["p", app["appPubkey"]],
        ]
        if "notifications" in scopes:
            tags.append(["notifications", "payment_received payment_sent"])
        return _nostr_mod.make_event(
            app["wallet_privkey"],
            kind=13194,
            content=" ".join(methods),
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
                        "pubkey": info["pubkey"],
                        "network": info["network"],
                        "block_height": info["block_height"],
                        "block_hash": info["block_hash"],
                        "methods": list(allowed_methods),
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
                amount_msat = int(params.get("amount") or 0)
                if amount_msat <= 0:
                    return {
                        "result_type": "make_invoice",
                        "error": {"code": "OTHER", "message": "Amount must be positive"},
                    }
                desc = str(params.get("description") or "")
                desc_hash = str(params.get("description_hash") or "")
                expiry = int(params.get("expiry") or 3600)
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
                    limit=int(params.get("limit") or 50),
                    offset=int(params.get("offset") or 0),
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
        override_amt = int(params.get("amount") or 0) or None
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
        amount_msat = int(params.get("amount") or 0)
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
                    if (
                        isinstance(frame, list)
                        and len(frame) >= 3
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
                    "version": "sovran-nwc-2.0.1",
                }

            if route == "/api/setup" and method == "POST":
                return 200, {"ok": True}

            if route in ("/api/unlock", "/api/start") and method == "POST":
                pw = str((body or {}).get("unlockPassword") or "")
                perm = str((body or {}).get("permission") or "full")
                token = self.issue_token(pw, permission=perm)
                return 200, {"token": token, "permission": perm}

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
                limit = int((qs.get("limit") or ["100"])[0])
                offset = int((qs.get("offset") or ["0"])[0])
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
                limit = int((qs.get("limit") or ["100"])[0])
                offset = int((qs.get("offset") or ["0"])[0])
                txs, total = self.store.list_transactions(
                    app_id=app_id, limit=limit, offset=offset
                )
                return 200, {"transactions": txs, "totalCount": total}

            return 404, {"error": f"Not found: {method} {route}"}

        except NwcStoreError as exc:
            return exc.http_status, {"error": str(exc), "code": exc.code}
        except _lnd_mod.LndError as exc:
            return 502, {"error": str(exc), "code": exc.code}


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
