"""Restricted launcher -> authenticated game connection -> account-page login.

Raw bootstrap secrets stay in native code. Proofs and tickets are random, hashed
at rest, PKCE-bound, and consumed inside SQLite write transactions (all workers).
Legacy UID-only join grants alone never authorize a platform login.
"""
from __future__ import annotations

import hmac
import re
from datetime import timedelta

from .security import pkce_s256, random_token, token_hash, utc_now
from .store import Store, iso

BOOTSTRAP_SECONDS = 3600
PROOF_SECONDS = 30
TICKET_SECONDS = 30
PURPOSE = "terminal-platform-login-v1"
TARGET = "https://mc.muxigame.com/account.html"
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class TerminalSsoStore:
    def __init__(self, store: Store):
        self.store = store
        with store._lock, store.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS terminal_bootstraps (
                    secret_hash TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    source_token_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_proofs (
                    proof_hash TEXT PRIMARY KEY,
                    bootstrap_hash TEXT NOT NULL REFERENCES terminal_bootstraps(secret_hash) ON DELETE CASCADE,
                    challenge TEXT NOT NULL, request_id TEXT NOT NULL,
                    purpose TEXT NOT NULL, target TEXT NOT NULL, expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_tickets (
                    ticket_hash TEXT PRIMARY KEY,
                    bootstrap_hash TEXT NOT NULL REFERENCES terminal_bootstraps(secret_hash) ON DELETE CASCADE,
                    challenge TEXT NOT NULL, request_id TEXT NOT NULL,
                    purpose TEXT NOT NULL, target TEXT NOT NULL,
                    server_hash TEXT NOT NULL, game_session TEXT NOT NULL, expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_disconnections (
                    server_hash TEXT NOT NULL, game_session TEXT NOT NULL, expires_at TEXT NOT NULL,
                    PRIMARY KEY(server_hash,game_session)
                );
            """)

    @staticmethod
    def _valid_source(db, bootstrap_hash, now):
        return db.execute("""SELECT b.account_id, a.uid FROM terminal_bootstraps b
            JOIN access_tokens t ON t.token_hash=b.source_token_hash AND t.account_id=b.account_id
            JOIN accounts a ON a.id=b.account_id
            WHERE b.secret_hash=? AND b.expires_at>? AND t.expires_at>? AND t.revoked_at IS NULL""",
            (bootstrap_hash, now, now)).fetchone()

    @staticmethod
    def _sweep(db, now):
        for table in ("terminal_tickets", "terminal_proofs", "terminal_bootstraps", "terminal_disconnections"):
            db.execute(f"DELETE FROM {table} WHERE expires_at<=?", (now,))

    def bootstrap(self, account_id: int, source_token: str) -> str:
        raw = random_token(32)
        now = utc_now()
        with self.store._lock, self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._sweep(db, iso(now))
            source = db.execute("""SELECT account_id FROM access_tokens
                WHERE token_hash=? AND account_id=? AND expires_at>? AND revoked_at IS NULL""",
                (token_hash(source_token), account_id, iso(now))).fetchone()
            if source is None:
                raise ValueError("Authentication is no longer valid")
            db.execute("INSERT INTO terminal_bootstraps VALUES(?,?,?,?)",
                (token_hash(raw), account_id, token_hash(source_token), iso(now+timedelta(seconds=BOOTSTRAP_SECONDS))))
        return raw

    def proof(self, bootstrap: str, challenge: str, request_id: str) -> str:
        if not _TOKEN.fullmatch(bootstrap) or not _TOKEN.fullmatch(challenge) or not _UUID.fullmatch(request_id):
            raise ValueError("Invalid terminal request")
        raw = random_token(32)
        now = utc_now()
        with self.store._lock, self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._sweep(db, iso(now))
            if self._valid_source(db, token_hash(bootstrap), iso(now)) is None:
                raise ValueError("Authentication is no longer valid")
            # At most one outstanding request per game process. Replaced requests fail closed.
            db.execute("DELETE FROM terminal_proofs WHERE bootstrap_hash=?", (token_hash(bootstrap),))
            db.execute("DELETE FROM terminal_tickets WHERE bootstrap_hash=?", (token_hash(bootstrap),))
            db.execute("INSERT INTO terminal_proofs VALUES(?,?,?,?,?,?,?)",
                (token_hash(raw), token_hash(bootstrap), challenge, request_id, PURPOSE, TARGET,
                 iso(now+timedelta(seconds=PROOF_SECONDS))))
        return raw

    def ticket(self, proof: str, uid: int, request_id: str, game_session: str, server_key: str) -> str:
        if not _TOKEN.fullmatch(proof) or not _UUID.fullmatch(request_id) or not _UUID.fullmatch(game_session):
            raise ValueError("Invalid terminal request")
        raw = random_token(32)
        now = utc_now()
        with self.store._lock, self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM terminal_disconnections WHERE server_hash=? AND game_session=? AND expires_at>?",
                          (token_hash(server_key), game_session, iso(now))).fetchone():
                raise ValueError("Game session disconnected")
            row = db.execute("""SELECT * FROM terminal_proofs
                WHERE proof_hash=? AND request_id=? AND purpose=? AND target=? AND expires_at>?""",
                (token_hash(proof), request_id, PURPOSE, TARGET, iso(now))).fetchone()
            source = self._valid_source(db, row["bootstrap_hash"], iso(now)) if row else None
            if source is None or source["uid"] != uid:
                raise ValueError("Terminal proof is invalid or expired")
            db.execute("DELETE FROM terminal_proofs WHERE proof_hash=?", (token_hash(proof),))
            db.execute("INSERT INTO terminal_tickets VALUES(?,?,?,?,?,?,?,?,?)",
                (token_hash(raw), row["bootstrap_hash"], row["challenge"], request_id,
                 PURPOSE, TARGET, token_hash(server_key), game_session,
                 iso(now+timedelta(seconds=TICKET_SECONDS))))
        return raw

    def exchange(self, ticket: str, verifier: str, request_id: str):
        if not _TOKEN.fullmatch(ticket) or not _TOKEN.fullmatch(verifier) or not _UUID.fullmatch(request_id):
            raise ValueError("Invalid terminal request")
        now = utc_now()
        with self.store._lock, self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT * FROM terminal_tickets
                WHERE ticket_hash=? AND request_id=? AND purpose=? AND target=? AND expires_at>?""",
                (token_hash(ticket), request_id, PURPOSE, TARGET, iso(now))).fetchone()
            source = self._valid_source(db, row["bootstrap_hash"], iso(now)) if row else None
            if source is None or not hmac.compare_digest(row["challenge"], pkce_s256(verifier)):
                raise ValueError("Terminal ticket is invalid or expired")
            account = self.store._account(db.execute(self.store._account_query()+" WHERE a.id=?", (source["account_id"],)).fetchone())
            if account is None:
                raise ValueError("Terminal account is no longer available")
            db.execute("DELETE FROM terminal_tickets WHERE ticket_hash=?", (token_hash(ticket),))
        return account

    def revoke_bootstrap(self, bootstrap: str) -> None:
        if not _TOKEN.fullmatch(bootstrap):
            raise ValueError("Invalid terminal credential")
        with self.store._lock, self.store.connect() as db:
            db.execute("DELETE FROM terminal_bootstraps WHERE secret_hash=?", (token_hash(bootstrap),))

    def disconnect(self, game_session: str, server_key: str) -> None:
        if not _UUID.fullmatch(game_session):
            raise ValueError("Invalid game session")
        with self.store._lock, self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR REPLACE INTO terminal_disconnections VALUES(?,?,?)",
                (token_hash(server_key),game_session,iso(utc_now()+timedelta(seconds=BOOTSTRAP_SECONDS))))
            db.execute("DELETE FROM terminal_tickets WHERE game_session=? AND server_hash=?",
                (game_session, token_hash(server_key)))
