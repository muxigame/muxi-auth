from __future__ import annotations

import hmac
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from .security import hash_password, needs_rehash, pkce_s256, random_token, token_hash, utc_now, verify_password


def iso(value: datetime) -> str:
    return value.isoformat()


@dataclass(frozen=True)
class Account:
    id: int
    subject: str
    email: str
    username: str
    role: str
    verified: bool
    created_at: str
    last_login_at: str | None

    def claims(self) -> dict:
        return {
            "sub": self.subject,
            "email": self.email,
            "email_verified": self.verified,
            "preferred_username": self.username,
            "username": self.username,
            "role": self.role,
        }

    def public(self) -> dict:
        return {
            "id": self.subject,
            "email": self.email,
            "username": self.username,
            "role": self.role,
            "verified": self.verified,
            "createdAt": self.created_at,
            "lastLoginAt": self.last_login_at,
        }


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    name: str
    client_type: str
    secret_hash: str | None
    redirect_uris: tuple[str, ...]
    scopes: tuple[str, ...]

    @property
    def public_client(self) -> bool:
        return self.client_type == "public"


class Store:
    def __init__(self, database: Path):
        self.database = database
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA journal_mode = WAL")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def _init_schema(self) -> None:
        with self._lock, self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'player',
                    verified INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                CREATE TABLE IF NOT EXISTS email_verifications (
                    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS web_sessions (
                    token_hash TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS web_sessions_account_id ON web_sessions(account_id);
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    client_type TEXT NOT NULL,
                    secret_hash TEXT,
                    redirect_uris TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS authorization_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    nonce TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS access_tokens (
                    token_hash TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
                    scope TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
                    scope TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                """
            )

    @staticmethod
    def _account(row: sqlite3.Row | None) -> Account | None:
        if row is None:
            return None
        return Account(
            id=int(row["id"]),
            subject=str(row["subject"]),
            email=str(row["email"]),
            username=str(row["username"]),
            role=str(row["role"]),
            verified=bool(row["verified"]),
            created_at=str(row["created_at"]),
            last_login_at=row["last_login_at"],
        )

    def register(self, email: str, username: str, password: str) -> tuple[Account, str]:
        now = utc_now()
        raw_verify = random_token(32)
        with self._lock, self.connect() as db:
            try:
                cur = db.execute(
                    """INSERT INTO accounts(subject,email,username,password_hash,created_at)
                       VALUES(?,?,?,?,?)""",
                    (str(uuid.uuid4()), email.lower(), username, hash_password(password), iso(now)),
                )
            except sqlite3.IntegrityError as error:
                text = str(error).lower()
                if "email" in text:
                    raise ValueError("该邮箱已经注册") from error
                raise ValueError("该用户名已经被使用") from error
            account_id = int(cur.lastrowid)
            db.execute(
                "INSERT INTO email_verifications(account_id,token_hash,expires_at) VALUES(?,?,?)",
                (account_id, token_hash(raw_verify), iso(now + timedelta(hours=24))),
            )
            account = self._account(db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone())
        return account, raw_verify  # type: ignore[return-value]

    def verify_email(self, raw_token: str) -> Account | None:
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT account_id,expires_at FROM email_verifications WHERE token_hash=?",
                (token_hash(raw_token),),
            ).fetchone()
            if row is None or datetime.fromisoformat(row["expires_at"]) < utc_now():
                return None
            account_id = int(row["account_id"])
            db.execute("UPDATE accounts SET verified=1 WHERE id=?", (account_id,))
            db.execute("DELETE FROM email_verifications WHERE account_id=?", (account_id,))
            return self._account(db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone())

    def authenticate(self, identity: str, password: str) -> Account | None:
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT * FROM accounts WHERE email=? COLLATE NOCASE OR username=? COLLATE NOCASE",
                (identity, identity),
            ).fetchone()
            if row is None or not verify_password(str(row["password_hash"]), password):
                return None
            account = self._account(row)
            if account is None or not account.verified:
                raise PermissionError("请先完成邮箱验证")
            if needs_rehash(str(row["password_hash"])):
                db.execute("UPDATE accounts SET password_hash=? WHERE id=?", (hash_password(password), account.id))
            now = iso(utc_now())
            db.execute("UPDATE accounts SET last_login_at=? WHERE id=?", (now, account.id))
            return self._account(db.execute("SELECT * FROM accounts WHERE id=?", (account.id,)).fetchone())

    def create_web_session(self, account_id: int, days: int) -> str:
        raw = random_token(40)
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute(
                "INSERT INTO web_sessions(token_hash,account_id,created_at,expires_at) VALUES(?,?,?,?)",
                (token_hash(raw), account_id, iso(now), iso(now + timedelta(days=days))),
            )
        return raw

    def web_session(self, raw: str | None) -> Account | None:
        if not raw:
            return None
        with self.connect() as db:
            row = db.execute(
                """SELECT a.* FROM web_sessions s JOIN accounts a ON a.id=s.account_id
                   WHERE s.token_hash=? AND s.expires_at>?""",
                (token_hash(raw), iso(utc_now())),
            ).fetchone()
            return self._account(row)

    def delete_web_session(self, raw: str | None) -> None:
        if not raw:
            return
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM web_sessions WHERE token_hash=?", (token_hash(raw),))

    def seed_client(
        self,
        client_id: str,
        name: str,
        client_type: str,
        redirect_uris: list[str],
        scopes: list[str],
        secret: str | None = None,
    ) -> None:
        secret_hash = token_hash(secret) if secret else None
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO oauth_clients(client_id,name,client_type,secret_hash,redirect_uris,scopes,created_at)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(client_id) DO UPDATE SET
                     name=excluded.name,client_type=excluded.client_type,secret_hash=excluded.secret_hash,
                     redirect_uris=excluded.redirect_uris,scopes=excluded.scopes""",
                (
                    client_id,
                    name,
                    client_type,
                    secret_hash,
                    json.dumps(redirect_uris),
                    " ".join(scopes),
                    iso(utc_now()),
                ),
            )

    def client(self, client_id: str) -> OAuthClient | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()
        if row is None:
            return None
        return OAuthClient(
            client_id=str(row["client_id"]),
            name=str(row["name"]),
            client_type=str(row["client_type"]),
            secret_hash=row["secret_hash"],
            redirect_uris=tuple(json.loads(str(row["redirect_uris"]))),
            scopes=tuple(str(row["scopes"]).split()),
        )

    @staticmethod
    def redirect_allowed(client: OAuthClient, redirect_uri: str) -> bool:
        if redirect_uri in client.redirect_uris:
            return True
        if not client.public_client:
            return False
        actual = urlsplit(redirect_uri)
        if actual.scheme != "http" or actual.hostname not in {"127.0.0.1", "::1"}:
            return False
        for registered in client.redirect_uris:
            expected = urlsplit(registered)
            if (
                expected.scheme == "http"
                and expected.hostname == actual.hostname
                and expected.path == actual.path
                and expected.query == actual.query
            ):
                return True
        return False

    @staticmethod
    def verify_client_secret(client: OAuthClient, secret: str | None) -> bool:
        if client.public_client:
            return secret in {None, ""}
        if not secret or not client.secret_hash:
            return False
        return hmac.compare_digest(client.secret_hash, token_hash(secret))

    def create_authorization_code(
        self,
        client_id: str,
        account_id: int,
        redirect_uri: str,
        scope: str,
        code_challenge: str,
        nonce: str | None,
    ) -> str:
        raw = random_token(32)
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO authorization_codes
                   (code_hash,client_id,account_id,redirect_uri,scope,code_challenge,nonce,created_at,expires_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    token_hash(raw), client_id, account_id, redirect_uri, scope, code_challenge, nonce,
                    iso(now), iso(now + timedelta(minutes=5)),
                ),
            )
        return raw

    def consume_authorization_code(
        self, raw: str, client_id: str, redirect_uri: str, verifier: str
    ) -> tuple[Account, str, str | None] | None:
        now = utc_now()
        with self._lock, self.connect() as db:
            row = db.execute(
                """SELECT * FROM authorization_codes
                   WHERE code_hash=? AND client_id=? AND redirect_uri=? AND used_at IS NULL""",
                (token_hash(raw), client_id, redirect_uri),
            ).fetchone()
            if row is None or datetime.fromisoformat(row["expires_at"]) < now:
                return None
            if not hmac.compare_digest(str(row["code_challenge"]), pkce_s256(verifier)):
                return None
            db.execute("UPDATE authorization_codes SET used_at=? WHERE code_hash=?", (iso(now), token_hash(raw)))
            account = self._account(db.execute("SELECT * FROM accounts WHERE id=?", (int(row["account_id"]),)).fetchone())
            if account is None:
                return None
            return account, str(row["scope"]), row["nonce"]

    def issue_access_token(self, account_id: int, client_id: str, scope: str, seconds: int) -> str:
        raw = random_token(40)
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute(
                "INSERT INTO access_tokens(token_hash,account_id,client_id,scope,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                (token_hash(raw), account_id, client_id, scope, iso(now), iso(now + timedelta(seconds=seconds))),
            )
        return raw

    def access_token(self, raw: str | None) -> tuple[Account, str, str] | None:
        if not raw:
            return None
        with self.connect() as db:
            row = db.execute(
                """SELECT t.client_id,t.scope,a.* FROM access_tokens t
                   JOIN accounts a ON a.id=t.account_id
                   WHERE t.token_hash=? AND t.revoked_at IS NULL AND t.expires_at>?""",
                (token_hash(raw), iso(utc_now())),
            ).fetchone()
            account = self._account(row)
            if row is None or account is None:
                return None
            return account, str(row["client_id"]), str(row["scope"])

    def issue_refresh_token(self, account_id: int, client_id: str, scope: str, days: int) -> str:
        raw = random_token(48)
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute(
                "INSERT INTO refresh_tokens(token_hash,account_id,client_id,scope,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                (token_hash(raw), account_id, client_id, scope, iso(now), iso(now + timedelta(days=days))),
            )
        return raw

    def consume_refresh_token(self, raw: str, client_id: str) -> tuple[Account, str] | None:
        now = utc_now()
        with self._lock, self.connect() as db:
            row = db.execute(
                """SELECT r.*,a.* FROM refresh_tokens r JOIN accounts a ON a.id=r.account_id
                   WHERE r.token_hash=? AND r.client_id=? AND r.revoked_at IS NULL""",
                (token_hash(raw), client_id),
            ).fetchone()
            if row is None or datetime.fromisoformat(row["expires_at"]) < now:
                return None
            db.execute("UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?", (iso(now), token_hash(raw)))
            account = self._account(row)
            return (account, str(row["scope"])) if account else None

    def revoke(self, raw: str) -> None:
        hashed = token_hash(raw)
        now = iso(utc_now())
        with self._lock, self.connect() as db:
            db.execute("UPDATE access_tokens SET revoked_at=? WHERE token_hash=?", (now, hashed))
            db.execute("UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?", (now, hashed))

    def list_accounts(self, limit: int = 200) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM accounts ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)
            ).fetchall()
        return [account.public() for row in rows if (account := self._account(row)) is not None]

    def promote_admin(self, identity: str) -> Account | None:
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT * FROM accounts WHERE email=? COLLATE NOCASE OR username=? COLLATE NOCASE",
                (identity, identity),
            ).fetchone()
            if row is None:
                return None
            db.execute("UPDATE accounts SET role='admin' WHERE id=?", (int(row["id"]),))
            return self._account(db.execute("SELECT * FROM accounts WHERE id=?", (int(row["id"]),)).fetchone())


