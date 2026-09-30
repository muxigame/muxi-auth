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
from .external_identity import upstream_subject as verified_upstream_subject


def iso(value: datetime) -> str:
    return value.isoformat()


def _has(row: sqlite3.Row, column: str) -> bool:
    """这一行查询里有没有这一列。并非每条 SQL 都 JOIN 了头像表。"""
    return column in row.keys()


@dataclass(frozen=True)
class Account:
    id: int
    subject: str
    uid: int
    username: str
    nickname: str
    game_name: str
    email: str | None
    role: str
    email_verified: bool
    created_at: str
    last_login_at: str | None
    #: 头像内容的指纹。为 None 表示没设过头像；用在 URL 上让浏览器换图时不吃旧缓存。
    avatar_etag: str | None = None

    def claims(self) -> dict:
        claims = {
            "sub": self.subject,
            "muxi_uid": self.uid,
            "preferred_username": self.username,
            "username": self.username,
            "name": self.nickname,
            "nickname": self.nickname,
            "game_name": str(self.uid),
            "role": self.role,
        }
        if self.email:
            claims["email"] = self.email
            claims["email_verified"] = self.email_verified
        return claims

    def public(self) -> dict:
        return {
            "id": self.subject,
            "uid": self.uid,
            "email": self.email,
            "username": self.username,
            "nickname": self.nickname,
            "gameName": str(self.uid),
            "role": self.role,
            "verified": self.email_verified,
            # 带指纹的地址：换了头像就是一个新 URL，不会被浏览器拿旧图糊弄过去。
            "avatarUrl": f"/api/account/avatar/{self.uid}?v={self.avatar_etag}" if self.avatar_etag else None,
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
            columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(accounts)").fetchall()
            }
            if columns and not {"uid", "nickname", "game_name"}.issubset(columns):
                count = int(db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])
                if count:
                    raise RuntimeError(
                        "旧 muxi 账户 schema 中存在账号，不能自动重建；请先执行显式数据迁移"
                    )
                db.executescript(
                    """
                    DROP TABLE IF EXISTS refresh_tokens;
                    DROP TABLE IF EXISTS access_tokens;
                    DROP TABLE IF EXISTS authorization_codes;
                    DROP TABLE IF EXISTS web_sessions;
                    DROP TABLE IF EXISTS email_verifications;
                    DROP TABLE IF EXISTS accounts;
                    """
                )
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL UNIQUE,
                    uid INTEGER NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    nickname TEXT NOT NULL,
                    game_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT,
                    role TEXT NOT NULL DEFAULT 'player',
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                CREATE TABLE IF NOT EXISTS uid_sequence (
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    next_uid INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO uid_sequence(id,next_uid) VALUES(1,10000);
                CREATE TABLE IF NOT EXISTS account_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    verified INTEGER NOT NULL DEFAULT 0,
                    is_primary INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS account_primary_email
                    ON account_emails(account_id) WHERE is_primary=1;
                CREATE TABLE IF NOT EXISTS email_verifications (
                    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS account_avatars (
                    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                    content_type TEXT NOT NULL,
                    bytes BLOB NOT NULL,
                    etag TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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
                CREATE TABLE IF NOT EXISTS external_identities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    provider TEXT NOT NULL,
                    provider_subject TEXT NOT NULL,
                    provider_nickname TEXT,
                    upstream_subject TEXT,
                    raw_profile TEXT,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT,
                    UNIQUE(provider, provider_subject)
                );
                CREATE TABLE IF NOT EXISTS external_oauth_states (
                    state_hash TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    code_verifier TEXT NOT NULL,
                    continue_to TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS external_signups (
                    token_hash TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    provider_subject TEXT NOT NULL,
                    provider_nickname TEXT,
                    upstream_subject TEXT,
                    raw_profile TEXT,
                    continue_to TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS launcher_auth_flows (
                    flow_hash TEXT PRIMARY KEY,
                    secret_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    cancel_after TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS external_binding_pending (
                    token_hash TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    session_hash TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    expected_id INTEGER,
                    profile TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS external_binding_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    provider TEXT NOT NULL,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            for table, additions in {
                "external_identities": {
                    "upstream_subject": "TEXT",
                    "raw_profile": "TEXT",
                },
                "external_oauth_states": {
                    "code_verifier": "TEXT",
                    "purpose": "TEXT NOT NULL DEFAULT 'login'",
                    "account_id": "INTEGER REFERENCES accounts(id) ON DELETE CASCADE",
                    "session_hash": "TEXT",
                    "expected_id": "INTEGER",
                },
                "external_signups": {
                    "upstream_subject": "TEXT",
                    "raw_profile": "TEXT",
                },
            }.items():
                columns = {
                    str(row["name"])
                    for row in db.execute(f"PRAGMA table_info({table})").fetchall()
                }
                for name, column_type in additions.items():
                    if name not in columns:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {column_type}")
            self._migrate_external_channels(db)
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS external_account_channel ON external_identities(account_id,provider) WHERE provider IN ('qq','wechat')")

    @staticmethod
    def _migrate_external_channels(db) -> None:
        for row in db.execute("SELECT * FROM external_identities WHERE provider='czl'").fetchall():
            try:
                profile = json.loads(row["raw_profile"] or "{}")
            except (ValueError, TypeError):
                continue
            channels = {p: verified_upstream_subject(profile, p) for p in ("qq", "wechat")}
            channels = {p: s for p, s in channels.items() if s}
            if not channels:
                continue  # Preserve unknown historical identities; never guess a channel.
            for provider, subject in channels.items():
                db.execute("""INSERT INTO external_identities
                    (account_id,provider,provider_subject,provider_nickname,upstream_subject,raw_profile,created_at,last_login_at)
                    VALUES(?,?,?,?,?,?,?,?)""", (row["account_id"], provider, row["provider_subject"],
                    row["provider_nickname"], subject, row["raw_profile"], row["created_at"], row["last_login_at"]))
            db.execute("DELETE FROM external_identities WHERE id=?", (row["id"],))

    def external_bindings(self, account_id: int) -> dict:
        with self.connect() as db:
            rows = db.execute("SELECT id,provider,provider_nickname FROM external_identities WHERE account_id=?", (account_id,)).fetchall()
            password = db.execute("SELECT password_hash FROM accounts WHERE id=?", (account_id,)).fetchone()
        return {"requiresPassword": bool(password and password[0]),
                "legacy": any(r["provider"] == "czl" for r in rows),
                "bindings": {p: {"bound": any(r["provider"] == p for r in rows),
                    "nickname": next((r["provider_nickname"] for r in rows if r["provider"] == p), None)} for p in ("qq", "wechat")}}

    def authorize_binding_change(self, account_id: int, session: str, password: str) -> None:
        with self.connect() as db:
            row = db.execute("SELECT password_hash FROM accounts WHERE id=?", (account_id,)).fetchone()
            session_row = db.execute("SELECT created_at,expires_at FROM web_sessions WHERE token_hash=? AND account_id=?", (token_hash(session), account_id)).fetchone()
        if not session_row or datetime.fromisoformat(session_row["expires_at"]) <= utc_now():
            raise ValueError("登录已失效，请重新登录")
        if row and row[0]:
            if not verify_password(row[0], password):
                raise ValueError("当前账号密码不正确")
        elif datetime.fromisoformat(session_row["created_at"]) < utc_now() - timedelta(minutes=10):
            raise ValueError("为保护账号，请重新登录后在 10 分钟内操作")

    @staticmethod
    def _binding_slot(db, account_id, provider):
        if provider not in ("qq", "wechat"):
            raise ValueError("不支持的绑定渠道")
        if db.execute("SELECT 1 FROM external_identities WHERE account_id=? AND provider='czl'", (account_id,)).fetchone():
            raise ValueError("历史第三方授权尚未识别渠道，请先通过原 QQ/微信重新登录")
        return db.execute("SELECT * FROM external_identities WHERE account_id=? AND provider=?", (account_id, provider)).fetchone()

    def binding_snapshot(self, account_id: int, provider: str, replace: bool) -> int | None:
        with self.connect() as db:
            row = self._binding_slot(db, account_id, provider)
        if bool(row) != replace:
            raise ValueError("绑定状态已变化，请刷新页面")
        return int(row["id"]) if row else None

    @staticmethod
    def _invalidate_binding_sessions(db, account_id, session_hash):
        db.execute("DELETE FROM web_sessions WHERE account_id=? AND token_hash<>?", (account_id, session_hash))
        for table in ("access_tokens", "refresh_tokens"):
            db.execute(f"UPDATE {table} SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL", (iso(utc_now()), account_id))
        db.execute("DELETE FROM authorization_codes WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM external_oauth_states WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM external_binding_pending WHERE account_id=?", (account_id,))

    def prepare_external_binding(self, context: dict, profile: dict) -> str:
        if not profile.get("upstream_subject"):
            raise ValueError("未能确认第三方身份")
        raw = random_token(32)
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM external_binding_pending WHERE expires_at<?", (iso(utc_now()),))
            db.execute("""INSERT INTO external_binding_pending VALUES(?,?,?,?,?,?,?)""",
                (token_hash(raw), context["account_id"], context["session_hash"], context["provider"],
                 context["expected_id"], json.dumps(profile, ensure_ascii=False), iso(utc_now()+timedelta(minutes=10))))
        return raw

    def pending_external_binding(self, raw: str, account_id: int, session: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM external_binding_pending WHERE token_hash=? AND account_id=? AND session_hash=? AND expires_at>?",
                (token_hash(raw), account_id, token_hash(session), iso(utc_now()))).fetchone()
        if not row:
            return None
        profile = json.loads(row["profile"])
        return {"provider": row["provider"], "nickname": profile.get("nickname"),
                "identityHint": token_hash(profile["upstream_subject"])[:8], "replacing": row["expected_id"] is not None}

    def finish_external_binding(self, raw: str, account_id: int, session: str, *, cancel: bool = False) -> None:
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM external_binding_pending WHERE token_hash=? AND account_id=? AND session_hash=? AND expires_at>?",
                (token_hash(raw), account_id, token_hash(session), iso(utc_now()))).fetchone()
            if not row:
                raise ValueError("授权确认已过期或已使用，请重新发起")
            if cancel:
                db.execute("DELETE FROM external_binding_pending WHERE token_hash=?", (token_hash(raw),))
                return
            if not db.execute("SELECT 1 FROM web_sessions WHERE token_hash=? AND account_id=? AND expires_at>?", (token_hash(session), account_id, iso(utc_now()))).fetchone():
                raise ValueError("登录已失效")
            old = self._binding_slot(db, account_id, row["provider"])
            if (int(old["id"]) if old else None) != row["expected_id"]:
                raise ValueError("绑定状态已变化，请刷新后重试")
            profile = json.loads(row["profile"])
            conflict = db.execute("""SELECT 1 FROM external_identities WHERE account_id<>? AND
                (provider_subject=? OR (provider=? AND upstream_subject=?))""",
                (account_id, profile["subject"], row["provider"], profile["upstream_subject"])).fetchone()
            if conflict:
                raise ValueError("该第三方账号或关联的 CZL 身份已绑定其他 muxi 账号，不能合并或转移")
            if old and old["upstream_subject"] == profile["upstream_subject"]:
                raise ValueError("选择的仍是原第三方账号，请在授权页面切换账号")
            if old:
                db.execute("DELETE FROM external_identities WHERE id=?", (old["id"],))
            db.execute("""INSERT INTO external_identities
                (account_id,provider,provider_subject,upstream_subject,provider_nickname,raw_profile,created_at)
                VALUES(?,?,?,?,?,?,?)""", (account_id, row["provider"], profile["subject"], profile["upstream_subject"],
                profile.get("nickname"), json.dumps(profile.get("raw_profile", {}), ensure_ascii=False), iso(utc_now())))
            db.execute("INSERT INTO external_binding_events(account_id,provider,action,created_at) VALUES(?,?,?,?)",
                (account_id, row["provider"], "replace" if old else "bind", iso(utc_now())))
            self._invalidate_binding_sessions(db, account_id, token_hash(session))

    def unlink_external(self, account_id: int, provider: str, session: str) -> None:
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM web_sessions WHERE account_id=? AND token_hash=? AND expires_at>?", (account_id, token_hash(session), iso(utc_now()))).fetchone():
                raise ValueError("登录已失效")
            row = self._binding_slot(db, account_id, provider)
            if not row:
                raise ValueError("该渠道尚未绑定")
            alternative = db.execute("SELECT 1 FROM external_identities WHERE account_id=? AND provider IN ('qq','wechat') AND provider<>?", (account_id, provider)).fetchone()
            password_login = db.execute("""SELECT 1 FROM accounts a JOIN account_emails e ON e.account_id=a.id
                WHERE a.id=? AND a.password_hash IS NOT NULL AND e.verified=1 AND e.is_primary=1""", (account_id,)).fetchone()
            if not alternative and not password_login:
                raise ValueError("不能解绑最后一种可用登录方式；请先绑定另一渠道，或使用换绑")
            db.execute("DELETE FROM external_identities WHERE id=?", (row["id"],))
            db.execute("INSERT INTO external_binding_events(account_id,provider,action,created_at) VALUES(?,?,?,?)", (account_id, provider, "unlink", iso(utc_now())))
            self._invalidate_binding_sessions(db, account_id, token_hash(session))

    @staticmethod
    def _account_query() -> str:
        return """
            SELECT a.*, e.email AS primary_email,
                   COALESCE(e.verified,0) AS primary_email_verified,
                   v.etag AS avatar_etag
            FROM accounts a
            LEFT JOIN account_emails e
              ON e.account_id=a.id AND e.is_primary=1
            LEFT JOIN account_avatars v ON v.account_id=a.id
        """

    @staticmethod
    def _account(row: sqlite3.Row | None) -> Account | None:
        if row is None:
            return None
        return Account(
            id=int(row["id"]),
            subject=str(row["subject"]),
            uid=int(row["uid"]),
            username=str(row["username"]),
            nickname=str(row["nickname"]),
            game_name=str(row["game_name"]),
            email=str(row["primary_email"]) if row["primary_email"] is not None else None,
            role=str(row["role"]),
            email_verified=bool(row["primary_email_verified"]),
            created_at=str(row["created_at"]),
            last_login_at=row["last_login_at"],
            avatar_etag=str(row["avatar_etag"]) if _has(row, "avatar_etag") and row["avatar_etag"] else None,
        )

    @staticmethod
    def _next_uid(db: sqlite3.Connection) -> int:
        row = db.execute("SELECT next_uid FROM uid_sequence WHERE id=1").fetchone()
        uid = int(row["next_uid"])
        db.execute("UPDATE uid_sequence SET next_uid=? WHERE id=1", (uid + 1,))
        return uid

    def register(self, email: str, username: str, nickname: str, password: str) -> tuple[Account, str]:
        now = utc_now()
        raw_verify = random_token(32)
        with self._lock, self.connect() as db:
            uid = self._next_uid(db)
            try:
                cur = db.execute(
                    """INSERT INTO accounts(subject,uid,username,nickname,game_name,password_hash,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), uid, username, nickname, username, hash_password(password), iso(now)),
                )
                account_id = int(cur.lastrowid)
                db.execute(
                    """INSERT INTO account_emails(account_id,email,verified,is_primary,created_at)
                       VALUES(?,?,0,1,?)""",
                    (account_id, email.lower(), iso(now)),
                )
            except sqlite3.IntegrityError as error:
                text = str(error).lower()
                if "email" in text:
                    raise ValueError("该邮箱已经注册") from error
                raise ValueError("该用户名已经被使用") from error
            db.execute(
                "INSERT INTO email_verifications(account_id,token_hash,expires_at) VALUES(?,?,?)",
                (account_id, token_hash(raw_verify), iso(now + timedelta(hours=24))),
            )
            account = self._account(
                db.execute(self._account_query() + " WHERE a.id=?", (account_id,)).fetchone()
            )
        return account, raw_verify  # type: ignore[return-value]

    def bind_email(self, account_id: int, email: str) -> str:
        """给账号绑定邮箱，返回验证令牌。

        QQ / 微信注册出来的账号一个邮箱都没有，而找回密码、换设备登录都要靠它，
        所以必须能补绑。已经验证过的邮箱这里不给改——那是另一件事（要先证明还
        握着旧邮箱），混在一起做会变成一条接管账号的捷径。
        """
        now = utc_now()
        raw_verify = random_token(32)
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT email,verified FROM account_emails WHERE account_id=? AND is_primary=1",
                (account_id,),
            ).fetchone()
            if row is not None and bool(row["verified"]):
                raise ValueError("该账号已经绑定并验证过邮箱")
            try:
                if row is None:
                    db.execute(
                        """INSERT INTO account_emails(account_id,email,verified,is_primary,created_at)
                           VALUES(?,?,0,1,?)""",
                        (account_id, email.lower(), iso(now)),
                    )
                else:
                    # 还没验证的那个可以直接换掉：写错地址的人否则就卡死了。
                    db.execute(
                        "UPDATE account_emails SET email=?,created_at=? WHERE account_id=? AND is_primary=1",
                        (email.lower(), iso(now), account_id),
                    )
            except sqlite3.IntegrityError as error:
                raise ValueError("该邮箱已经被其它账号使用") from error
            # 一个账号同时只留一张待验证的票，重发即作废上一张。
            db.execute(
                "INSERT OR REPLACE INTO email_verifications(account_id,token_hash,expires_at) VALUES(?,?,?)",
                (account_id, token_hash(raw_verify), iso(now + timedelta(hours=24))),
            )
        return raw_verify

    def resend_verification(self, email: str) -> tuple[Account, str] | None:
        """重发验证信。

        **必须免登录**：登录本身就要求邮箱已验证，没收到信的人否则永远进不来。
        调用方不要把「查无此人」和「已经验证过」区分着告诉前端，那等于拿这个接口
        当邮箱探测器用；两种情况都回同一句话。
        """
        now = utc_now()
        raw_verify = random_token(32)
        with self._lock, self.connect() as db:
            row = db.execute(
                self._account_query() + " WHERE e.email=? COLLATE NOCASE AND e.verified=0",
                (email.lower(),),
            ).fetchone()
            account = self._account(row)
            if account is None:
                return None
            db.execute(
                "INSERT OR REPLACE INTO email_verifications(account_id,token_hash,expires_at) VALUES(?,?,?)",
                (account.id, token_hash(raw_verify), iso(now + timedelta(hours=24))),
            )
        return account, raw_verify

    def set_avatar(self, account_id: int, data: bytes, content_type: str, etag: str) -> None:
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO account_avatars(account_id,content_type,bytes,etag,updated_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(account_id) DO UPDATE SET
                     content_type=excluded.content_type, bytes=excluded.bytes,
                     etag=excluded.etag, updated_at=excluded.updated_at""",
                (account_id, content_type, data, etag, iso(utc_now())),
            )

    def avatar(self, uid: int) -> tuple[bytes, str, str] | None:
        """按 UID 取头像，返回 (内容, content-type, etag)。"""
        with self.connect() as db:
            row = db.execute(
                """SELECT v.bytes,v.content_type,v.etag FROM account_avatars v
                   JOIN accounts a ON a.id=v.account_id WHERE a.uid=?""",
                (uid,),
            ).fetchone()
        return (bytes(row["bytes"]), str(row["content_type"]), str(row["etag"])) if row else None

    def clear_avatar(self, account_id: int) -> None:
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM account_avatars WHERE account_id=?", (account_id,))

    def delete_account(self, account_id: int) -> bool:
        """注销账号。外键级联会带走邮箱、会话、令牌、头像。

        UID 不回收：uid_sequence 只增不减。游戏存档是按 UID 推出来的 UUID 存的，
        回收 UID 等于把新人扔进别人的身体里。
        """
        with self._lock, self.connect() as db:
            cur = db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
            return cur.rowcount > 0

    def verify_email(self, raw_token: str) -> Account | None:
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT account_id,expires_at FROM email_verifications WHERE token_hash=?",
                (token_hash(raw_token),),
            ).fetchone()
            if row is None or datetime.fromisoformat(row["expires_at"]) < utc_now():
                return None
            account_id = int(row["account_id"])
            db.execute(
                "UPDATE account_emails SET verified=1 WHERE account_id=? AND is_primary=1",
                (account_id,),
            )
            db.execute("DELETE FROM email_verifications WHERE account_id=?", (account_id,))
            return self._account(
                db.execute(self._account_query() + " WHERE a.id=?", (account_id,)).fetchone()
            )

    def authenticate(self, identity: str, password: str) -> Account | None:
        with self._lock, self.connect() as db:
            row = db.execute(
                self._account_query()
                + """ WHERE a.username=? COLLATE NOCASE
                       OR CAST(a.uid AS TEXT)=?
                       OR e.email=? COLLATE NOCASE""",
                (identity, identity, identity),
            ).fetchone()
            if row is None or row["password_hash"] is None or not verify_password(str(row["password_hash"]), password):
                return None
            account = self._account(row)
            if account is None or not account.email_verified:
                raise PermissionError("请先完成邮箱验证")
            if needs_rehash(str(row["password_hash"])):
                db.execute("UPDATE accounts SET password_hash=? WHERE id=?", (hash_password(password), account.id))
            now = iso(utc_now())
            db.execute("UPDATE accounts SET last_login_at=? WHERE id=?", (now, account.id))
            return self._account(
                db.execute(self._account_query() + " WHERE a.id=?", (account.id,)).fetchone()
            )

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
                self._account_query()
                + """ JOIN web_sessions s ON s.account_id=a.id
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
            account = self._account(
                db.execute(self._account_query() + " WHERE a.id=?", (int(row["account_id"]),)).fetchone()
            )
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
                """SELECT a.*, e.email AS primary_email,
                          COALESCE(e.verified,0) AS primary_email_verified,
                          t.client_id AS token_client_id, t.scope AS token_scope
                   FROM access_tokens t
                   JOIN accounts a ON a.id=t.account_id
                   LEFT JOIN account_emails e ON e.account_id=a.id AND e.is_primary=1
                   WHERE t.token_hash=? AND t.revoked_at IS NULL AND t.expires_at>?""",
                (token_hash(raw), iso(utc_now())),
            ).fetchone()
            account = self._account(row)
            if row is None or account is None:
                return None
            return account, str(row["token_client_id"]), str(row["token_scope"])

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
                """SELECT a.*, e.email AS primary_email,
                          COALESCE(e.verified,0) AS primary_email_verified,
                          r.scope AS token_scope, r.expires_at AS token_expires_at
                   FROM refresh_tokens r
                   JOIN accounts a ON a.id=r.account_id
                   LEFT JOIN account_emails e ON e.account_id=a.id AND e.is_primary=1
                   WHERE r.token_hash=? AND r.client_id=? AND r.revoked_at IS NULL""",
                (token_hash(raw), client_id),
            ).fetchone()
            if row is None or datetime.fromisoformat(row["token_expires_at"]) < now:
                return None
            db.execute("UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?", (iso(now), token_hash(raw)))
            account = self._account(row)
            return (account, str(row["token_scope"])) if account else None

    def revoke(self, raw: str) -> None:
        hashed = token_hash(raw)
        now = iso(utc_now())
        with self._lock, self.connect() as db:
            db.execute("UPDATE access_tokens SET revoked_at=? WHERE token_hash=?", (now, hashed))
            db.execute("UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?", (now, hashed))

    def list_accounts(self, limit: int = 200) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                self._account_query() + " ORDER BY a.id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [account.public() for row in rows if (account := self._account(row)) is not None]

    def promote_admin(self, identity: str) -> Account | None:
        with self._lock, self.connect() as db:
            row = db.execute(
                self._account_query()
                + """ WHERE a.username=? COLLATE NOCASE
                       OR CAST(a.uid AS TEXT)=?
                       OR e.email=? COLLATE NOCASE""",
                (identity, identity, identity),
            ).fetchone()
            if row is None:
                return None
            db.execute("UPDATE accounts SET role='admin' WHERE id=?", (int(row["id"]),))
            return self._account(
                db.execute(self._account_query() + " WHERE a.id=?", (int(row["id"]),)).fetchone()
            )

    def update_profile(self, account_id: int, username: str, nickname: str) -> Account:
        with self._lock, self.connect() as db:
            try:
                db.execute(
                    "UPDATE accounts SET username=?,nickname=? WHERE id=?",
                    (username, nickname, account_id),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("该用户名已经被使用") from error
            account = self._account(
                db.execute(self._account_query() + " WHERE a.id=?", (account_id,)).fetchone()
            )
            if account is None:
                raise ValueError("账号不存在")
            return account

    def create_external_state(self, provider: str, continue_to: str, *, account_id: int | None = None, session: str = "", expected_id: int | None = None) -> tuple[str, str]:
        raw = random_token(32)
        verifier = random_token(48)
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM external_oauth_states WHERE expires_at<?", (iso(now),))
            db.execute(
                """INSERT INTO external_oauth_states
                   (state_hash,provider,code_verifier,continue_to,created_at,expires_at)
                   VALUES(?,?,?,?,?,?)""",
                (
                    token_hash(raw), provider, verifier, continue_to,
                    iso(now), iso(now + timedelta(minutes=10)),
                ),
            )
            if account_id is not None:
                db.execute("UPDATE external_oauth_states SET purpose='binding',account_id=?,session_hash=?,expected_id=? WHERE state_hash=?",
                    (account_id, token_hash(session), expected_id, token_hash(raw)))
        return raw, verifier

    def consume_external_state(self, raw: str) -> tuple[str, str, str] | None:
        row = self.consume_external_state_context(raw)
        return (row["provider"], row["code_verifier"], row["continue_to"]) if row else None

    def consume_external_state_context(self, raw: str) -> dict | None:
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT *
                   FROM external_oauth_states WHERE state_hash=?""",
                (token_hash(raw),),
            ).fetchone()
            db.execute("DELETE FROM external_oauth_states WHERE state_hash=?", (token_hash(raw),))
        if row is None or datetime.fromisoformat(str(row["expires_at"])) < now:
            return None
        return dict(row)

    def external_account(
        self,
        provider: str,
        provider_subject: str,
        raw_profile: dict | None = None,
        upstream_subject: str | None = None,
    ) -> Account | None:
        identity_provider = provider
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if raw_profile:
                db.execute("UPDATE external_identities SET raw_profile=? WHERE provider='czl' AND provider_subject=?", (json.dumps(raw_profile, ensure_ascii=False), provider_subject))
                self._migrate_external_channels(db)
            row = db.execute(
                self._account_query()
                + """ JOIN external_identities x ON x.account_id=a.id
                       WHERE x.provider=? AND x.provider_subject=? AND (x.upstream_subject IS NULL OR x.upstream_subject=?)""",
                (identity_provider, provider_subject, upstream_subject),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                """UPDATE external_identities
                   SET last_login_at=?, upstream_subject=COALESCE(?,upstream_subject),
                       raw_profile=COALESCE(?,raw_profile)
                   WHERE provider=? AND provider_subject=?""",
                (
                    iso(utc_now()), upstream_subject,
                    json.dumps(raw_profile, ensure_ascii=False) if raw_profile is not None else None,
                    identity_provider, provider_subject,
                ),
            )
            db.execute("UPDATE accounts SET last_login_at=? WHERE id=?", (iso(utc_now()), int(row["id"])))
            return self._account(row)

    def create_external_signup(
        self,
        provider: str,
        provider_subject: str,
        provider_nickname: str | None,
        continue_to: str,
        raw_profile: dict | None = None,
        upstream_subject: str | None = None,
    ) -> str:
        raw = random_token(32)
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM external_signups WHERE expires_at<?", (iso(now),))
            db.execute(
                "DELETE FROM external_signups WHERE provider=? AND provider_subject=?",
                (provider, provider_subject),
            )
            db.execute(
                """INSERT INTO external_signups
                   (token_hash,provider,provider_subject,provider_nickname,upstream_subject,raw_profile,
                    continue_to,created_at,expires_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    token_hash(raw), provider, provider_subject, provider_nickname, upstream_subject,
                    json.dumps(raw_profile, ensure_ascii=False) if raw_profile is not None else None,
                    continue_to,
                    iso(now), iso(now + timedelta(minutes=20)),
                ),
            )
        return raw

    def external_signup(self, raw: str) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM external_signups WHERE token_hash=? AND expires_at>?",
                (token_hash(raw), iso(utc_now())),
            ).fetchone()
        return dict(row) if row is not None else None

    def complete_external_signup(self, raw: str, username: str, nickname: str) -> tuple[Account, str]:
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            signup = db.execute(
                "SELECT * FROM external_signups WHERE token_hash=? AND expires_at>?",
                (token_hash(raw), iso(now)),
            ).fetchone()
            if signup is None:
                raise ValueError("第三方注册会话无效或已过期")

            signup = dict(signup)
            try:
                normalized = verified_upstream_subject(json.loads(signup["raw_profile"] or "{}"), signup["provider"])
                if normalized:
                    signup["upstream_subject"] = normalized
            except (ValueError, TypeError):
                pass

            identity_provider = str(signup["provider"])
            existing = db.execute(
                "SELECT account_id,upstream_subject FROM external_identities WHERE provider=? AND provider_subject=?",
                (identity_provider, signup["provider_subject"]),
            ).fetchone()
            if existing is not None:
                if existing["upstream_subject"] != signup["upstream_subject"]:
                    raise ValueError("第三方身份已变化，请登录原账号后换绑")
                db.execute("DELETE FROM external_signups WHERE token_hash=?", (token_hash(raw),))
                account = self._account(
                    db.execute(self._account_query() + " WHERE a.id=?", (int(existing["account_id"]),)).fetchone()
                )
                if account is None:
                    raise ValueError("第三方账号绑定异常")
                return account, str(signup["continue_to"])

            if db.execute("SELECT 1 FROM external_identities WHERE provider_subject=? OR (provider=? AND upstream_subject=?)",
                          (signup["provider_subject"], identity_provider, signup["upstream_subject"])).fetchone():
                raise ValueError("该 CZL 身份已关联账号，请登录原账号后手动绑定此渠道")

            uid = self._next_uid(db)
            try:
                cur = db.execute(
                    """INSERT INTO accounts(subject,uid,username,nickname,game_name,password_hash,created_at)
                       VALUES(?,?,?,?,?,NULL,?)""",
                    (str(uuid.uuid4()), uid, username, nickname, username, iso(now)),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("该用户名已经被使用") from error
            account_id = int(cur.lastrowid)
            db.execute(
                """INSERT INTO external_identities
                   (account_id,provider,provider_subject,provider_nickname,upstream_subject,raw_profile,
                    created_at,last_login_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    account_id, identity_provider, signup["provider_subject"], signup["provider_nickname"],
                    signup["upstream_subject"], signup["raw_profile"], iso(now), iso(now),
                ),
            )
            db.execute("DELETE FROM external_signups WHERE token_hash=?", (token_hash(raw),))
            account = self._account(
                db.execute(self._account_query() + " WHERE a.id=?", (account_id,)).fetchone()
            )
            if account is None:
                raise ValueError("账号创建失败")
            return account, str(signup["continue_to"])

    def create_launcher_auth_flow(self, minutes: int = 20) -> tuple[str, str]:
        flow = random_token(24)
        secret = random_token(32)
        now = utc_now()
        with self._lock, self.connect() as db:
            db.execute("DELETE FROM launcher_auth_flows WHERE expires_at<?", (iso(now),))
            db.execute(
                """INSERT INTO launcher_auth_flows
                   (flow_hash,secret_hash,status,cancel_after,created_at,expires_at)
                   VALUES(?,?, 'pending', NULL, ?, ?)""",
                (
                    token_hash(flow), token_hash(secret), iso(now),
                    iso(now + timedelta(minutes=minutes)),
                ),
            )
        return flow, secret

    def launcher_auth_flow_resume(self, flow: str, secret: str) -> bool:
        now = utc_now()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE launcher_auth_flows
                   SET cancel_after=NULL
                   WHERE flow_hash=? AND secret_hash=? AND status='pending' AND expires_at>?""",
                (token_hash(flow), token_hash(secret), iso(now)),
            )
            return cursor.rowcount > 0

    def launcher_auth_flow_cancel(self, flow: str, secret: str, grace_seconds: int = 2) -> bool:
        now = utc_now()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE launcher_auth_flows
                   SET cancel_after=?
                   WHERE flow_hash=? AND secret_hash=? AND status='pending' AND expires_at>?""",
                (
                    iso(now + timedelta(seconds=grace_seconds)),
                    token_hash(flow), token_hash(secret), iso(now),
                ),
            )
            return cursor.rowcount > 0

    def launcher_auth_flow_status(self, flow: str, secret: str) -> str | None:
        now = utc_now()
        with self._lock, self.connect() as db:
            row = db.execute(
                """SELECT status,cancel_after,expires_at FROM launcher_auth_flows
                   WHERE flow_hash=? AND secret_hash=?""",
                (token_hash(flow), token_hash(secret)),
            ).fetchone()
            if row is None:
                return None
            if datetime.fromisoformat(str(row["expires_at"])) <= now:
                db.execute(
                    "DELETE FROM launcher_auth_flows WHERE flow_hash=?",
                    (token_hash(flow),),
                )
                return "expired"
            status = str(row["status"])
            cancel_after = row["cancel_after"]
            if status == "pending" and cancel_after:
                if datetime.fromisoformat(str(cancel_after)) <= now:
                    db.execute(
                        "UPDATE launcher_auth_flows SET status='cancelled' WHERE flow_hash=?",
                        (token_hash(flow),),
                    )
                    return "cancelled"
            return status

    def account_by_uid(self, uid: int) -> Account | None:
        with self.connect() as db:
            return self._account(db.execute(self._account_query() + " WHERE a.uid=?", (uid,)).fetchone())

    def complete_launcher_auth_flow(self, flow: str, secret: str) -> None:
        with self._lock, self.connect() as db:
            db.execute(
                "DELETE FROM launcher_auth_flows WHERE flow_hash=? AND secret_hash=?",
                (token_hash(flow), token_hash(secret)),
            )


