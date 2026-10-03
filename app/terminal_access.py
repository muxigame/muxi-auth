"""Bind one existing launcher access token to one live game connection.

Request/session UUIDs are public correlation data, not authentication tokens.
No bootstrap, proof, ticket, access token, or refresh token is issued here.
"""
from datetime import timedelta
import re

from .security import token_hash, utc_now
from .store import iso

UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
SECONDS = 30


class TerminalAccessStore:
    def __init__(self, store):
        self.store = store
        with store._lock, store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS terminal_access_requests (
                    request_id TEXT PRIMARY KEY, server_hash TEXT NOT NULL,
                    game_session TEXT NOT NULL, account_id INTEGER NOT NULL,
                    source_hash TEXT, expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminal_access_connections (
                    server_hash TEXT NOT NULL, game_session TEXT NOT NULL,
                    account_id INTEGER NOT NULL, source_hash TEXT NOT NULL,
                    PRIMARY KEY(server_hash, game_session)
                );
                CREATE TABLE IF NOT EXISTS terminal_access_disconnects (
                    server_hash TEXT NOT NULL, game_session TEXT NOT NULL,
                    expires_at TEXT NOT NULL, PRIMARY KEY(server_hash, game_session)
                );
            ''')

    @staticmethod
    def _ids(request_id, session):
        if not UUID.fullmatch(request_id) or not UUID.fullmatch(session):
            raise ValueError('Invalid connection correlation')

    @staticmethod
    def _sweep(db, now):
        db.execute('DELETE FROM terminal_access_requests WHERE expires_at<=?', (now,))
        db.execute('DELETE FROM terminal_access_disconnects WHERE expires_at<=?', (now,))
        db.execute('''DELETE FROM terminal_access_connections WHERE source_hash NOT IN
            (SELECT token_hash FROM access_tokens WHERE expires_at>? AND revoked_at IS NULL)''', (now,))

    def create(self, account_id, request_id, session, service_key):
        self._ids(request_id, session)
        now = utc_now()
        authority = token_hash(service_key)
        with self.store._lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self._sweep(db, iso(now))
            if db.execute('SELECT 1 FROM terminal_access_disconnects WHERE server_hash=? AND game_session=?',
                          (authority, session)).fetchone():
                raise ValueError('Connection has ended')
            if db.execute('SELECT 1 FROM terminal_access_requests WHERE request_id=?', (request_id,)).fetchone():
                raise ValueError('Connection request already exists')
            db.execute('INSERT INTO terminal_access_requests VALUES(?,?,?,?,NULL,?)',
                       (request_id, authority, session, account_id, iso(now+timedelta(seconds=SECONDS))))

    def bind(self, account_id, access_token, client_id, request_id, session):
        self._ids(request_id, session)
        now = iso(utc_now())
        source = token_hash(access_token)
        with self.store._lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self._sweep(db, now)
            token = db.execute('''SELECT 1 FROM access_tokens WHERE token_hash=? AND account_id=?
                AND client_id=? AND expires_at>? AND revoked_at IS NULL''',
                (source, account_id, client_id, now)).fetchone()
            request = db.execute('''SELECT * FROM terminal_access_requests
                WHERE request_id=? AND game_session=? AND account_id=? AND expires_at>? AND source_hash IS NULL''',
                (request_id, session, account_id, now)).fetchone()
            if token is None or request is None:
                raise ValueError('Existing account authorization does not match the live connection')
            db.execute('UPDATE terminal_access_requests SET source_hash=? WHERE request_id=?', (source, request_id))

    def claim(self, account_id, request_id, session, service_key):
        self._ids(request_id, session)
        authority = token_hash(service_key)
        now = iso(utc_now())
        with self.store._lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self._sweep(db, now)
            row = db.execute('''SELECT r.source_hash FROM terminal_access_requests r
                JOIN access_tokens t ON t.token_hash=r.source_hash AND t.account_id=r.account_id
                WHERE r.request_id=? AND r.game_session=? AND r.server_hash=? AND r.account_id=?
                  AND r.expires_at>? AND t.expires_at>? AND t.revoked_at IS NULL''',
                (request_id, session, authority, account_id, now, now)).fetchone()
            if row is None:
                raise ValueError('Account connection authorization expired')
            db.execute('DELETE FROM terminal_access_requests WHERE request_id=?', (request_id,))
            db.execute('''INSERT INTO terminal_access_connections VALUES(?,?,?,?)
                ON CONFLICT(server_hash,game_session) DO UPDATE SET account_id=excluded.account_id,source_hash=excluded.source_hash''',
                (authority, session, account_id, row['source_hash']))

    def active(self, account_id, session, service_key):
        if not UUID.fullmatch(session):
            return False
        with self.store.connect() as db:
            return db.execute('''SELECT 1 FROM terminal_access_connections c
                JOIN access_tokens t ON t.token_hash=c.source_hash AND t.account_id=c.account_id
                WHERE c.server_hash=? AND c.game_session=? AND c.account_id=?
                  AND t.expires_at>? AND t.revoked_at IS NULL''',
                (token_hash(service_key), session, account_id, iso(utc_now()))).fetchone() is not None

    def disconnect(self, session, service_key):
        if not UUID.fullmatch(session):
            raise ValueError('Invalid connection correlation')
        authority = token_hash(service_key)
        with self.store._lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self._sweep(db, iso(utc_now()))
            db.execute('DELETE FROM terminal_access_requests WHERE server_hash=? AND game_session=?', (authority, session))
            db.execute('DELETE FROM terminal_access_connections WHERE server_hash=? AND game_session=?', (authority, session))
            db.execute('''INSERT INTO terminal_access_disconnects VALUES(?,?,?)
                ON CONFLICT(server_hash,game_session) DO UPDATE SET expires_at=excluded.expires_at''',
                (authority, session, iso(utc_now()+timedelta(hours=12))))

    def revoke(self, session, service_key):
        """End only native social authorization; a live connection may authenticate again."""
        if not UUID.fullmatch(session):
            raise ValueError('Invalid connection correlation')
        authority = token_hash(service_key)
        with self.store._lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM terminal_access_requests WHERE server_hash=? AND game_session=?', (authority, session))
            db.execute('DELETE FROM terminal_access_connections WHERE server_hash=? AND game_session=?', (authority, session))
