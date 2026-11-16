"""Auth-only QA composition. No main/config import, environment, socket or signer.

The caller owns a new private evidence directory. Credentials remain in memory;
only the real Store's normal hashed records are persisted to its new database.
"""
from dataclasses import dataclass, field
from pathlib import Path
import re
import secrets

from fastapi import FastAPI
from app.store import Store
from app.terminal_access import TerminalAccessStore
from app.terminal_access_api import terminal_access_router


@dataclass(frozen=True)
class TestSettings:
    terminal_sso_enabled: bool = True
    terminal_sso_server_key: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    minecraft_profile_key: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    bmc_launcher_client_id: str = 'terminal-access-isolated-qa'


@dataclass(repr=False)
class Fixture:
    app: FastAPI
    store: Store
    bindings: TerminalAccessStore
    settings: TestSettings
    accounts: tuple
    access: tuple
    wrong_client_access: str


def build(directory: Path, private_case: Path) -> Fixture:
    directory, private_case = directory.absolute(), private_case.resolve(strict=True)
    if directory != directory.resolve() or private_case not in directory.parents or directory.exists():
        raise ValueError('Use a new real fixture directory inside the explicit private case')
    directory.mkdir()
    database = directory / 'fixture-auth.db'
    store = Store(database)
    settings = TestSettings()
    if settings.terminal_sso_server_key == settings.minecraft_profile_key:
        raise RuntimeError('Fixture authority collision')
    for client in (settings.bmc_launcher_client_id, 'terminal-access-wrong-client'):
        store.seed_client(client, 'Isolated QA', 'public', ['http://127.0.0.1/callback'], ['openid', 'profile'])
    accounts, access = [], []
    for name in ('Fixture_A', 'Fixture_B'):
        _, verification = store.register(name.lower() + '@example.com', name, name, secrets.token_urlsafe(24))
        account = store.verify_email(verification)
        if account is None:
            raise RuntimeError('Fixture account initialization failed')
        token = store.issue_access_token(account.id, settings.bmc_launcher_client_id, 'openid profile', 3600)
        if re.fullmatch(r'[A-Za-z0-9_-]{54}', token) is None:
            raise RuntimeError('Actual Store token contract changed')
        accounts.append(account)
        access.append(token)
    other = store.issue_access_token(accounts[0].id, 'terminal-access-wrong-client', 'openid profile', 3600)
    bindings = TerminalAccessStore(store)
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.include_router(terminal_access_router(lambda: settings, lambda: store, lambda: bindings))
    return Fixture(app, store, bindings, settings, tuple(accounts), tuple(access), other)
