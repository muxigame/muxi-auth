from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .terminal_access import SECONDS
from .terminal_server_auth import terminal_player


class Correlation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    requestId: str = Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    gameSession: str = Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


class ServerCorrelation(Correlation):
    uid: int = Field(ge=10000, le=9999999999999999)


class ServerSession(BaseModel):
    model_config = ConfigDict(extra='forbid')
    uid: int = Field(ge=10000, le=9999999999999999)
    gameSession: str = Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def terminal_access_router(settings_getter, store_getter, bindings_getter):
    router = APIRouter()

    def enabled():
        settings = settings_getter()
        if not settings.terminal_sso_enabled:
            raise HTTPException(404, 'Terminal account connection unavailable')
        return settings

    def server_account(payload, request):
        settings = enabled()
        account = terminal_player(settings, store_getter(), payload.uid, request.headers.get('x-muxi-server-key', ''))
        return settings, account

    def response(payload, account, **extra):
        return JSONResponse({'uid': account.uid, 'gameSession': payload.gameSession,
            **({'requestId': payload.requestId} if hasattr(payload, 'requestId') else {}), **extra},
            headers={'Cache-Control': 'no-store'})

    @router.post('/api/internal/minecraft/terminal-context/create', include_in_schema=False)
    def create(payload: ServerCorrelation, request: Request):
        settings, account = server_account(payload, request)
        try:
            bindings_getter().create(account.id, payload.requestId, payload.gameSession, settings.terminal_sso_server_key)
        except ValueError:
            raise HTTPException(401, 'Live account connection unavailable') from None
        return response(payload, account, expiresInSeconds=SECONDS)

    @router.post('/api/launcher/minecraft/terminal-context/bind', include_in_schema=False)
    def bind(payload: Correlation, request: Request):
        settings = enabled()
        value = request.headers.get('authorization', '')
        scheme, _, access = value.partition(' ')
        result = store_getter().access_token(access if scheme.lower() == 'bearer' else '')
        if result is None or result[1] != settings.bmc_launcher_client_id:
            raise HTTPException(401, 'Existing launcher account authorization required')
        try:
            bindings_getter().bind(result[0].id, access, settings.bmc_launcher_client_id, payload.requestId, payload.gameSession)
        except ValueError:
            raise HTTPException(401, 'Account does not match the live game connection') from None
        return response(payload, result[0])

    @router.post('/api/internal/minecraft/terminal-context/claim', include_in_schema=False)
    def claim(payload: ServerCorrelation, request: Request):
        settings, account = server_account(payload, request)
        try:
            bindings_getter().claim(account.id, payload.requestId, payload.gameSession, settings.terminal_sso_server_key)
        except ValueError:
            raise HTTPException(401, 'Account connection authorization expired') from None
        return response(payload, account)

    @router.post('/api/internal/minecraft/terminal-context/status', include_in_schema=False)
    def status(payload: ServerSession, request: Request):
        settings, account = server_account(payload, request)
        return response(payload, account, authenticated=bindings_getter().active(account.id, payload.gameSession, settings.terminal_sso_server_key))

    @router.post('/api/internal/minecraft/terminal-context/disconnect', include_in_schema=False)
    def disconnect(payload: ServerSession, request: Request):
        settings, account = server_account(payload, request)
        bindings_getter().disconnect(payload.gameSession, settings.terminal_sso_server_key)
        return response(payload, account, authenticated=False)

    @router.post('/api/internal/minecraft/terminal-context/revoke', include_in_schema=False)
    def revoke(payload: ServerSession, request: Request):
        settings, account = server_account(payload, request)
        bindings_getter().revoke(payload.gameSession, settings.terminal_sso_server_key)
        return response(payload, account, authenticated=False)

    return router
