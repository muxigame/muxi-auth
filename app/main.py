from __future__ import annotations

import base64
import hmac
import os
from urllib.request import Request as ServiceRequest, urlopen
from urllib.parse import urlsplit as service_urlsplit
import json
import re
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from html import escape
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from .config import ROOT, settings
from .minecraft_identity import game_identity
from . import avatar as avatar_rules
from . import minecraft_join as join_grants
from .external_oauth import ExternalOAuthError, authorize_url as external_authorize_url, exchange_profile, provider_status
from .security import OidcSigner, utc_now, token_hash
from .store import Account, OAuthClient, Store
from .terminal_sso import TerminalSsoStore, BOOTSTRAP_SECONDS, TICKET_SECONDS, TARGET
from .terminal_server_auth import terminal_player
from .terminal_access import TerminalAccessStore
from .terminal_access_api import terminal_access_router


WEB_ROOT = ROOT / "web"
store = Store(settings.database_path)
terminal_sso = TerminalSsoStore(store)
terminal_access = TerminalAccessStore(store)
signer = OidcSigner(settings.signing_key_path)

store.seed_client(
    settings.bmc_launcher_client_id,
    "Better MC Launcher",
    "public",
    [settings.bmc_launcher_redirect_uri],
    ["openid", "profile", "email"],
)
store.seed_client(
    settings.bmc_web_client_id,
    "Better MC Website",
    "confidential",
    [settings.bmc_web_redirect_uri],
    ["openid", "profile", "email"],
    settings.bmc_web_client_secret or None,
)

app = FastAPI(
    title="muxi 账户",
    version="1.0.0",
    docs_url="/api/docs" if settings.enable_docs else None,
    redoc_url=None,
)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.include_router(terminal_access_router(lambda: settings, lambda: store, lambda: terminal_access))


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True, "service": "muxi-auth"}


def minecraft_player(uid: int, request: Request) -> Account:
    """Shared gate for the two game-server endpoints: server key, then the player."""
    key = settings.minecraft_profile_key
    supplied = request.headers.get("x-muxi-server-key", "")
    if len(key) < 32:
        raise HTTPException(status_code=503, detail="Game identity service is not configured")
    if not supplied or not hmac.compare_digest(supplied.encode(), key.encode()):
        raise HTTPException(status_code=401, detail="Invalid game server credential")
    if not 10000 <= uid <= 9999999999999999:
        raise HTTPException(status_code=404, detail="Player not found")
    account = store.account_by_uid(uid)
    if account is None:
        raise HTTPException(status_code=404, detail="Player not found")
    return account


@app.get("/api/internal/minecraft/identity/{uid}", include_in_schema=False)
def minecraft_identity(uid: int, request: Request) -> JSONResponse:
    account = minecraft_player(uid, request)
    # Deliberately exclude email, username, subject, roles and OAuth credentials.
    return JSONResponse(game_identity(account.uid, account.nickname), headers={"Cache-Control": "no-store"})


def check_game_admission(uid: int):
    # This gate applies only to game entry, never website login or nickname sync.
    if os.getenv("MUXI_GAME_ADMISSION_ENABLED") != "1":
        return
    base = os.getenv("MUXI_GAME_PLATFORM_URL", "").rstrip("/")
    key = os.getenv("MUXI_GAME_PLATFORM_KEY", "")
    parsed = service_urlsplit(base)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if len(key) < 32 or parsed.username or parsed.query or parsed.fragment or not (
            parsed.scheme == "https" or local and parsed.scheme == "http"):
        raise HTTPException(503, "Game admission service is not configured")
    try:
        req = ServiceRequest(base + "/api/internal/game/admission/" + str(uid),
                             headers={"x-muxi-server-key": key})
        # Do not forward credentials through redirects.
        from urllib.request import HTTPRedirectHandler, build_opener
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        with build_opener(NoRedirect).open(req, timeout=5) as response:
            result = json.loads(response.read(4096))
        if result.get("uid") != uid or type(result.get("allowed")) is not bool:
            raise ValueError("Invalid admission response")
    except Exception:
        raise HTTPException(503, "Game admission service unavailable")
    if not result["allowed"]:
        raise HTTPException(403, "This UID is banned from game entry")


@app.post("/api/internal/minecraft/join/{uid}", include_in_schema=False)
def minecraft_join_consume(uid: int, request: Request) -> JSONResponse:
    """游戏服务端在放人进世界之前核销票据。没票就是冒名，409。

    和上面那个 identity 端点分开，是因为昵称同步每 60 秒就会跑一轮；两者合并的话
    刷新会把在线玩家的票吃掉，玩家下次重连就进不来了。
    """
    account = minecraft_player(uid, request)
    check_game_admission(uid)
    if not join_grants.consume(uid):
        raise HTTPException(status_code=409, detail="No pending join grant for this UID")
    return JSONResponse(game_identity(account.uid, account.nickname), headers={"Cache-Control": "no-store"})


@app.post("/api/launcher/minecraft/join", include_in_schema=False)
def minecraft_join_mint(request: Request) -> JSONResponse:
    """启动器在玩家发起进服连接的那一刻换票。凭据是本人的 access token。"""
    result = store.access_token(bearer(request))
    if result is None:
        raise HTTPException(status_code=401, detail="登录状态已过期，请重新登录")
    account, _client_id, _scope = result
    seconds = join_grants.mint(account.uid)
    return JSONResponse(
        {"ok": True, "uid": account.uid, "loginName": str(account.uid), "expiresInSeconds": seconds},
        headers={"Cache-Control": "no-store"},
    )


def terminal_enabled() -> None:
    if not settings.terminal_sso_enabled:
        raise HTTPException(status_code=404, detail="Terminal login is unavailable")
    if not settings.terminal_legacy_enabled:
        raise HTTPException(status_code=410, detail="Use the existing account access token")


class TerminalProofRequest(BaseModel):
    challenge: str = Field(min_length=43, max_length=43)
    requestId: str = Field(min_length=36, max_length=36)


class TerminalTicketRequest(BaseModel):
    proof: str = Field(min_length=43, max_length=43)
    uid: int
    requestId: str = Field(min_length=36, max_length=36)
    gameSession: str = Field(min_length=36, max_length=36)


class TerminalExchangeRequest(BaseModel):
    ticket: str = Field(min_length=43, max_length=43)
    verifier: str = Field(min_length=43, max_length=43)
    requestId: str = Field(min_length=36, max_length=36)
    target: str = Field(min_length=1, max_length=256)


class TerminalDisconnectRequest(BaseModel):
    uid: int
    gameSession: str = Field(min_length=36, max_length=36)


@app.post("/api/launcher/minecraft/terminal-bootstrap", include_in_schema=False)
def terminal_bootstrap(request: Request) -> JSONResponse:
    terminal_enabled()
    token = bearer(request)
    result = store.access_token(token)
    if result is None or result[1] != settings.bmc_launcher_client_id:
        raise HTTPException(status_code=401, detail="Launcher authentication required")
    try:
        raw = terminal_sso.bootstrap(result[0].id, token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Launcher authentication expired") from None
    return JSONResponse({"credential": raw, "uid": result[0].uid, "expiresInSeconds": BOOTSTRAP_SECONDS},
                        headers={"Cache-Control": "no-store"})


@app.post("/api/launcher/minecraft/terminal-proof", include_in_schema=False)
def terminal_proof(payload: TerminalProofRequest, request: Request) -> JSONResponse:
    terminal_enabled()
    auth = request.headers.get("authorization", "")
    if not auth.startswith("MuxiTerminal "):
        raise HTTPException(status_code=401, detail="Terminal credential required")
    try:
        proof = terminal_sso.proof(auth[len("MuxiTerminal "):], payload.challenge, payload.requestId)
    except ValueError:
        raise HTTPException(status_code=401, detail="Terminal authentication expired") from None
    return JSONResponse({"proof": proof}, headers={"Cache-Control": "no-store"})


@app.post("/api/internal/minecraft/terminal-ticket", include_in_schema=False)
def terminal_ticket(payload: TerminalTicketRequest, request: Request) -> JSONResponse:
    terminal_enabled()
    # The caller is a game server; the native account proof must independently match its player.
    account = terminal_player(settings, store, payload.uid, request.headers.get("x-muxi-server-key", ""))
    try:
        ticket = terminal_sso.ticket(payload.proof, payload.uid, payload.requestId,
                                     payload.gameSession, settings.terminal_sso_server_key)
    except ValueError:
        raise HTTPException(status_code=401, detail="Terminal authentication failed") from None
    return JSONResponse({"ticket": ticket, "expiresInSeconds": TICKET_SECONDS,
                         "uid": account.uid, "requestId": payload.requestId, "gameSession": payload.gameSession},
                        headers={"Cache-Control": "no-store"})


@app.post("/api/internal/minecraft/terminal-disconnect", include_in_schema=False)
def terminal_disconnect(payload: TerminalDisconnectRequest, request: Request) -> JSONResponse:
    terminal_enabled()
    terminal_player(settings, store, payload.uid, request.headers.get("x-muxi-server-key", ""))
    try:
        terminal_sso.disconnect(payload.gameSession, settings.terminal_sso_server_key)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid terminal session") from None
    return JSONResponse({"ok": True}, headers={"Cache-Control": "no-store"})


@app.post("/api/launcher/minecraft/terminal-bootstrap/revoke", include_in_schema=False)
def terminal_bootstrap_revoke(request: Request) -> JSONResponse:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("MuxiTerminal "):
        raise HTTPException(status_code=401, detail="Terminal credential required")
    try:
        terminal_sso.revoke_bootstrap(auth[len("MuxiTerminal "):])
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid terminal credential") from None
    return JSONResponse({"ok": True}, headers={"Cache-Control": "no-store"})


@app.post("/api/internal/terminal/exchange", include_in_schema=False)
def terminal_exchange(payload: TerminalExchangeRequest, request: Request) -> JSONResponse:
    terminal_enabled()
    client = confidential_client_from_basic(request)
    if client is None or client.client_id != settings.bmc_web_client_id:
        raise HTTPException(status_code=401, detail="Platform client authentication required")
    if payload.target != TARGET or request.headers.get("origin"):
        raise HTTPException(status_code=403, detail="Invalid terminal audience")
    try:
        account = terminal_sso.exchange(payload.ticket, payload.verifier, payload.requestId)
    except ValueError:
        raise HTTPException(status_code=401, detail="Terminal login expired; use normal login") from None
    # Claims come from the platform account, never from a game UID, OP flag or packet role.
    return JSONResponse({"user": account.claims(), "target": TARGET, "audience": client.client_id},
                        headers={"Cache-Control": "no-store"})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    if settings.secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith(("/oauth", "/api/account", "/api/launcher", "/api/internal/minecraft/terminal", "/api/internal/terminal", "/login", "/register", "/account")):
        response.headers["Cache-Control"] = "no-store"
    return response


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=16)
    nickname: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    identity: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ProfileRequest(BaseModel):
    username: str = Field(min_length=3, max_length=16)
    nickname: str = Field(min_length=1, max_length=64)


class BindEmailRequest(BaseModel):
    email: EmailStr


class ResendRequest(BaseModel):
    email: EmailStr


class DeleteAccountRequest(BaseModel):
    # 让人把用户名原样打一遍。注销不可撤销，一个「确定吗」的弹窗挡不住手滑。
    username: str = Field(min_length=1, max_length=64)


class ExternalCompleteRequest(BaseModel):
    ticket: str = Field(min_length=16, max_length=256)
    username: str = Field(min_length=3, max_length=16)
    nickname: str = Field(min_length=1, max_length=64)


class BindingRequest(BaseModel):
    action: str = "bind"
    password: str = Field(default="", max_length=128)


def binding_account(request: Request, *, mutation: bool = False) -> Account:
    account = current_web_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="请先登录当前 muxi 账号")
    if mutation and (request.headers.get("origin") != settings.issuer or request.headers.get("x-muxi-account-action") != "1"):
        raise HTTPException(status_code=403, detail="请求来源校验失败，请从账号页操作")
    return account


def current_web_account(request: Request) -> Account | None:
    return store.web_session(request.cookies.get("muxi_session"))


def bearer(request: Request) -> str | None:
    value = request.headers.get("authorization", "")
    return value[7:].strip() if value.lower().startswith("bearer ") else None


def safe_continue(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/account"
    return value


def append_query(url: str, **values: str | None) -> str:
    parts = urlsplit(url)
    query = list(parse_qsl(parts.query, keep_blank_values=True))
    query.extend((key, value) for key, value in values.items() if value is not None)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def send_verification_email(email: str, nickname: str, verify_url: str) -> None:
    if not settings.smtp_host:
        return
    message = EmailMessage()
    message["Subject"] = "验证你的 muxi 账户"
    message["From"] = settings.smtp_from
    message["To"] = email
    message.set_content(
        f"你好 {nickname}，\n\n请打开下面的链接验证你的 muxi 账户：\n{verify_url}\n\n链接 24 小时内有效。"
    )
    smtp_cls = smtplib.SMTP_SSL if settings.smtp_ssl else smtplib.SMTP
    with smtp_cls(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if not settings.smtp_ssl:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(WEB_ROOT / "index.html")


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(WEB_ROOT / "login.html")


@app.get("/register", include_in_schema=False)
def register_page() -> FileResponse:
    return FileResponse(WEB_ROOT / "register.html")


@app.get("/account", include_in_schema=False)
def account_page() -> FileResponse:
    return FileResponse(WEB_ROOT / "account.html")


@app.get("/external/complete", include_in_schema=False)
def external_complete_page() -> FileResponse:
    return FileResponse(WEB_ROOT / "external-complete.html")


@app.post("/api/account/register", status_code=201)
def register(
    payload: RegisterRequest,
    request: Request,
    background: BackgroundTasks,
    continue_to: str = "",
) -> dict:
    username = payload.username.strip()
    nickname = payload.nickname.strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", username):
        raise HTTPException(status_code=422, detail="用户名只能使用 3–16 位字母、数字和下划线")
    if not nickname:
        raise HTTPException(status_code=422, detail="昵称不能为空")
    if not settings.smtp_host and not settings.dev_verify:
        raise HTTPException(status_code=503, detail="邮件验证服务尚未启用")
    try:
        account, raw_verify = store.register(str(payload.email), username, nickname, payload.password)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    safe_next = safe_continue(continue_to) if continue_to else "/account"
    verify_url = (
        f"{settings.issuer}/api/account/verify?token={quote(raw_verify)}"
        f"&continue_to={quote(safe_next, safe='')}"
    )
    return send_verification(background, account, raw_verify, safe_next)


def send_verification(background: BackgroundTasks, account: Account, raw_verify: str, safe_next: str) -> dict:
    """把验证信排进后台队列，并返回前端要展示的结果。注册、补绑、重发共用。"""
    verify_url = (
        f"{settings.issuer}/api/account/verify?token={quote(raw_verify)}"
        f"&continue_to={quote(safe_next, safe='')}"
    )
    background.add_task(send_verification_email, account.email, account.nickname, verify_url)
    result = {
        "ok": True,
        # 把地址回给前端，界面才能写出「已发往 x@y」——只说「已发送」的话，
        # 打错一个字母的人会一直等一封永远不会到的信。
        "email": account.email,
        "message": "验证邮件已发送，请在 24 小时内完成验证",
    }
    if settings.dev_verify:
        result["verificationUrl"] = verify_url
    return result


@app.post("/api/account/email")
def bind_email(payload: BindEmailRequest, request: Request, background: BackgroundTasks) -> dict:
    """给 QQ / 微信注册出来的账号补一个邮箱，或改掉还没验证的那个。"""
    account = current_web_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="请先登录")
    if not settings.smtp_host and not settings.dev_verify:
        raise HTTPException(status_code=503, detail="邮件验证服务尚未启用")
    try:
        raw_verify = store.bind_email(account.id, str(payload.email))
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    refreshed = store.account_by_uid(account.uid) or account
    return send_verification(background, refreshed, raw_verify, "/account")


@app.post("/api/account/verification/resend")
def resend_verification(payload: ResendRequest, background: BackgroundTasks) -> dict:
    """重发验证信。

    **故意不要求登录**：登录本身就卡着「邮箱已验证」，没收到信的人否则永远进不来。
    也**故意不区分**查无此人 / 已经验证过 —— 分开回答就等于把这个接口变成邮箱探测器。
    """
    if not settings.smtp_host and not settings.dev_verify:
        raise HTTPException(status_code=503, detail="邮件验证服务尚未启用")
    pending = store.resend_verification(str(payload.email))
    if pending is None:
        return {"ok": True, "message": "如果该邮箱尚待验证，我们已经重新发送了一封验证邮件"}
    account, raw_verify = pending
    result = send_verification(background, account, raw_verify, "/account")
    result["message"] = "如果该邮箱尚待验证，我们已经重新发送了一封验证邮件"
    return result


@app.post("/api/account/avatar")
async def upload_avatar(request: Request, file: UploadFile = File(...)) -> dict:
    account = current_web_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="请先登录")
    # 先卡长度再读：不设上限的话，一个大文件就能把内存顶穿。多读一个字节用来判超限。
    data = await file.read(avatar_rules.MAX_BYTES + 1)
    try:
        content_type, etag = avatar_rules.validate(data)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    store.set_avatar(account.id, data, content_type, etag)
    return {"ok": True, "avatarUrl": f"/api/account/avatar/{account.uid}?v={etag}"}


@app.delete("/api/account/avatar")
def delete_avatar(request: Request) -> dict:
    account = current_web_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="请先登录")
    store.clear_avatar(account.id)
    return {"ok": True}


@app.get("/api/account/avatar/{uid}")
def serve_avatar(uid: int) -> Response:
    """按 UID 提供头像。头像本来就要显示给同服玩家看，不需要登录。

    Content-Type 用的是服务端按魔数判出来的那个，不是上传时客户端说的那个。
    """
    found = store.avatar(uid)
    if found is None:
        raise HTTPException(status_code=404, detail="没有头像")
    data, content_type, etag = found
    return Response(
        content=data,
        media_type=content_type,
        headers={
            # URL 带内容指纹，所以可以让浏览器放心长缓存：换头像就是换 URL。
            "Cache-Control": "public, max-age=31536000, immutable",
            "ETag": f'"{etag}"',
            "Content-Disposition": "inline",
        },
    )


@app.delete("/api/account")
def delete_account(payload: DeleteAccountRequest, request: Request, response: Response) -> dict:
    """注销账号。不可撤销。

    要求把用户名原样打一遍再执行——注销会级联删掉邮箱、会话和令牌，
    一个「确定吗」的弹窗挡不住手滑。

    UID 不回收：游戏存档是按 UID 推出来的离线 UUID 存的，回收等于把新注册的人
    扔进别人的身体里。
    """
    account = current_web_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="请先登录")
    if payload.username.strip().lower() != account.username.lower():
        raise HTTPException(status_code=422, detail="用户名不匹配，账号未注销")
    if not store.delete_account(account.id):
        raise HTTPException(status_code=404, detail="账号不存在")
    response.delete_cookie("muxi_session", path="/")
    return {"ok": True, "message": "账号已注销"}


@app.get("/api/account/verify")
def verify_email(token: str = "", continue_to: str = "") -> RedirectResponse:
    ok = bool(token) and store.verify_email(token) is not None
    safe_next = safe_continue(continue_to) if continue_to else "/account"
    return RedirectResponse(
        f"/login?verified={'1' if ok else '0'}&continue={quote(safe_next, safe='')}",
        status_code=303,
    )


@app.post("/api/account/login")
def login(payload: LoginRequest, response: Response) -> dict:
    try:
        account = store.authenticate(payload.identity.strip(), payload.password)
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    if account is None:
        raise HTTPException(status_code=401, detail="账号或密码不正确")
    raw = store.create_web_session(account.id, settings.web_session_days)
    response.set_cookie(
        "muxi_session",
        raw,
        max_age=settings.web_session_days * 86400,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    return {"user": account.public()}


@app.get("/api/account/me")
def me(request: Request) -> dict:
    account = current_web_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="请先登录")
    return {"user": account.public()}


@app.patch("/api/account/profile")
def update_profile(payload: ProfileRequest, request: Request) -> dict:
    account = current_web_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="请先登录")
    username = payload.username.strip()
    nickname = payload.nickname.strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", username):
        raise HTTPException(status_code=422, detail="用户名只能使用 3–16 位字母、数字和下划线")
    if not nickname:
        raise HTTPException(status_code=422, detail="昵称不能为空")
    try:
        updated = store.update_profile(account.id, username, nickname)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return {"user": updated.public()}


@app.post("/api/account/logout")
def logout(request: Request, response: Response) -> dict:
    store.delete_web_session(request.cookies.get("muxi_session"))
    response.delete_cookie("muxi_session", path="/")
    return {"ok": True}


def set_web_session(response: Response, account: Account) -> None:
    raw = store.create_web_session(account.id, settings.web_session_days)
    response.set_cookie(
        "muxi_session",
        raw,
        max_age=settings.web_session_days * 86400,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )


@app.get("/api/external/providers")
def external_providers(response: Response) -> dict:
    response.headers["Cache-Control"] = "no-store"
    return {"providers": provider_status()}


@app.get("/api/account/external")
def account_external(request: Request) -> dict:
    account = binding_account(request)
    return {**store.external_bindings(account.id), "providers": provider_status()}


@app.post("/api/account/external/{provider}/start")
def start_account_binding(provider: str, payload: BindingRequest, request: Request) -> dict:
    account = binding_account(request, mutation=True)
    if payload.action not in ("bind", "replace"):
        raise HTTPException(status_code=400, detail="无效的绑定操作")
    try:
        session = request.cookies.get("muxi_session", "")
        store.authorize_binding_change(account.id, session, payload.password)
        expected = store.binding_snapshot(account.id, provider, payload.action == "replace")
        state, verifier = store.create_external_state(provider, "/account", account_id=account.id, session=session, expected_id=expected)
        url = external_authorize_url(provider, state, verifier, user_agent=request.headers.get("user-agent", ""), binding=True)
    except (ValueError, ExternalOAuthError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"url": url}


@app.get("/api/account/external/pending")
def pending_account_binding(request: Request) -> dict:
    account = binding_account(request)
    return {"pending": store.pending_external_binding(request.cookies.get("muxi_binding_ticket", ""), account.id, request.cookies.get("muxi_session", ""))}


@app.post("/api/account/external/confirm")
def confirm_account_binding(payload: BindingRequest, request: Request, response: Response) -> dict:
    account = binding_account(request, mutation=True)
    if payload.action not in ("confirm", "cancel"):
        raise HTTPException(status_code=400, detail="无效的确认操作")
    try:
        store.finish_external_binding(request.cookies.get("muxi_binding_ticket", ""), account.id, request.cookies.get("muxi_session", ""), cancel=payload.action == "cancel")
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    response.delete_cookie("muxi_binding_ticket", path="/api/account/external")
    return {"ok": True}


@app.post("/api/account/external/{provider}/unlink")
def unlink_account_binding(provider: str, payload: BindingRequest, request: Request) -> dict:
    account = binding_account(request, mutation=True)
    session = request.cookies.get("muxi_session", "")
    try:
        store.authorize_binding_change(account.id, session, payload.password)
        store.unlink_external(account.id, provider, session)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"ok": True}


@app.post("/api/launcher/auth-flow", status_code=201)
def create_launcher_auth_flow() -> dict:
    flow, secret = store.create_launcher_auth_flow()
    return {"flow": flow, "secret": secret, "expiresIn": 1200}


@app.get("/api/launcher/auth-flow/{flow}")
def launcher_auth_flow_status(flow: str, secret: str = "") -> dict:
    if not flow or not secret:
        raise HTTPException(status_code=404, detail="启动器授权会话不存在")
    status = store.launcher_auth_flow_status(flow, secret)
    if status is None:
        raise HTTPException(status_code=404, detail="启动器授权会话不存在")
    return {"status": status}


@app.post("/api/launcher/auth-flow/{flow}/resume")
def resume_launcher_auth_flow(flow: str, secret: str = "") -> Response:
    if not flow or not secret or not store.launcher_auth_flow_resume(flow, secret):
        raise HTTPException(status_code=404, detail="启动器授权会话不存在")
    return Response(status_code=204)


@app.post("/api/launcher/auth-flow/{flow}/cancel")
def cancel_launcher_auth_flow(flow: str, secret: str = "") -> Response:
    if not flow or not secret or not store.launcher_auth_flow_cancel(flow, secret):
        raise HTTPException(status_code=404, detail="启动器授权会话不存在")
    return Response(status_code=204)


@app.delete("/api/launcher/auth-flow/{flow}")
def complete_launcher_auth_flow(flow: str, secret: str = "") -> Response:
    if flow and secret:
        store.complete_launcher_auth_flow(flow, secret)
    return Response(status_code=204)


@app.get("/external/{provider}/start")
def external_start(provider: str, request: Request, continue_to: str = "/account") -> RedirectResponse:
    if provider not in {"qq", "wechat"}:
        raise HTTPException(status_code=404, detail="不支持的第三方登录方式")
    safe_next = safe_continue(continue_to)
    state, verifier = store.create_external_state(provider, safe_next)
    try:
        destination = external_authorize_url(
            provider, state, verifier, user_agent=request.headers.get("user-agent", "")
        )
    except ExternalOAuthError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return RedirectResponse(destination, status_code=303, headers={"Cache-Control": "no-store"})


@app.get("/external/czl/callback")
def external_czl_callback(
    request: Request,
    state: str = "",
    code: str = "",
    error: str = "",
) -> RedirectResponse:
    consumed = store.consume_external_state_context(state) if state else None
    if consumed is None:
        return RedirectResponse("/login?external=invalid_state", status_code=303)
    provider, verifier, continue_to = consumed["provider"], consumed["code_verifier"], consumed["continue_to"]
    binding = consumed["purpose"] == "binding"
    if binding:
        account = current_web_account(request)
        if account is None or account.id != consumed["account_id"] or token_hash(request.cookies.get("muxi_session", "")) != consumed["session_hash"]:
            return RedirectResponse("/account?binding=session_changed", status_code=303)
    if error or not code:
        if binding:
            return RedirectResponse("/account?binding=cancelled", status_code=303)
        return RedirectResponse(
            f"/login?external={quote(error or 'cancelled', safe='')}&continue={quote(continue_to, safe='')}",
            status_code=303,
        )
    try:
        profile = exchange_profile(provider, code, verifier)
    except ExternalOAuthError:
        if binding:
            return RedirectResponse("/account?binding=failed", status_code=303)
        return RedirectResponse(
            f"/login?external=failed&continue={quote(continue_to, safe='')}", status_code=303
        )

    if binding:
        ticket = store.prepare_external_binding(consumed, {"subject": profile.subject, "upstream_subject": profile.upstream_subject,
            "nickname": profile.nickname, "raw_profile": profile.raw_profile})
        response = RedirectResponse("/account?binding=confirm", status_code=303)
        response.set_cookie("muxi_binding_ticket", ticket, httponly=True, secure=settings.secure_cookies,
                            samesite="lax", max_age=600, path="/api/account/external")
        return response

    account = store.external_account(
        provider,
        profile.subject,
        raw_profile=profile.raw_profile,
        upstream_subject=profile.upstream_subject,
    )
    if account is not None:
        response = RedirectResponse(continue_to, status_code=303)
        set_web_session(response, account)
        return response

    ticket = store.create_external_signup(
        provider,
        profile.subject,
        profile.nickname,
        continue_to,
        raw_profile=profile.raw_profile,
        upstream_subject=profile.upstream_subject,
    )
    return RedirectResponse(f"/external/complete?ticket={quote(ticket, safe='')}", status_code=303)


@app.get("/api/external/signup")
def external_signup(ticket: str) -> dict:
    signup = store.external_signup(ticket)
    if signup is None:
        raise HTTPException(status_code=404, detail="第三方注册会话无效或已过期")
    return {
        "provider": signup["provider"],
        "nickname": signup.get("provider_nickname") or "",
        "continue": safe_continue(str(signup.get("continue_to") or "/account")),
    }


@app.post("/api/external/complete")
def external_complete(payload: ExternalCompleteRequest, response: Response) -> dict:
    username = payload.username.strip()
    nickname = payload.nickname.strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", username):
        raise HTTPException(status_code=422, detail="用户名只能使用 3–16 位字母、数字和下划线")
    if not nickname:
        raise HTTPException(status_code=422, detail="昵称不能为空")
    try:
        account, continue_to = store.complete_external_signup(payload.ticket, username, nickname)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    set_web_session(response, account)
    return {"user": account.public(), "continue": safe_continue(continue_to)}


def validate_authorization_request(
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    code_challenge: str,
    code_challenge_method: str,
) -> tuple[OAuthClient, str]:
    client = store.client(client_id)
    if client is None:
        raise HTTPException(status_code=400, detail="unknown client_id")
    if not store.redirect_allowed(client, redirect_uri):
        raise HTTPException(status_code=400, detail="invalid redirect_uri")
    if response_type != "code":
        raise HTTPException(status_code=400, detail="only response_type=code is supported")
    requested = [item for item in scope.split() if item]
    if "openid" not in requested or any(item not in client.scopes for item in requested):
        raise HTTPException(status_code=400, detail="invalid scope")
    if code_challenge_method != "S256" or not code_challenge:
        raise HTTPException(status_code=400, detail="PKCE S256 is required")
    return client, " ".join(dict.fromkeys(requested))


@app.get("/oauth/authorize")
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "openid profile email",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str = "",
    code_challenge_method: str = "",
) -> RedirectResponse:
    client, normalized_scope = validate_authorization_request(
        client_id, redirect_uri, response_type, scope, code_challenge, code_challenge_method
    )
    account = current_web_account(request)
    if account is None:
        relative = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(f"/login?continue={quote(relative, safe='')}", status_code=303)
    code = store.create_authorization_code(
        client.client_id, account.id, redirect_uri, normalized_scope, code_challenge, nonce
    )
    destination = append_query(redirect_uri, code=code, state=state, iss=settings.issuer)
    return RedirectResponse(destination, status_code=303)


def oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def parse_client_auth(request: Request, form: dict[str, str]) -> tuple[str, str | None]:
    client_id = form.get("client_id", "")
    secret = form.get("client_secret")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8")
            client_id, secret = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return "", None
    return client_id, secret


def confidential_client_from_basic(request: Request) -> OAuthClient | None:
    client_id, secret = parse_client_auth(request, {})
    client = store.client(client_id)
    if client is None or client.public_client or not store.verify_client_secret(client, secret):
        return None
    return client


def id_token_for(account: Account, client_id: str, nonce: str | None) -> str:
    now = utc_now()
    claims = {
        "iss": settings.issuer,
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
    }
    claims.update(account.claims())
    if nonce:
        claims["nonce"] = nonce
    return signer.id_token(claims)


def issue_tokens(account: Account, client_id: str, scope: str, nonce: str | None = None) -> dict:
    access = store.issue_access_token(account.id, client_id, scope, settings.access_token_seconds)
    refresh = store.issue_refresh_token(account.id, client_id, scope, settings.refresh_token_days)
    result = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.access_token_seconds,
        "refresh_token": refresh,
        "scope": scope,
    }
    if "openid" in scope.split():
        result["id_token"] = id_token_for(account, client_id, nonce)
    return result


@app.post("/oauth/token")
async def token(request: Request):
    raw_form = await request.form()
    form = {str(k): str(v) for k, v in raw_form.items()}
    client_id, client_secret = parse_client_auth(request, form)
    client = store.client(client_id)
    if client is None or not store.verify_client_secret(client, client_secret):
        return oauth_error("invalid_client", "client authentication failed", 401)

    grant_type = form.get("grant_type", "")
    if grant_type == "authorization_code":
        code = form.get("code", "")
        redirect_uri = form.get("redirect_uri", "")
        verifier = form.get("code_verifier", "")
        if not code or not verifier or not store.redirect_allowed(client, redirect_uri):
            return oauth_error("invalid_grant", "invalid authorization code request")
        consumed = store.consume_authorization_code(code, client_id, redirect_uri, verifier)
        if consumed is None:
            return oauth_error("invalid_grant", "authorization code is invalid, expired, used, or PKCE failed")
        account, scope, nonce = consumed
        return JSONResponse(
            issue_tokens(account, client_id, scope, nonce),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    if grant_type == "refresh_token":
        raw_refresh = form.get("refresh_token", "")
        consumed = store.consume_refresh_token(raw_refresh, client_id) if raw_refresh else None
        if consumed is None:
            return oauth_error("invalid_grant", "refresh token is invalid, expired, or already rotated")
        account, scope = consumed
        requested_scope = form.get("scope", "").strip()
        if requested_scope:
            requested = set(requested_scope.split())
            original = set(scope.split())
            if not requested.issubset(original):
                return oauth_error("invalid_scope", "scope may only be narrowed during refresh")
            scope = " ".join(item for item in scope.split() if item in requested)
        return JSONResponse(
            issue_tokens(account, client_id, scope),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return oauth_error("unsupported_grant_type", "supported grants: authorization_code, refresh_token")


@app.get("/oauth/userinfo")
def userinfo(request: Request):
    result = store.access_token(bearer(request))
    if result is None:
        return oauth_error("invalid_token", "access token is invalid or expired", 401)
    account, _client_id, scope = result
    claims = {"sub": account.subject}
    allowed = set(scope.split())
    if "profile" in allowed:
        claims.update({
            "muxi_uid": account.uid,
            "preferred_username": account.username,
            "username": account.username,
            "name": account.nickname,
            "nickname": account.nickname,
            "game_name": str(account.uid),
            "role": account.role,
            "created_at": account.created_at,
            "last_login_at": account.last_login_at,
        })
    if "email" in allowed and account.email:
        claims.update({"email": account.email, "email_verified": account.email_verified})
    return claims


@app.post("/oauth/revoke")
async def revoke(request: Request):
    raw_form = await request.form()
    form = {str(k): str(v) for k, v in raw_form.items()}
    client_id, client_secret = parse_client_auth(request, form)
    client = store.client(client_id)
    if client is None or not store.verify_client_secret(client, client_secret):
        return oauth_error("invalid_client", "client authentication failed", 401)
    raw = form.get("token", "")
    if raw:
        store.revoke(raw)
    return Response(status_code=200, headers={"Cache-Control": "no-store"})


def metadata() -> dict:
    return {
        "issuer": settings.issuer,
        "authorization_endpoint": f"{settings.issuer}/oauth/authorize",
        "token_endpoint": f"{settings.issuer}/oauth/token",
        "userinfo_endpoint": f"{settings.issuer}/oauth/userinfo",
        "revocation_endpoint": f"{settings.issuer}/oauth/revoke",
        "jwks_uri": f"{settings.issuer}/oauth/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "muxi_uid", "preferred_username", "username",
            "name", "nickname", "game_name", "email", "email_verified", "role", "created_at", "last_login_at"
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
    }


@app.get("/.well-known/openid-configuration")
def openid_configuration() -> dict:
    return metadata()


@app.get("/.well-known/oauth-authorization-server")
def oauth_configuration() -> dict:
    return metadata()


@app.get("/oauth/jwks.json")
def jwks() -> dict:
    return {"keys": [signer.jwk]}


@app.get("/api/admin/users")
def admin_users(request: Request, limit: int = 200):
    # This is a server-to-server management endpoint for trusted first-party sites.
    # End-user browsers never receive the confidential client secret.
    client = confidential_client_from_basic(request)
    if client is None:
        raise HTTPException(status_code=401, detail="invalid management client")
    return {"users": store.list_accounts(limit)}


app.mount("/static", StaticFiles(directory=WEB_ROOT / "static"), name="static")

