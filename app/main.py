from __future__ import annotations

import base64
import json
import re
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from html import escape
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from .config import ROOT, settings
from .external_oauth import ExternalOAuthError, authorize_url as external_authorize_url, exchange_profile, provider_status
from .security import OidcSigner, utc_now
from .store import Account, OAuthClient, Store


WEB_ROOT = ROOT / "web"
store = Store(settings.database_path)
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


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True, "service": "muxi-auth"}


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
    if request.url.path.startswith(("/oauth", "/api/account", "/api/launcher", "/login", "/register", "/account")):
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


class ExternalCompleteRequest(BaseModel):
    ticket: str = Field(min_length=16, max_length=256)
    username: str = Field(min_length=3, max_length=16)
    nickname: str = Field(min_length=1, max_length=64)


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
    background.add_task(send_verification_email, account.email, account.nickname, verify_url)
    result = {"ok": True, "message": "验证邮件已发送，请在 24 小时内完成验证"}
    if settings.dev_verify:
        result["verificationUrl"] = verify_url
    return result


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
def external_providers() -> dict:
    return {"providers": provider_status()}


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
def external_start(provider: str, continue_to: str = "/account") -> RedirectResponse:
    if provider not in {"qq", "wechat"}:
        raise HTTPException(status_code=404, detail="不支持的第三方登录方式")
    safe_next = safe_continue(continue_to)
    state, verifier = store.create_external_state(provider, safe_next)
    try:
        destination = external_authorize_url(provider, state, verifier)
    except ExternalOAuthError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return RedirectResponse(destination, status_code=303)


@app.get("/external/czl/callback")
def external_czl_callback(
    state: str = "",
    code: str = "",
    error: str = "",
) -> RedirectResponse:
    consumed = store.consume_external_state(state) if state else None
    if consumed is None:
        return RedirectResponse("/login?external=invalid_state", status_code=303)
    provider, verifier, continue_to = consumed
    if error or not code:
        return RedirectResponse(
            f"/login?external={quote(error or 'cancelled', safe='')}&continue={quote(continue_to, safe='')}",
            status_code=303,
        )
    try:
        profile = exchange_profile(provider, code, verifier)
    except ExternalOAuthError:
        return RedirectResponse(
            f"/login?external=failed&continue={quote(continue_to, safe='')}", status_code=303
        )

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
            "game_name": account.game_name,
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

