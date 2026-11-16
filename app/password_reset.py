"""Email recovery with opaque links; never put a recovery secret in a URL query.

Account lookup, throttling and delivery run after the uniform public response.
This module deliberately never logs an exception body, address, password or token.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Callable
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError

from .config import ROOT, Settings
from .security import token_hash, utc_now
from .store import Store


LOGGER = logging.getLogger(__name__)
MESSAGE = "如果该邮箱关联可找回的账户，我们会发送一封邮件。请稍后检查收件箱和垃圾邮件。"
INVALID_LINK = "链接已失效或已使用，请重新申请找回密码"
PRIVATE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}
MAX_BODY_BYTES = 4096


class ResetEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(max_length=254, repr=False)


class ResetConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$", repr=False)
    password: str = Field(min_length=10, max_length=128, repr=False)
    password_confirm: str = Field(min_length=10, max_length=128, repr=False)


def reset_issuer(settings: Settings) -> str:
    """Use the configured, fixed account origin, never Host or a return URL."""
    parts = urlsplit(settings.issuer)
    production = parts.scheme == "https" and parts.hostname == "account.muxigame.com" and parts.port in (None, 443)
    development = settings.dev_verify and parts.scheme == "http" and parts.hostname in {"127.0.0.1", "localhost", "::1"}
    if not (production or development) or parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise ValueError("Invalid password recovery origin")
    return settings.issuer.rstrip("/")


def require_same_origin(request: Request, settings: Settings) -> None:
    if request.headers.get("origin") != settings.issuer or request.headers.get("x-muxi-account-action") != "1":
        raise HTTPException(403, "请求来源校验失败，请从账户官网操作")


def client_fingerprint(request: Request) -> str:
    # Production's only published port is loopback. Its reviewed nginx vhost
    # overwrites X-Real-IP with $remote_addr. XFF is appendable by callers.
    raw = request.headers.get("x-real-ip") or (request.client.host if request.client else "")
    try:
        address = ipaddress.ip_address(raw).compressed
    except ValueError:
        address = "unknown"
    return token_hash("password-reset-client:" + address)


async def read_payload(request: Request, model: type[BaseModel], detail: str) -> BaseModel:
    # Do not let FastAPI's default validation response echo secret inputs.
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "请使用网页表单提交")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_BODY_BYTES:
            raise HTTPException(413, "提交内容过长")
        data.extend(chunk)
    try:
        return model.model_validate(json.loads(data))
    except (ValueError, ValidationError):
        raise HTTPException(422, detail) from None


def send_email(settings: Settings, email: str, subject: str, content: str) -> None:
    if not settings.smtp_host:
        raise RuntimeError("Mail service unavailable")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = email
    message.set_content(content)
    context = ssl.create_default_context()
    if settings.smtp_ssl:
        connection = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15, context=context)
    else:
        connection = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
    with connection as smtp:
        if not settings.smtp_ssl:
            smtp.starttls(context=context)
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


def deliver_reset(settings: Settings, store: Store, email: str, client_hash: str) -> None:
    raw = None
    try:
        pending = store.request_password_reset(email, client_hash)
        if pending is None:
            return
        account, raw = pending
        link = reset_issuer(settings) + "/reset-password#token=" + raw
        send_email(settings, account.email, "重置你的 muxi 账户密码", (
            "你申请了重置 muxi 账户密码。请在 15 分钟内打开下面的链接，并在账户官网设置新密码：\n\n"
            + link + "\n\n链接只能使用一次，重新申请会使之前的链接失效。"
            "如果你没有申请，请忽略本邮件，你的密码和登录状态不会因此改变。\n"
            "请勿将此链接转发给他人。muxi 不会在邮件中索取或发送你的密码。"
        ))
    except Exception:
        if raw:
            try:
                store.cancel_password_reset(raw)
            except Exception:
                LOGGER.warning("Password recovery cancellation failed")
        LOGGER.warning("Password recovery request could not be completed")


def notify_reset(settings: Settings, email: str) -> None:
    try:
        send_email(settings, email, "你的 muxi 账户密码已更新", (
            "你的 muxi 账户密码已更新，更新时间（UTC）：" + utc_now().strftime("%Y-%m-%d %H:%M")
            + "。\n\n账户中心的旧登录会话、访问令牌和刷新令牌已失效，请从 https://account.muxigame.com/login 重新登录。"
            "\n如果不是你本人操作，请立即联系账户管理员。此邮件不包含密码或登录链接。"
        ))
    except Exception:
        LOGGER.warning("Password recovery notification could not be delivered")


def password_reset_router(get_settings: Callable[[], Settings], get_store: Callable[[], Store]) -> APIRouter:
    router = APIRouter()

    @router.get("/forgot-password", include_in_schema=False)
    def forgot_page() -> FileResponse:
        return FileResponse(ROOT / "web" / "forgot-password.html", headers=PRIVATE_HEADERS)

    @router.get("/reset-password", include_in_schema=False)
    def reset_page() -> FileResponse:
        return FileResponse(ROOT / "web" / "reset-password.html", headers=PRIVATE_HEADERS)

    @router.post("/api/account/password-reset/request", status_code=202, include_in_schema=False)
    async def request_reset(request: Request, background: BackgroundTasks) -> JSONResponse:
        settings = get_settings()
        require_same_origin(request, settings)
        payload = await read_payload(request, ResetEmailRequest, "请输入有效的邮箱地址")
        try:
            reset_issuer(settings)
        except ValueError:
            raise HTTPException(503, "找回密码服务暂不可用，请稍后重试") from None
        if not settings.smtp_host:
            raise HTTPException(503, "找回密码服务暂不可用，请稍后重试")
        background.add_task(deliver_reset, settings, get_store(), str(payload.email), client_fingerprint(request))
        return JSONResponse({"ok": True, "message": MESSAGE}, status_code=202, headers=PRIVATE_HEADERS)

    @router.post("/api/account/password-reset/confirm", include_in_schema=False)
    async def confirm_reset(request: Request, background: BackgroundTasks) -> JSONResponse:
        settings = get_settings()
        require_same_origin(request, settings)
        payload = await read_payload(request, ResetConfirmRequest, "请检查链接，并输入两次相同的 10–128 位新密码")
        if payload.password != payload.password_confirm:
            raise HTTPException(422, "两次输入的密码不一致")
        try:
            reset_issuer(settings)
        except ValueError:
            raise HTTPException(503, "找回密码服务暂不可用，请稍后重试") from None
        try:
            account = get_store().consume_password_reset(payload.token, payload.password)
        except ValueError:
            raise HTTPException(422, "新密码必须为 10–128 位") from None
        if account is None:
            raise HTTPException(400, INVALID_LINK)
        background.add_task(notify_reset, settings, account.email)
        response = JSONResponse({"ok": True, "message": "密码已更新，原账户登录状态已失效，请重新登录。"}, headers=PRIVATE_HEADERS)
        response.delete_cookie("muxi_session", path="/", secure=settings.secure_cookies, httponly=True, samesite="lax")
        return response

    return router
