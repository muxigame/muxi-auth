from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import settings


class ExternalOAuthError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExternalProfile:
    provider: str
    subject: str
    nickname: str | None
    raw_profile: dict[str, Any]
    upstream_subject: str | None = None


def provider_status() -> dict[str, bool]:
    enabled = bool(settings.czl_client_id and settings.czl_client_secret)
    return {"qq": enabled, "wechat": enabled}


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authorize_url(provider: str, state: str, code_verifier: str) -> str:
    if provider not in {"qq", "wechat"}:
        raise ExternalOAuthError("不支持的第三方登录方式")
    if not provider_status()[provider]:
        raise ExternalOAuthError("第三方登录尚未配置")

    params = urllib.parse.urlencode(
        {
            "client_id": settings.czl_client_id,
            "redirect_uri": settings.czl_redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
            "code_challenge_method": "S256",
            "code_challenge": pkce_s256(code_verifier),
            "upstream_providers": provider,
        }
    )
    return f"{settings.czl_authorize_endpoint}?{params}"


def _json_request(request: urllib.request.Request, *, timeout: int = 15) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        try:
            raw = error.read().decode("utf-8", "replace")
            parsed = json.loads(raw)
            detail = parsed.get("error_description") or parsed.get("error")
        except Exception:
            detail = None
        raise ExternalOAuthError(detail or f"CZL Connect 返回 HTTP {error.code}") from error
    except Exception as error:
        raise ExternalOAuthError("CZL Connect 暂时不可用") from error

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ExternalOAuthError("CZL Connect 返回了无效 JSON") from error
    if not isinstance(data, dict):
        raise ExternalOAuthError("CZL Connect 返回了无效响应")
    return data


def _exchange_token(code: str, code_verifier: str) -> dict[str, Any]:
    common = {
        "grant_type": "authorization_code",
        "client_id": settings.czl_client_id,
        "code": code,
        "redirect_uri": settings.czl_redirect_uri,
        "code_verifier": code_verifier,
    }
    basic = base64.b64encode(
        f"{settings.czl_client_id}:{settings.czl_client_secret}".encode("utf-8")
    ).decode("ascii")

    def request_token(use_basic: bool) -> dict[str, Any]:
        form = dict(common)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if use_basic:
            headers["Authorization"] = f"Basic {basic}"
        else:
            form["client_secret"] = settings.czl_client_secret
        request = urllib.request.Request(
            settings.czl_token_endpoint,
            data=urllib.parse.urlencode(form).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        return _json_request(request)

    try:
        data = request_token(True)
    except ExternalOAuthError:
        data = request_token(False)
    if not data.get("access_token"):
        raise ExternalOAuthError("CZL Connect 没有返回 access_token")
    return data


def _userinfo(access_token: str) -> dict[str, Any]:
    endpoints = [
        settings.czl_userinfo_endpoint,
        "https://connect.czl.net/api/oidc/userinfo",
    ]
    last_error: Exception | None = None
    for endpoint in dict.fromkeys(endpoints):
        request = urllib.request.Request(
            endpoint,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        try:
            return _json_request(request)
        except ExternalOAuthError as error:
            last_error = error
    raise ExternalOAuthError("无法读取 CZL Connect 用户信息") from last_error


def _candidate_provider(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    aliases = {
        "weixin": "wechat",
        "wx": "wechat",
        "we_chat": "wechat",
        "qqconnect": "qq",
    }
    return aliases.get(text, text)


def _find_upstream_subject(profile: dict[str, Any], provider: str) -> str | None:
    upstreams = profile.get("upstreams")
    if not isinstance(upstreams, list):
        return None
    id_keys = ("unionid", "openid", "sub", "subject", "uid", "user_id", "id")
    provider_keys = ("provider", "type", "name", "platform", "source")
    for item in upstreams:
        if not isinstance(item, dict):
            continue
        item_provider = ""
        for key in provider_keys:
            if key in item:
                item_provider = _candidate_provider(item.get(key))
                if item_provider:
                    break
        if item_provider and item_provider != provider:
            continue
        for key in id_keys:
            value = item.get(key)
            if value is not None and str(value).strip():
                return f"{key}:{str(value).strip()}"
    return None


def exchange_profile(provider: str, code: str, code_verifier: str) -> ExternalProfile:
    if provider not in {"qq", "wechat"}:
        raise ExternalOAuthError("不支持的第三方登录方式")
    if not provider_status()[provider]:
        raise ExternalOAuthError("第三方登录尚未配置")

    token = _exchange_token(code, code_verifier)
    profile = _userinfo(str(token["access_token"]))
    sub = str(profile.get("sub") or profile.get("id") or "").strip()
    if not sub:
        raise ExternalOAuthError("CZL Connect userinfo 缺少稳定用户标识")

    nickname = str(
        profile.get("nickname") or profile.get("name") or profile.get("username") or ""
    ).strip() or None
    return ExternalProfile(
        provider=provider,
        subject=f"czl:{sub}",
        nickname=nickname,
        raw_profile=profile,
        upstream_subject=_find_upstream_subject(profile, provider),
    )
