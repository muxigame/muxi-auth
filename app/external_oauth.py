from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import settings
from .external_identity import upstream_subject as verified_upstream_subject


class ExternalOAuthError(RuntimeError):
    pass


class ExternalIdentityUnclear(ExternalOAuthError):
    """The broker answered, but which QQ / WeChat account was used is not certain."""


CZL_PROVIDERS = ("qq", "wechat")
OIDC_PROVIDERS = ("microsoft", "google")
PROVIDERS = CZL_PROVIDERS + OIDC_PROVIDERS
PROVIDER_NAMES = {"qq": "QQ", "wechat": "微信", "microsoft": "Microsoft", "google": "Google"}


@dataclass(frozen=True)
class ExternalProfile:
    provider: str
    subject: str
    nickname: str | None
    raw_profile: dict[str, Any]
    upstream_subject: str | None = None


def provider_status() -> dict[str, bool]:
    enabled = bool(settings.czl_client_id and settings.czl_client_secret)
    return {
        "qq": enabled,
        "wechat": enabled,
        "microsoft": bool(settings.microsoft_client_id and settings.microsoft_client_secret),
        "google": bool(settings.google_client_id and settings.google_client_secret),
    }


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authorize_url(provider: str, state: str, code_verifier: str, *, user_agent: str = "", binding: bool = False) -> str:
    if provider in OIDC_PROVIDERS:
        if not provider_status()[provider]:
            raise ExternalOAuthError(f"{PROVIDER_NAMES[provider]} 登录尚未配置")
        return _oidc_authorize(provider, state, code_verifier, binding)
    if provider not in CZL_PROVIDERS:
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
            **({"prompt": "consent"} if binding else {}),
        }
    )
    authorization = f"{settings.czl_authorize_endpoint}?{params}"
    if not settings.czl_direct_upstream:
        return authorization

    # This is the same navigation used by CZL's own QQ/WeChat login buttons.
    # The browser visits CZL (which sets its own state/session cookies), then
    # CZL redirects to Tencent. Do NOT fetch the Tencent URL server-side and
    # relay it: that would leave CZL's browser cookies behind.
    # After upstream login, resume the entire original OAuth request, never
    # send the upstream code directly to muxi or bypass application consent.
    endpoint = urllib.parse.urlsplit(settings.czl_authorize_endpoint)
    if (endpoint.scheme, endpoint.netloc, endpoint.path) != (
        "https", "connect.czl.net", "/oauth2/authorize"
    ) or endpoint.query or endpoint.fragment:
        raise ExternalOAuthError("CZL 直达登录需要使用官方 OAuth2 授权端点")
    direct_params = {"redirect": authorization}
    if provider == "wechat":
        # Match device routing used by CZL's own login page.
        mobile = re.search(
            r"Mobile|Android|iPhone|iPad|iPod|BlackBerry|Windows Phone|Opera Mini|IEMobile|Xiaomi|Huawei|Vivo|Oppo",
            user_agent,
            re.IGNORECASE,
        )
        direct_params["device"] = "mobile" if mobile else "pc"
    return (
        f"https://connect.czl.net/api/auth/upstream/{provider}?"
        + urllib.parse.urlencode(direct_params)
    )


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


def _find_upstream_subject(profile: dict[str, Any], provider: str) -> str | None:
    return verified_upstream_subject(profile, provider)


def exchange_profile(provider: str, code: str, code_verifier: str) -> ExternalProfile:
    if provider in OIDC_PROVIDERS:
        if not provider_status()[provider]:
            raise ExternalOAuthError(f"{PROVIDER_NAMES[provider]} 登录尚未配置")
        return _oidc_exchange(provider, code, code_verifier)
    if provider not in CZL_PROVIDERS:
        raise ExternalOAuthError("不支持的第三方登录方式")
    if not provider_status()[provider]:
        raise ExternalOAuthError("第三方登录尚未配置")

    token = _exchange_token(code, code_verifier)
    profile = _userinfo(str(token["access_token"]))
    sub = str(profile.get("sub") or profile.get("id") or "").strip()
    if not sub:
        raise ExternalOAuthError("CZL Connect userinfo 缺少稳定用户标识")
    upstream = _find_upstream_subject(profile, provider)
    if not upstream:
        raise ExternalIdentityUnclear("未能确认所选 QQ/微信身份，请在 CZL 绑定对应渠道后重试")

    nickname = str(
        profile.get("nickname") or profile.get("name") or profile.get("username") or ""
    ).strip() or None
    return ExternalProfile(
        provider=provider,
        subject=f"czl:{sub}",
        nickname=nickname,
        raw_profile=profile,
        upstream_subject=upstream,
    )


# ── Microsoft / Google: direct OpenID Connect, no broker ──────────────────────

@dataclass(frozen=True)
class OidcProvider:
    authorize: str
    token: str
    issuer: re.Pattern
    client_id: str
    client_secret: str


def _oidc(provider: str) -> OidcProvider:
    if provider == "microsoft":
        tenant = (settings.microsoft_tenant or "common").strip()
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,64}", tenant):
            raise ExternalOAuthError("Microsoft 租户配置无效")
        base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
        return OidcProvider(f"{base}/authorize", f"{base}/token",
                            re.compile(r"https://login\.microsoftonline\.com/[0-9a-f-]{36}/v2\.0"),
                            settings.microsoft_client_id, settings.microsoft_client_secret)
    if provider == "google":
        return OidcProvider("https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
                            re.compile(r"(https://)?accounts\.google\.com"),
                            settings.google_client_id, settings.google_client_secret)
    raise ExternalOAuthError("不支持的第三方登录方式")


def _oidc_authorize(provider: str, state: str, code_verifier: str, binding: bool) -> str:
    config = _oidc(provider)
    params = {
        "client_id": config.client_id,
        "redirect_uri": settings.external_redirect_uri(provider),
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": pkce_s256(code_verifier),
    }
    if binding:
        # Always let the user pick which account to bind, never silently reuse one.
        params["prompt"] = "select_account"
    return f"{config.authorize}?{urllib.parse.urlencode(params)}"


def _id_token_claims(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception as error:
        raise ExternalOAuthError("身份令牌无效") from error
    if not isinstance(claims, dict):
        raise ExternalOAuthError("身份令牌无效")
    return claims


def _oidc_exchange(provider: str, code: str, code_verifier: str) -> ExternalProfile:
    config = _oidc(provider)
    name = PROVIDER_NAMES[provider]
    request = urllib.request.Request(
        config.token,
        data=urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "redirect_uri": settings.external_redirect_uri(provider),
            "code_verifier": code_verifier,
        }).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        token = _json_request(request)
    except ExternalOAuthError as error:
        raise ExternalOAuthError(f"{name} 登录失败：{error}") from error
    # The ID token comes straight from the provider's token endpoint over TLS with
    # our client secret (OIDC Core 3.1.3.7), so its claims are checked, not its signature.
    claims = _id_token_claims(str(token.get("id_token") or ""))
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if config.client_id not in audiences:
        raise ExternalOAuthError(f"{name} 身份令牌不是发给本站的")
    if not config.issuer.fullmatch(str(claims.get("iss") or "")):
        raise ExternalOAuthError(f"{name} 身份令牌签发方不正确")
    try:
        expired = float(claims.get("exp", 0)) < time.time() - 60
    except (TypeError, ValueError):
        expired = True
    if expired:
        raise ExternalOAuthError(f"{name} 身份令牌已过期")
    sub = str(claims.get("sub") or "").strip()
    if not sub or len(sub) > 255:
        raise ExternalOAuthError(f"{name} 没有返回稳定的用户标识")
    nickname = str(claims.get("name") or claims.get("given_name") or "").strip()[:64] or None
    profile = {key: claims[key] for key in ("sub", "name", "email", "email_verified", "tid", "iss") if key in claims}
    return ExternalProfile(
        provider=provider,
        subject=f"{provider}:{sub}",
        nickname=nickname,
        raw_profile=profile,
        upstream_subject=f"sub:{sub}",
    )
