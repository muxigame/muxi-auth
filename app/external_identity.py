"""Provider-specific identity extraction from CZL's verified userinfo response."""
def upstream_subject(profile: dict, provider: str) -> str | None:
    if not isinstance(profile, dict):
        return None
    aliases = {"wx": "wechat", "weixin": "wechat", "we_chat": "wechat", "qqconnect": "qq"}
    matches = set()
    for item in profile.get("upstreams", []) if isinstance(profile.get("upstreams"), list) else []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("upstream_type") or item.get("provider") or item.get("type") or item.get("platform") or item.get("name") or "").lower()
        if aliases.get(kind, kind) != provider:
            continue
        data = item.get("provider_data")
        data = data if isinstance(data, dict) else {}
        # Prefer the provider's stable subject, never an untyped CZL connection-row id.
        for key, value in [("upstream_user_id", item.get("upstream_user_id")),
                           *[(k, item.get(k) or data.get(k)) for k in ("unionid", "openid", "sub", "subject", "uid", "user_id", "id")]]:
            if value is not None and str(value).strip():
                matches.add(f"{key}:{str(value).strip()}")
                break
    return next(iter(matches)) if len(matches) == 1 else None
