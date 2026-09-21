# Muxi Account

MuxiGame 的独立统一账户服务。它同时提供账户官网、OAuth 2.0 Authorization Server 和 OpenID Connect Provider。

## 已实现

- 邮箱注册、邮箱验证、网页登录与 HttpOnly Session Cookie
- Argon2id 密码哈希，稳定且与用户名解耦的 OIDC `sub`
- Authorization Code Flow
- PKCE，且授权端点强制 `S256`
- Native/Public Client 的随机 loopback port 回调
- OIDC discovery、JWKS、RS256 ID Token、UserInfo
- Access Token、Refresh Token rotation、Token revocation
- Better MC Website（confidential client）和 Better MC Launcher（public native client）的预置注册

## 本地启动

```powershell
Copy-Item .env.example .env
# 本地调试时把 MUXI_ISSUER 改成 http://127.0.0.1:9000，并设置 MUXI_AUTH_DEV_VERIFY=1
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 9000
```

生产环境建议由反向代理为 `https://account.muxigame.com` 终止 TLS。`data/oidc-signing.pem` 是 OIDC 身份签名密钥，必须持久化并备份，不能每次部署重建。

## 预置客户端

`better-mc-launcher` 是 public native client，不存在 `client_secret`。它使用系统浏览器、Authorization Code + PKCE，并回调到 `127.0.0.1` 的随机端口。

`better-mc-web` 是 confidential web client，需要在 Muxi Account 与 Better MC 网站两边配置相同的高熵 secret。

## 安全边界

Minecraft 本体目前不接 OAuth。Better MC Launcher 登录成功后只把 Muxi 用户名传给现有 OfflineAuth，因此游戏服务器侧仍保持当前离线 UUID 逻辑。

