# muxi 账户

muxigame 的独立统一账户服务。它同时提供账户官网、OAuth 2.0 Authorization Server 和 OpenID Connect Provider。

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

### CZL Connect 生产配置

本机 `.env` 不进入 Git，也不会随发布归档自动传到服务器。生产凭据必须写入
`/opt/muxi-auth/.env` 的 `MUXI_CZL_CLIENT_ID` 和 `MUXI_CZL_CLIENT_SECRET`；这个文件在
后续部署中持久保留。更换 `.env` 后需要重新创建容器，而不是只改本机文件。

GitHub Actions 支持同名 Secrets 作为可选的完整覆盖对。不设置时保留服务器原值；只设置
其中一项会阻止部署。`scripts/deploy_config.py` 在替换运行中版本之前检查 Compose 解析后的
有效凭据及生产 issuer，覆盖配置前生成私有备份，解析失败自动恢复原文件，不输出密钥值。

生产部署不再仅检查 `/healthz`。还必须通过 `scripts/check_external_auth.py`：QQ、微信
开关均启用、入口返回 CZL 授权跳转、上游渠道与 S256 PKCE 参数正确，回调必须为
`https://account.muxigame.com/external/czl/callback`。此检查不代替真人扫码和授权回调验收。

## 预置客户端

`better-mc-launcher` 是 public native client，不存在 `client_secret`。它使用系统浏览器、Authorization Code + PKCE，并回调到 `127.0.0.1` 的随机端口。

`better-mc-web` 是 confidential web client，需要在 muxi 账户 与 Better MC 网站两边配置相同的高熵 secret。

## 安全边界

Minecraft 本体目前不接 OAuth。Better MC Launcher 登录成功后只把 muxi 用户名传给现有 OfflineAuth，因此游戏服务器侧仍保持当前离线 UUID 逻辑。

