"""Check production provider availability and redirects, without logging in."""
from __future__ import annotations

import argparse
import json
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_redirect(provider: str, status: int, location: str, issuer: str) -> None:
    url = urlsplit(location)
    query = parse_qs(url.query)
    sensitive = {"client_secret", "code_verifier", "access_token", "refresh_token", "id_token"}
    if status != 303 or (url.scheme, url.netloc) != ("https", "connect.czl.net"):
        raise ValueError("Third-party login did not redirect to CZL")
    if sensitive.intersection(query):
        raise ValueError("A credential must never appear in the authorization URL")
    if url.path.startswith("/api/auth/upstream/"):
        if url.path != f"/api/auth/upstream/{provider}" or len(query.get("redirect", [])) != 1:
            raise ValueError("CZL direct provider entry or continuation is incorrect")
        if provider == "wechat" and query.get("device") not in (["pc"], ["mobile"]):
            raise ValueError("CZL WeChat device routing is incorrect")
        url = urlsplit(query["redirect"][0])
        query = parse_qs(url.query)
    expected = {
        "response_type": ["code"],
        "redirect_uri": [issuer.rstrip("/") + "/external/czl/callback"],
        "upstream_providers": [provider],
        "code_challenge_method": ["S256"],
    }
    if status != 303 or (url.scheme, url.netloc, url.path) != (
        "https", "connect.czl.net", "/oauth2/authorize"
    ):
        raise ValueError("Third-party login did not redirect to CZL")
    if any(query.get(key) != value for key, value in expected.items()):
        raise ValueError("CZL callback, provider selection or PKCE is incorrect")
    if not all(query.get(key, [""])[0] for key in ("state", "code_challenge", "client_id")):
        raise ValueError("CZL authorization is missing required parameters")
    if sensitive.intersection(query):
        raise ValueError("A credential must never appear in the authorization URL")


def check(base: str, issuer: str) -> None:
    opener = build_opener(NoRedirect())
    def get(path: str):
        try:
            return opener.open(Request(base.rstrip("/") + path, headers={
                "Cache-Control": "no-cache", "User-Agent": "muxi-deploy-readiness"
            }), timeout=15)
        except HTTPError as error:
            return error
    with get("/api/external/providers") as response:
        if response.code != 200:
            raise ValueError("Provider availability endpoint failed")
        providers = json.load(response).get("providers", {})
        if any(providers.get(name) is not True for name in ("qq", "wechat")):
            raise ValueError("QQ/WeChat is disabled; deployment is not ready")
    for provider in ("qq", "wechat"):
        with get(f"/external/{provider}/start?continue_to=%2Faccount") as response:
            check_redirect(provider, response.code, response.headers.get("Location", ""), issuer)
    print("CZL readiness passed: QQ/WeChat enabled, both authorization redirects and PKCE verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://account.muxigame.com")
    parser.add_argument("--issuer", default="https://account.muxigame.com")
    args = parser.parse_args()
    try:
        check(args.base_url, args.issuer)
    except Exception:
        raise SystemExit("CZL deployment readiness failed; no authorization codes or credentials were logged.")
