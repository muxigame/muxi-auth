"""Dedicated terminal server authority; never borrow the identity lookup key."""
import hmac

from fastapi import HTTPException


def terminal_player(settings, store, uid: int, supplied: str):
    key = settings.terminal_sso_server_key
    # A copied identity credential cannot become a terminal credential by configuration.
    if (not 32 <= len(key) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in key)
            or hmac.compare_digest(key.encode(), settings.minecraft_profile_key.encode())):
        raise HTTPException(status_code=503, detail="Terminal server authority is not configured")
    if not supplied or not hmac.compare_digest(supplied.encode(), key.encode()):
        raise HTTPException(status_code=401, detail="Invalid terminal server credential")
    if not 10000 <= uid <= 9999999999999999:
        raise HTTPException(status_code=404, detail="Player not found")
    account = store.account_by_uid(uid)
    if account is None:
        raise HTTPException(status_code=404, detail="Player not found")
    return account
