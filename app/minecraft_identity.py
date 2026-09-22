"""Stable offline game identity; a display name is never a login identifier."""
from __future__ import annotations

import hashlib
import re
import unicodedata
import uuid


def game_identity(uid: int, nickname: str) -> dict:
    if type(uid) is not int or not 10000 <= uid <= 9999999999999999:
        raise ValueError("UID is outside the Minecraft login-name range")
    name = str(uid)
    # Match Java UUID.nameUUIDFromBytes exactly, not UUID3(namespace, name).
    offline = uuid.UUID(bytes=hashlib.md5(("OfflinePlayer:" + name).encode("utf-8")).digest(), version=3)
    display = "".join(c for c in unicodedata.normalize("NFC", nickname) if not unicodedata.category(c).startswith("C") and c != "§").strip()
    display = re.sub(r"\s+", " ", display)[:64].strip() or name
    return {"uid": uid, "loginName": name, "offlineUuid": str(offline), "displayName": display}
