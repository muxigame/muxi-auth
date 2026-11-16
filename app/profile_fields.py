"""账户资料里可选、可公开展示的几项：个性签名、生日、性别、所在地。

这些只出现在账户页（/api/account/me），不进 OIDC claims，也不下发给游戏。
空字符串表示「未填」，存储时统一成空串；生日未填存 NULL。
"""
from __future__ import annotations

import re
from datetime import date

FIELDS = ("bio", "birthday", "gender", "location")
GENDERS = ("", "male", "female", "other", "secret")
BIO_MAX = 80
LOCATION_MAX = 32

_CONTROL = re.compile(r"[\u0000-\u001f\u007f  ]")


def _text(value: object, limit: int, label: str, *, multiline: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label}格式不正确")
    text = value.strip()
    if multiline:
        # 签名允许换行，但不允许其他控制字符；连续空行压成一个。
        text = re.sub(r"\r\n?", "\n", text)
        if _CONTROL.search(text.replace("\n", "")):
            raise ValueError(f"{label}包含不支持的字符")
        text = re.sub(r"\n{3,}", "\n\n", text)
    elif _CONTROL.search(text):
        raise ValueError(f"{label}包含不支持的字符")
    if len(text) > limit:
        raise ValueError(f"{label}最多 {limit} 个字")
    return text


def normalize(changes: dict, *, today: date | None = None) -> dict:
    """校验并规范化提交的资料。只返回提交了的键；未知键直接拒绝。"""
    unknown = set(changes) - set(FIELDS)
    if unknown:
        raise ValueError("包含不支持的资料项")
    out: dict = {}
    if "bio" in changes:
        out["bio"] = _text(changes["bio"], BIO_MAX, "个性签名", multiline=True)
    if "location" in changes:
        out["location"] = _text(changes["location"], LOCATION_MAX, "所在地")
    if "gender" in changes:
        gender = changes["gender"]
        if gender not in GENDERS:
            raise ValueError("性别选项不正确")
        out["gender"] = gender
    if "birthday" in changes:
        raw = changes["birthday"]
        if raw in (None, ""):
            out["birthday"] = None
        else:
            if not isinstance(raw, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
                raise ValueError("生日格式应为 YYYY-MM-DD")
            try:
                value = date.fromisoformat(raw)
            except ValueError as error:
                raise ValueError("生日不是有效日期") from error
            if value < date(1900, 1, 1) or value > (today or date.today()):
                raise ValueError("生日超出可选范围")
            out["birthday"] = value.isoformat()
    return out
