"""头像图片的校验。

按**文件内容**判类型，不看客户端报的 Content-Type，也不看扩展名——这两样都是上传者
说了算的。服务端随后会用这里判出来的类型回给所有人，认错了就等于让上传者决定别人的
浏览器怎么解析这段字节。

**SVG 一律拒绝。** 它是可以带 <script> 的 XML 文档，浏览器会当页面执行；虽然响应头有
nosniff、而且是同源以外的路径，但把一份用户可控的可执行文档挂在自己域名下，收益为零、
风险不是零。头像只要位图。
"""
from __future__ import annotations

import hashlib

#: 单个头像的上限。头像最终显示成一个几十像素的小圆；给到 512 KB 已经宽得离谱，
#: 再大只是让人往数据库里塞原图。
MAX_BYTES = 512 * 1024

#: 允许的类型。键是魔数判出来的结果，值是回给浏览器的 Content-Type。
KINDS = {
    "png": "image/png",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "gif": "image/gif",
}


def image_kind(data: bytes) -> str | None:
    """按魔数判断图片类型；不认识返回 None。"""
    if len(data) < 12:
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    return None


def validate(data: bytes) -> tuple[str, str]:
    """校验并返回 (content_type, etag)。不合格抛 ValueError。"""
    if not data:
        raise ValueError("图片是空的")
    if len(data) > MAX_BYTES:
        raise ValueError(f"图片不能超过 {MAX_BYTES // 1024} KB")
    kind = image_kind(data)
    if kind is None:
        raise ValueError("只支持 PNG、JPEG、WebP 和 GIF 图片")
    return KINDS[kind], hashlib.sha256(data).hexdigest()[:16]
