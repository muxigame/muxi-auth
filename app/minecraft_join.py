"""一次性进服票据。

offline-mode 的 Minecraft 不做任何身份校验：谁把用户名填成别人的 UID，服务端就认谁。
UID 是五六位顺号，要撞上一个真实玩家只要从 10000 往上试几十次。密码、加密、换个不好猜
的登录名都救不了这一点——问题不在于名字好不好猜，而在于**名字本身就是凭据**，而名字是
公开的（游戏里 /msg 的 Tab 补全会把在线玩家的登录名全列出来）。

所以服务端不再相信用户名，改成在放人进世界之前问这里一句：
「这个 UID 刚刚有人拿本人的账号换过票吗？」

票由启动器在玩家真正发起连接那一刻换走——它手里有本人的 access token，别人没有。

票是一次性的，也是短命的：

  · 一次性：核销过就没了，同一张票不会被旁人重放
  · 短命  ：只够覆盖「点加入服务器」到「服务端握完手」这几秒

两条合起来，把冒名压缩成「必须在本人正在进服的那几秒里、还要抢在本人前面把票用掉」，
而且一旦被抢，本人当场进不去——是一次看得见的失败，不是悄无声息的盗号。

存内存不存库是有意的：票的寿命以秒计，进程重启后玩家重新点一次加入就又有了，为它建表、
写迁移、清过期行，全是白搭的工程量。

⚠ 这里依赖 muxi-auth 是**单进程**（Dockerfile 的 CMD 里没有 --workers）。谁要给它加
worker，必须先把这份 dict 换成进程间共享的存储，否则票会落在 A 进程、核销请求打到 B
进程，表现是「有时进得去有时进不去」，而且只在高峰期复现。
"""
from __future__ import annotations

import time
from threading import Lock

#: 票的有效期。要盖住「游戏发起连接 → 启动器选路/建隧道 → 服务端握完手」这一整段。
#: 实测建隧道本身家宽 3.0 秒、蜂窝 4.5 秒，赶上服务器正在重启还会更久，所以留得宽一些；
#: 反正一次性这条才是拦人的关键，把有效期压到几秒只会让正常玩家进不去。
GRANT_SECONDS = 180

#: 每个 UID 只留一张票。启动器在每条连接上都换票（服务器列表的状态查询也算一条），
#: 不封顶的话一个挂着多人游戏界面的玩家能攒出成百上千张。后换的覆盖先换的，
#: 玩家视角下没有区别：他点一次加入就现换一张。
_grants: dict[int, float] = {}
_lock = Lock()


def _sweep(now: float) -> None:
    for uid in [uid for uid, expires in _grants.items() if expires <= now]:
        _grants.pop(uid, None)


def mint(uid: int) -> int:
    """给 uid 发一张票，返回有效秒数。调用方必须已经验明身份。"""
    if type(uid) is not int or not 10000 <= uid <= 9999999999999999:
        raise ValueError("UID is outside the Minecraft login-name range")
    now = time.monotonic()
    with _lock:
        _sweep(now)
        _grants[uid] = now + GRANT_SECONDS
    return GRANT_SECONDS


def consume(uid: int) -> bool:
    """核销 uid 的票。有且未过期返回 True，并且这张票就此作废。"""
    if type(uid) is not int:
        return False
    now = time.monotonic()
    with _lock:
        _sweep(now)
        return _grants.pop(uid, None) is not None


def outstanding() -> int:
    """当前还没被用掉、也没过期的票数。给健康检查和测试看。"""
    now = time.monotonic()
    with _lock:
        _sweep(now)
        return len(_grants)


def reset() -> None:
    """只给测试用。"""
    with _lock:
        _grants.clear()
