from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.avatar import MAX_BYTES, image_kind, validate
from app.store import Store

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
WEBP = b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 64
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


class AvatarRuleTests(unittest.TestCase):
    def test_type_comes_from_the_bytes_not_the_upload(self):
        self.assertEqual("image/png", validate(PNG)[0])
        self.assertEqual("image/jpeg", validate(JPEG)[0])
        self.assertEqual("image/webp", validate(WEBP)[0])

    def test_svg_is_refused(self):
        # SVG 是能带 <script> 的 XML 文档，浏览器会当页面执行。
        # 把一份上传者可控的可执行文档挂在自己域名下，收益为零。
        with self.assertRaises(ValueError):
            validate(SVG)
        self.assertIsNone(image_kind(SVG))

    def test_a_png_header_glued_onto_anything_is_still_served_as_png(self):
        # 提醒后人：魔数只保证浏览器按 PNG 解析，不保证内容是张好图。
        # 安全性靠的是"绝不按上传者说的类型回给别人"，不是靠这段字节真是图片。
        self.assertEqual("image/png", validate(PNG + SVG)[0])

    def test_oversized_and_empty_are_refused(self):
        with self.assertRaises(ValueError):
            validate(PNG + b"\x00" * MAX_BYTES)
        with self.assertRaises(ValueError):
            validate(b"")

    def test_etag_tracks_content(self):
        self.assertEqual(validate(PNG)[1], validate(PNG)[1])
        self.assertNotEqual(validate(PNG)[1], validate(JPEG)[1])


class AccountManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="muxi-auth-")
        self.store = Store(Path(self.tmp.name) / "auth.db")

    def tearDown(self):
        self.tmp.cleanup()

    def external_account(self, username="QQPlayer"):
        """QQ / 微信注册出来的账号：没有密码，也没有邮箱。"""
        ticket = self.store.create_external_signup(
            "qq", f"czl:{username}", "企鹅", "/account",
            raw_profile={"upstreams": []}, upstream_subject=f"openid:{username}",
        )
        account, _continue = self.store.complete_external_signup(ticket, username, "企鹅")
        return account

    # ---- 补绑邮箱 ----

    def test_external_account_starts_without_an_email(self):
        account = self.external_account()
        self.assertIsNone(account.email)
        self.assertFalse(account.email_verified)

    def test_binding_gives_the_account_a_pending_email(self):
        account = self.external_account()
        token = self.store.bind_email(account.id, "qq@example.com")
        refreshed = self.store.account_by_uid(account.uid)
        self.assertEqual("qq@example.com", refreshed.email)
        self.assertFalse(refreshed.email_verified)
        self.assertIsNotNone(self.store.verify_email(token))
        self.assertTrue(self.store.account_by_uid(account.uid).email_verified)

    def test_an_unverified_address_can_be_corrected(self):
        # 打错一个字母的人否则就卡死了：收不到信，也换不掉地址。
        account = self.external_account()
        self.store.bind_email(account.id, "typo@example.com")
        token = self.store.bind_email(account.id, "right@example.com")
        self.assertEqual("right@example.com", self.store.account_by_uid(account.uid).email)
        self.assertIsNotNone(self.store.verify_email(token))

    def test_rebinding_invalidates_the_previous_link(self):
        account = self.external_account()
        stale = self.store.bind_email(account.id, "typo@example.com")
        self.store.bind_email(account.id, "right@example.com")
        self.assertIsNone(self.store.verify_email(stale))

    def test_a_verified_address_cannot_be_swapped_out_here(self):
        # 换掉已验证的邮箱要先证明还握着旧邮箱。混进补绑就是一条接管账号的捷径。
        account = self.external_account()
        token = self.store.bind_email(account.id, "qq@example.com")
        self.store.verify_email(token)
        with self.assertRaises(ValueError):
            self.store.bind_email(account.id, "attacker@example.com")

    def test_an_address_cannot_be_stolen_from_another_account(self):
        taken, _ = self.store.register("taken@example.com", "Owner_1", "本人", "correct-horse-battery")
        account = self.external_account()
        with self.assertRaises(ValueError):
            self.store.bind_email(account.id, "taken@example.com")
        self.assertIsNone(self.store.account_by_uid(account.uid).email)

    # ---- 重发验证信 ----

    def test_resend_works_while_the_address_is_pending(self):
        self.store.register("new@example.com", "Player_1", "玩家", "correct-horse-battery")
        found = self.store.resend_verification("new@example.com")
        self.assertIsNotNone(found)
        account, token = found
        self.assertIsNotNone(self.store.verify_email(token))

    def test_resend_reports_nothing_for_unknown_or_verified_addresses(self):
        # 调用方把这两种都回同一句话，否则这个接口就是个邮箱探测器。
        self.assertIsNone(self.store.resend_verification("nobody@example.com"))
        _, token = self.store.register("done@example.com", "Player_2", "玩家", "correct-horse-battery")
        self.store.verify_email(token)
        self.assertIsNone(self.store.resend_verification("done@example.com"))

    # ---- 头像 ----

    def test_avatar_round_trips_by_uid(self):
        account = self.external_account()
        content_type, etag = validate(PNG)
        self.store.set_avatar(account.id, PNG, content_type, etag)
        data, served_type, served_etag = self.store.avatar(account.uid)
        self.assertEqual((PNG, "image/png", etag), (data, served_type, served_etag))
        self.assertIn(etag, self.store.account_by_uid(account.uid).public()["avatarUrl"])

    def test_replacing_and_clearing_an_avatar(self):
        account = self.external_account()
        self.store.set_avatar(account.id, PNG, *validate(PNG))
        self.store.set_avatar(account.id, JPEG, *validate(JPEG))
        self.assertEqual("image/jpeg", self.store.avatar(account.uid)[1])
        self.store.clear_avatar(account.id)
        self.assertIsNone(self.store.avatar(account.uid))
        self.assertIsNone(self.store.account_by_uid(account.uid).public()["avatarUrl"])

    def test_no_avatar_is_not_an_error(self):
        account = self.external_account()
        self.assertIsNone(self.store.avatar(account.uid))
        self.assertIsNone(self.store.avatar(999999))

    # ---- 注销 ----

    def test_deleting_an_account_takes_its_email_and_avatar_with_it(self):
        account, token = self.store.register("gone@example.com", "Leaver_1", "再见", "correct-horse-battery")
        self.store.verify_email(token)
        self.store.set_avatar(account.id, PNG, *validate(PNG))

        self.assertTrue(self.store.delete_account(account.id))
        self.assertIsNone(self.store.account_by_uid(account.uid))
        self.assertIsNone(self.store.avatar(account.uid))
        # 邮箱也要跟着走，否则本人拿同一个邮箱重新注册会撞上一条孤儿记录。
        second, _ = self.store.register("gone@example.com", "Leaver_2", "回来了", "correct-horse-battery")
        self.assertNotEqual(account.uid, second.uid)

    def test_deleting_twice_is_not_an_error_the_second_time(self):
        account, _ = self.store.register("x@example.com", "Twice_1", "两次", "correct-horse-battery")
        self.assertTrue(self.store.delete_account(account.id))
        self.assertFalse(self.store.delete_account(account.id))

    def test_uid_is_never_reused(self):
        # 游戏存档按 UID 推出来的离线 UUID 存。回收 UID 等于把新人扔进别人的身体里。
        first, _ = self.store.register("a@example.com", "First_1", "一", "correct-horse-battery")
        self.store.delete_account(first.id)
        second, _ = self.store.register("b@example.com", "Second_1", "二", "correct-horse-battery")
        self.assertGreater(second.uid, first.uid)


if __name__ == "__main__":
    unittest.main()
