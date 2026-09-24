import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app import minecraft_join as grants
from app.main import minecraft_join_consume, minecraft_join_mint


SERVER_KEY = 'k' * 32


def account(uid=10042, nickname='洛可'):
    return SimpleNamespace(uid=uid, nickname=nickname, id=1, subject='s')


class GrantStoreTests(unittest.TestCase):
    def setUp(self):
        grants.reset()

    def test_a_grant_can_only_be_used_once(self):
        grants.mint(10042)
        self.assertTrue(grants.consume(10042))
        # 这一条就是整个机制：旁人重放同一张票拿不到第二次进服机会。
        self.assertFalse(grants.consume(10042))

    def test_grant_does_not_leak_to_another_uid(self):
        grants.mint(10042)
        self.assertFalse(grants.consume(10043))
        self.assertTrue(grants.consume(10042))

    def test_expired_grant_is_refused(self):
        grants.mint(10042)
        with patch.object(grants.time, 'monotonic', return_value=time.monotonic() + grants.GRANT_SECONDS + 1):
            self.assertFalse(grants.consume(10042))
            self.assertEqual(0, grants.outstanding())

    def test_repeated_minting_keeps_one_grant_per_uid(self):
        # 启动器每条连接都换票，服务器列表的状态查询也算。不封顶的话挂着多人游戏
        # 界面就能攒出几百张。
        for _ in range(200):
            grants.mint(10042)
        self.assertEqual(1, grants.outstanding())
        self.assertTrue(grants.consume(10042))
        self.assertFalse(grants.consume(10042))

    def test_invalid_uid_never_becomes_a_grant(self):
        for uid in (True, '10042', 9999, 10000000000000000):
            with self.assertRaises(ValueError):
                grants.mint(uid)
        self.assertEqual(0, grants.outstanding())


class JoinEndpointTests(unittest.TestCase):
    def setUp(self):
        grants.reset()

    def request(self, key=SERVER_KEY, bearer=None):
        headers = [(b'x-muxi-server-key', key.encode())]
        if bearer is not None:
            headers.append((b'authorization', f'Bearer {bearer}'.encode()))
        return Request({'type': 'http', 'headers': headers})

    def body(self, response):
        return json.loads(bytes(response.body).decode())

    def test_mint_then_consume_lets_the_real_player_in(self):
        with patch('app.main.store') as store, patch('app.main.settings', SimpleNamespace(minecraft_profile_key=SERVER_KEY)):
            store.access_token.return_value = (account(), 'client', 'openid profile')
            minted = self.body(minecraft_join_mint(self.request(bearer='good')))
            self.assertEqual({'ok': True, 'uid': 10042, 'loginName': '10042', 'expiresInSeconds': grants.GRANT_SECONDS}, minted)

            store.account_by_uid.return_value = account()
            profile = self.body(minecraft_join_consume(10042, self.request()))
            self.assertEqual('10042', profile['loginName'])
            self.assertEqual('洛可', profile['displayName'])

    def test_guessing_a_uid_without_a_grant_is_refused(self):
        # 冒名的人能拿到 UID（顺号，还在 Tab 补全里），但换不到票。
        with patch('app.main.store') as store, patch('app.main.settings', SimpleNamespace(minecraft_profile_key=SERVER_KEY)):
            store.account_by_uid.return_value = account()
            with self.assertRaises(HTTPException) as caught:
                minecraft_join_consume(10042, self.request())
        self.assertEqual(409, caught.exception.status_code)

    def test_consumed_grant_cannot_be_replayed(self):
        with patch('app.main.store') as store, patch('app.main.settings', SimpleNamespace(minecraft_profile_key=SERVER_KEY)):
            store.access_token.return_value = (account(), 'client', 'openid profile')
            minecraft_join_mint(self.request(bearer='good'))
            store.account_by_uid.return_value = account()
            minecraft_join_consume(10042, self.request())
            with self.assertRaises(HTTPException) as caught:
                minecraft_join_consume(10042, self.request())
        self.assertEqual(409, caught.exception.status_code)

    def test_minting_requires_a_live_access_token(self):
        with patch('app.main.store') as store:
            store.access_token.return_value = None
            with self.assertRaises(HTTPException) as caught:
                minecraft_join_mint(self.request(bearer='expired'))
        self.assertEqual(401, caught.exception.status_code)
        self.assertEqual(0, grants.outstanding())

    def test_consume_requires_the_server_key(self):
        with patch('app.main.store') as store, patch('app.main.settings', SimpleNamespace(minecraft_profile_key=SERVER_KEY)):
            store.account_by_uid.return_value = account()
            grants.mint(10042)
            with self.assertRaises(HTTPException) as caught:
                minecraft_join_consume(10042, self.request(key='wrong-key-but-long-enough-x'))
        self.assertEqual(401, caught.exception.status_code)
        # 密钥不对时票不能被吃掉，否则谁都能拿错密钥把别人的票刷没。
        self.assertEqual(1, grants.outstanding())

    def test_unknown_uid_is_not_told_apart_from_a_missing_grant_by_minting(self):
        with patch('app.main.store') as store, patch('app.main.settings', SimpleNamespace(minecraft_profile_key=SERVER_KEY)):
            store.account_by_uid.return_value = None
            with self.assertRaises(HTTPException) as caught:
                minecraft_join_consume(10042, self.request())
        self.assertEqual(404, caught.exception.status_code)


if __name__ == '__main__':
    unittest.main()
