import unittest
from types import SimpleNamespace
from unittest.mock import patch
from starlette.requests import Request
from fastapi import HTTPException
from app.minecraft_identity import game_identity
from app.main import minecraft_identity


class MinecraftIdentityTests(unittest.TestCase):
    def request(self, key=''):
        return Request({'type': 'http', 'headers': [(b'x-muxi-server-key', key.encode())]})

    def test_uid_and_uuid_are_stable_across_nickname_changes(self):
        a = game_identity(10000, '洛可')
        b = game_identity(10000, '新的昵称')
        self.assertEqual('10000', a['loginName'])
        self.assertEqual(a['offlineUuid'], b['offlineUuid'])
        self.assertEqual('洛可', a['displayName'])
        self.assertEqual({'uid','loginName','offlineUuid','displayName'}, set(a))

    def test_duplicate_unicode_names_do_not_merge_identity(self):
        self.assertNotEqual(game_identity(10000, '洛可')['offlineUuid'], game_identity(10001, '洛可')['offlineUuid'])

    def test_invalid_uid_rejected(self):
        for uid in (True, '10000', 9999, 10000000000000000):
            with self.assertRaises(ValueError): game_identity(uid, '洛可')

    def test_control_and_format_characters_are_not_forwarded(self):
        name = game_identity(10000, '洛\n可\u202e§')['displayName']
        self.assertEqual('洛可', name)

    def test_endpoint_requires_dedicated_server_key_before_lookup(self):
        with patch('app.main.settings', SimpleNamespace(minecraft_profile_key='x'*48)), patch('app.main.store') as store:
            with self.assertRaises(HTTPException) as error: minecraft_identity(10000, self.request('bad'))
            self.assertEqual(401, error.exception.status_code)
            store.account_by_uid.assert_not_called()

    def test_endpoint_returns_only_display_identity(self):
        with patch('app.main.settings', SimpleNamespace(minecraft_profile_key='x'*48)), patch('app.main.store') as store:
            store.account_by_uid.return_value = SimpleNamespace(uid=10000, nickname='洛可', email='private@example.com')
            result = minecraft_identity(10000, self.request('x'*48))
            self.assertEqual('no-store', result.headers['cache-control'])
            self.assertNotIn(b'private@example.com', result.body)


if __name__ == '__main__': unittest.main()
