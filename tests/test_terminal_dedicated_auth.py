from dataclasses import replace
from unittest.mock import patch
import unittest

import test_terminal_sso as fixtures


class TerminalDedicatedAuthorityTests(unittest.TestCase):
    setUp=fixtures.TerminalSsoTests.setUp
    tearDown=fixtures.TerminalSsoTests.tearDown
    proof=fixtures.TerminalSsoTests.proof
    ticket=fixtures.TerminalSsoTests.ticket
    exchange=fixtures.TerminalSsoTests.exchange
    def payload(self, proof=None):
        return {"proof": proof or self.proof(), "uid": self.account.uid,
                "requestId": self.request_id, "gameSession": self.game_session}

    def post(self, route, body, key):
        return self.client.post("/api/internal/minecraft/"+route, json=body,
                                headers={"X-Muxi-Server-Key":key})

    def test_identity_social_and_missing_credentials_never_authorize_terminal_routes(self):
        body=self.payload()
        for key in ("", self.settings.minecraft_profile_key, "f"*32, "unconfigured-other-key-32-characters"):
            self.assertEqual(401,self.post("terminal-ticket",body,key).status_code)
            self.assertEqual(401,self.post("terminal-disconnect",body,key).status_code)
        result=self.post("terminal-ticket",body,self.settings.terminal_sso_server_key)
        self.assertEqual(200,result.status_code)
        self.assertEqual(self.account.uid,result.json()["uid"])
        self.assertEqual(self.request_id,result.json()["requestId"])
        self.assertEqual(self.game_session,result.json()["gameSession"])
        self.assertEqual(30,result.json()["expiresInSeconds"])
        self.assertEqual("no-store",result.headers["cache-control"])
        self.assertEqual(200,self.exchange(result.json()["ticket"]).status_code)

    def test_terminal_and_social_keys_cannot_query_identity_or_consume_join_grants(self):
        for key in (self.settings.terminal_sso_server_key, "f"*32):
            headers={"X-Muxi-Server-Key":key}
            self.assertEqual(401,self.client.get(f"/api/internal/minecraft/identity/{self.account.uid}",headers=headers).status_code)
            self.assertEqual(401,self.client.post(f"/api/internal/minecraft/join/{self.account.uid}",headers=headers).status_code)
        self.assertEqual(200,self.client.get(f"/api/internal/minecraft/identity/{self.account.uid}",
            headers={"X-Muxi-Server-Key":self.settings.minecraft_profile_key}).status_code)

    def test_no_key_fallback_for_unconfigured_invalid_or_reused_authority(self):
        body=self.payload()
        for invalid in ("", "short", "x"*513, "x"*31+" ", "x"*31+"\u00e9", self.settings.minecraft_profile_key):
            with patch.object(__import__('app.main',fromlist=['settings']),"settings",replace(self.settings,terminal_sso_server_key=invalid)):
                self.assertEqual(503,self.post("terminal-ticket",body,self.settings.minecraft_profile_key).status_code)
                self.assertEqual(503,self.post("terminal-disconnect",body,self.settings.minecraft_profile_key).status_code)
        self.assertEqual(200,self.post("terminal-ticket",body,self.settings.terminal_sso_server_key).status_code)

    def test_dedicated_http_disconnect_revokes_ticket_and_blocks_delayed_issuance(self):
        result=self.post("terminal-ticket",self.payload(),self.settings.terminal_sso_server_key)
        self.assertEqual(200,result.status_code)
        body={"uid":self.account.uid,"gameSession":self.game_session}
        self.assertEqual(200,self.post("terminal-disconnect",body,self.settings.terminal_sso_server_key).status_code)
        self.assertEqual(401,self.exchange(result.json()["ticket"]).status_code)
        self.assertEqual(401,self.post("terminal-ticket",self.payload(),self.settings.terminal_sso_server_key).status_code)

    def test_verified_uid_cannot_be_replaced_by_supplied_profile_or_role(self):
        body=self.payload()
        body['uid']=self.account.uid+1
        self.assertIn(self.post("terminal-ticket",body,self.settings.terminal_sso_server_key).status_code,(401,404))
        body['uid']=self.account.uid;body['role']='admin'
        result=self.post("terminal-ticket",body,self.settings.terminal_sso_server_key)
        self.assertEqual(200,result.status_code)
        self.assertEqual(self.account.uid,result.json()['uid'])
        self.assertEqual('player',self.exchange(result.json()['ticket']).json()['user']['role'])

    def test_dedicated_key_is_excluded_from_settings_repr(self):
        self.assertNotIn(self.settings.terminal_sso_server_key,repr(self.settings))
