from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import main
from app.security import token_hash, utc_now
from app.store import Store, iso
from app.terminal_access import TerminalAccessStore


class TerminalAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name)/'auth.db')
        self.bindings = TerminalAccessStore(self.store)
        self.settings = replace(main.settings, terminal_sso_enabled=True, terminal_legacy_enabled=False,
            terminal_sso_server_key='synthetic-shared-service-key-32-characters', minecraft_profile_key='identity-authority-32-characters-only')
        self.store.seed_client(self.settings.bmc_launcher_client_id,'Native','public',['http://127.0.0.1/callback'],['openid','profile'])
        self.accounts=[]
        self.access=[]
        for name in ('Bind_A','Bind_B'):
            account, verification = self.store.register(name.lower()+'@example.com',name,name,'fixture-password-131')
            account = self.store.verify_email(verification)
            self.accounts.append(account)
            self.access.append(self.store.issue_access_token(account.id,self.settings.bmc_launcher_client_id,'openid profile',3600))
        self.patches=[patch.object(main,'store',self.store),patch.object(main,'terminal_access',self.bindings),patch.object(main,'settings',self.settings)]
        for item in self.patches:item.start()
        self.client=TestClient(main.app)
        self.request_id=str(uuid.uuid4())
        self.session=str(uuid.uuid4())
        self.headers={'x-muxi-server-key':self.settings.terminal_sso_server_key}

    def tearDown(self):
        self.client.close()
        for item in reversed(self.patches):item.stop()
        self.temp.cleanup()

    def body(self):return {'uid':self.accounts[0].uid,'requestId':self.request_id,'gameSession':self.session}
    def create(self,**kwargs):return self.client.post('/api/internal/minecraft/terminal-context/create',json=kwargs.get('body',self.body()),headers=kwargs.get('headers',self.headers))
    def bind(self,token=None,**kwargs):return self.client.post('/api/launcher/minecraft/terminal-context/bind',
        json=kwargs.get('body',{'requestId':self.request_id,'gameSession':self.session}),headers={'authorization':'Bearer '+(token or self.access[0])})
    def claim(self):return self.client.post('/api/internal/minecraft/terminal-context/claim',json=self.body(),headers=self.headers)
    def status(self):return self.client.post('/api/internal/minecraft/terminal-context/status',json={'uid':self.accounts[0].uid,'gameSession':self.session},headers=self.headers)
    def disconnect(self):return self.client.post('/api/internal/minecraft/terminal-context/disconnect',json={'uid':self.accounts[0].uid,'gameSession':self.session},headers=self.headers)

    def test_existing_access_is_only_account_credential_no_new_tokens_or_cookies(self):
        with self.store.connect() as db:before=db.execute('SELECT COUNT(*) FROM access_tokens').fetchone()[0]
        for response in (self.create(),self.bind(),self.claim()):
            self.assertEqual(200,response.status_code)
            self.assertEqual(self.accounts[0].uid,response.json()['uid'])
            self.assertEqual(self.request_id,response.json()['requestId'])
            self.assertEqual(self.session,response.json()['gameSession'])
            self.assertFalse({'token','access_token','refresh_token','credential','proof','ticket'} & set(response.json()))
            self.assertNotIn('set-cookie',response.headers)
            self.assertEqual('no-store',response.headers['cache-control'])
        self.assertTrue(self.status().json()['authenticated'])
        with self.store.connect() as db:self.assertEqual(before,db.execute('SELECT COUNT(*) FROM access_tokens').fetchone()[0])

    def test_unbound_request_or_other_account_cannot_authorize_uid(self):
        self.assertEqual(200,self.create().status_code)
        self.assertEqual(401,self.claim().status_code)
        self.assertEqual(401,self.bind(self.access[1]).status_code)
        self.assertEqual(200,self.bind().status_code)
        self.assertEqual(200,self.claim().status_code)

    def test_plain_uuid_is_never_account_authentication(self):
        self.assertEqual(200,self.create().status_code)
        self.assertEqual(401,self.bind(self.request_id).status_code)
        self.assertEqual(401,self.bind(self.session).status_code)
        self.assertFalse(self.status().json()['authenticated'])

    def test_service_authority_cannot_be_replaced_by_access_or_identity_key(self):
        for key in ('',self.access[0],self.settings.minecraft_profile_key):
            self.assertEqual(401,self.create(headers={'x-muxi-server-key':key}).status_code)
        with patch.object(main,'settings',replace(self.settings,terminal_sso_server_key=self.settings.minecraft_profile_key)):
            self.assertEqual(503,self.create().status_code)

    def test_source_revoke_between_bind_and_claim_fails_closed(self):
        self.create();self.bind()
        with self.store.connect() as db:db.execute('UPDATE access_tokens SET revoked_at=? WHERE token_hash=?',(iso(utc_now()),token_hash(self.access[0])))
        self.assertEqual(401,self.claim().status_code)
        self.assertFalse(self.status().json()['authenticated'])

    def test_source_expiry_or_revoke_after_claim_revokes_connection(self):
        self.create();self.bind();self.claim()
        with self.store.connect() as db:db.execute('UPDATE access_tokens SET expires_at=? WHERE token_hash=?',(iso(utc_now()-timedelta(seconds=1)),token_hash(self.access[0])))
        self.assertFalse(self.status().json()['authenticated'])

    def test_request_and_game_session_are_bound_and_claim_consumed_once(self):
        self.create()
        self.assertEqual(401,self.bind(body={'requestId':self.request_id,'gameSession':str(uuid.uuid4())}).status_code)
        self.assertEqual(200,self.bind().status_code)
        self.assertEqual(401,self.bind().status_code)
        self.assertEqual(200,self.claim().status_code)
        self.assertEqual(401,self.claim().status_code)

    def test_expired_context_does_not_accept_valid_access(self):
        self.create()
        with self.store.connect() as db:db.execute('UPDATE terminal_access_requests SET expires_at=?',(iso(utc_now()-timedelta(seconds=1)),))
        self.assertEqual(401,self.bind().status_code)
        self.assertEqual(401,self.claim().status_code)

    def test_disconnect_blocks_delayed_bind_claim_and_create(self):
        self.create();self.bind();self.claim()
        self.assertEqual(200,self.disconnect().status_code)
        self.assertFalse(self.status().json()['authenticated'])
        self.assertEqual(401,self.bind().status_code)
        self.assertEqual(401,self.claim().status_code)
        self.request_id=str(uuid.uuid4())
        self.assertEqual(401,self.create().status_code)

    def test_native_revoke_keeps_live_connection_rebindable_but_disconnect_does_not(self):
        self.create();self.bind();self.claim()
        response=self.client.post('/api/internal/minecraft/terminal-context/revoke',
            json={'uid':self.accounts[0].uid,'gameSession':self.session},headers=self.headers)
        self.assertEqual(200,response.status_code)
        self.assertFalse(self.status().json()['authenticated'])
        self.request_id=str(uuid.uuid4())
        self.assertEqual(200,self.create().status_code)
        self.assertEqual(200,self.bind().status_code)
        self.assertEqual(200,self.claim().status_code)
        self.assertTrue(self.status().json()['authenticated'])
        self.disconnect();self.request_id=str(uuid.uuid4())
        self.assertEqual(401,self.create().status_code)

    def test_profile_and_role_fields_are_rejected_not_used_as_identity(self):
        for body in ({**self.body(),'role':'admin'},{**self.body(),'profileName':'10000'}):
            self.assertEqual(422,self.create(body=body).status_code)
        self.create()
        self.assertEqual(422,self.bind(body={'requestId':self.request_id,'gameSession':self.session,'uid':self.accounts[1].uid}).status_code)

    def test_legacy_credentials_are_not_minted_by_default(self):
        response=self.client.post('/api/launcher/minecraft/terminal-bootstrap',headers={'authorization':'Bearer '+self.access[0]})
        self.assertEqual(410,response.status_code)
        response=self.client.post('/api/launcher/minecraft/terminal-proof',json={'challenge':'A'*43,'requestId':self.request_id},headers={'authorization':'MuxiTerminal '+self.access[0]})
        self.assertEqual(410,response.status_code)


if __name__=='__main__':unittest.main()
