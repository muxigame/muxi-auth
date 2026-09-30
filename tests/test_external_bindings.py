import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException, Request, Response
from fastapi.testclient import TestClient
from app import main
from app.external_identity import upstream_subject
from app.external_oauth import ExternalProfile
from app.security import token_hash
from app.store import Store


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'test.db')
        self.account, token = self.store.register('one@example.com', 'PlayerOne', '玩家', 'good-password-123')
        self.store.verify_email(token)
        self.session = self.store.create_web_session(self.account.id, 30)
        self.patch = patch.object(main, 'store', self.store)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.settings = patch.object(main, 'settings', replace(main.settings, issuer='http://testserver'))
        self.settings.start(); self.addCleanup(self.settings.stop)

    def request(self, *, session=None, origin='http://testserver', action=True, ticket=''):
        headers = [(b'cookie', f'muxi_session={session if session is not None else self.session}; muxi_binding_ticket={ticket}'.encode())]
        if origin is not None: headers.append((b'origin', origin.encode()))
        if action: headers.append((b'x-muxi-account-action', b'1'))
        return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': headers})

    def pending(self, provider='qq', subject='czl:one', upstream='openid:one', account=None, session=None, replacing=False):
        account = account or self.account
        session = session or self.session
        expected = self.store.binding_snapshot(account.id, provider, replacing)
        state, _ = self.store.create_external_state(provider, '/account', account_id=account.id, session=session, expected_id=expected)
        context = self.store.consume_external_state_context(state)
        return self.store.prepare_external_binding(context, {'subject': subject, 'upstream_subject': upstream, 'nickname': '<img onerror=alert(1)>', 'raw_profile': {}})

    def bind(self, **kwargs):
        ticket = self.pending(**kwargs)
        self.store.finish_external_binding(ticket, (kwargs.get('account') or self.account).id, kwargs.get('session') or self.session)
        return ticket

    def test_bind_requires_confirmation_and_preserves_uid(self):
        ticket = self.pending()
        self.assertFalse(self.store.external_bindings(self.account.id)['bindings']['qq']['bound'])
        self.store.finish_external_binding(ticket, self.account.id, self.session)
        self.assertEqual(self.account.uid, self.store.external_account('qq', 'czl:one', upstream_subject='openid:one').uid)
        self.assertIsNone(self.store.external_account('wechat', 'czl:one', upstream_subject='openid:one'))

    def test_provider_extraction_uses_real_czl_fields(self):
        p = {'upstreams': [{'id': 42, 'upstream_type': 'wechat', 'upstream_user_id': 'wx-user'}, {'id': 43, 'upstream_type': 'qq', 'upstream_user_id': 'qq-user'}]}
        self.assertEqual('upstream_user_id:qq-user', upstream_subject(p, 'qq'))
        self.assertEqual('upstream_user_id:wx-user', upstream_subject(p, 'wechat'))
        self.assertIsNone(upstream_subject({'upstreams': [{'id': 42}]}, 'qq'))

    def test_ambiguous_provider_subject_fails_closed(self):
        self.assertIsNone(upstream_subject({'upstreams': [{'provider': 'qq', 'openid': 'a'}, {'provider': 'qq', 'openid': 'b'}]}, 'qq'))

    def test_conflict_never_merges_accounts(self):
        self.bind()
        second, _ = self.store.register('two@example.com', 'PlayerTwo', '另一个', 'good-password-123')
        session = self.store.create_web_session(second.id, 30)
        ticket = self.pending(account=second, session=session)
        with self.assertRaisesRegex(ValueError, '其他 muxi'):
            self.store.finish_external_binding(ticket, second.id, session)
        self.assertFalse(self.store.external_bindings(second.id)['bindings']['qq']['bound'])

    def test_cancel_replace_keeps_original(self):
        self.bind()
        ticket = self.pending(subject='czl:new', upstream='openid:new', replacing=True)
        self.store.finish_external_binding(ticket, self.account.id, self.session, cancel=True)
        self.assertIsNotNone(self.store.external_account('qq', 'czl:one', upstream_subject='openid:one'))

    def test_replace_removes_old_login_only_after_confirmation(self):
        self.bind()
        ticket = self.pending(subject='czl:new', upstream='openid:new', replacing=True)
        self.assertIsNotNone(self.store.external_account('qq', 'czl:one', upstream_subject='openid:one'))
        self.store.finish_external_binding(ticket, self.account.id, self.session)
        self.assertIsNone(self.store.external_account('qq', 'czl:one', upstream_subject='openid:one'))
        self.assertIsNotNone(self.store.external_account('qq', 'czl:new', upstream_subject='openid:new'))

    def test_same_identity_is_not_replacement(self):
        self.bind()
        ticket = self.pending(replacing=True)
        with self.assertRaisesRegex(ValueError, '仍是原'):
            self.store.finish_external_binding(ticket, self.account.id, self.session)

    def test_unlink_does_not_revive_via_aggregate_identity(self):
        self.bind()
        self.bind(provider='wechat', upstream='openid:wx')
        self.store.unlink_external(self.account.id, 'qq', self.session)
        self.assertIsNone(self.store.external_account('qq', 'czl:one', upstream_subject='openid:one'))
        self.assertIsNotNone(self.store.external_account('wechat', 'czl:one', upstream_subject='openid:wx'))

    def test_last_passwordless_login_is_protected_even_with_verified_email(self):
        self.bind()
        with self.store.connect() as db: db.execute('UPDATE accounts SET password_hash=NULL WHERE id=?', (self.account.id,))
        with self.assertRaisesRegex(ValueError, '最后一种'):
            self.store.unlink_external(self.account.id, 'qq', self.session)

    def test_password_and_fresh_session_required(self):
        with self.assertRaisesRegex(ValueError, '密码'):
            self.store.authorize_binding_change(self.account.id, self.session, 'wrong')
        self.store.authorize_binding_change(self.account.id, self.session, 'good-password-123')
        with self.store.connect() as db:
            db.execute('UPDATE accounts SET password_hash=NULL')
            db.execute("UPDATE web_sessions SET created_at='2000-01-01T00:00:00+00:00'")
        with self.assertRaisesRegex(ValueError, '10 分钟'):
            self.store.authorize_binding_change(self.account.id, self.session, '')

    def test_confirm_is_single_use_and_wrong_session_cannot_consume(self):
        ticket = self.pending()
        with self.assertRaises(ValueError): self.store.finish_external_binding(ticket, self.account.id, 'wrong')
        self.store.finish_external_binding(ticket, self.account.id, self.session)
        with self.assertRaises(ValueError): self.store.finish_external_binding(ticket, self.account.id, self.session)

    def test_expired_pending_does_not_change_binding(self):
        ticket = self.pending()
        with self.store.connect() as db: db.execute("UPDATE external_binding_pending SET expires_at='2000-01-01T00:00:00+00:00'")
        with self.assertRaises(ValueError): self.store.finish_external_binding(ticket, self.account.id, self.session)
        self.assertFalse(self.store.external_bindings(self.account.id)['bindings']['qq']['bound'])

    def test_stale_concurrent_intent_does_not_overwrite(self):
        a = self.pending(subject='czl:a', upstream='openid:a')
        b = self.pending(subject='czl:b', upstream='openid:b')
        self.store.finish_external_binding(a, self.account.id, self.session)
        with self.assertRaises(ValueError): self.store.finish_external_binding(b, self.account.id, self.session)
        self.assertIsNone(self.store.external_account('qq', 'czl:b', upstream_subject='openid:b'))

    def test_other_sessions_revoked_but_current_survives(self):
        other = self.store.create_web_session(self.account.id, 30)
        self.bind()
        self.assertIsNone(self.store.web_session(other))
        self.assertIsNotNone(self.store.web_session(self.session))

    def test_api_rejects_csrf_and_no_login(self):
        for req in [self.request(origin='https://evil.example'), self.request(action=False), self.request(origin=None), self.request(session='wrong')]:
            with self.assertRaises(HTTPException): main.binding_account(req, mutation=True)

    def test_callback_binds_original_session_not_current_other_account(self):
        state, _ = self.store.create_external_state('qq', '/account', account_id=self.account.id, session=self.session)
        with patch.object(main, 'exchange_profile') as exchange:
            response = main.external_czl_callback(self.request(session='wrong'), state, 'code', '')
            exchange.assert_not_called()
        self.assertIn('session_changed', response.headers['location'])

    def test_callback_prepares_without_binding_or_switching_login(self):
        state, _ = self.store.create_external_state('qq', '/account', account_id=self.account.id, session=self.session)
        profile = ExternalProfile('qq', 'czl:one', 'QQ昵称', {}, 'openid:one')
        with patch.object(main, 'exchange_profile', return_value=profile):
            response = main.external_czl_callback(self.request(), state, 'code', '')
        self.assertEqual('/account?binding=confirm', response.headers['location'])
        self.assertIn('HttpOnly', response.headers['set-cookie'])
        self.assertNotIn('muxi_session=', response.headers['set-cookie'])
        self.assertFalse(self.store.external_bindings(self.account.id)['bindings']['qq']['bound'])

    def test_start_captures_identity_on_server_and_requests_consent(self):
        with patch.object(main, 'external_authorize_url', return_value='https://connect.czl.net/example') as authorize:
            result = main.start_account_binding('qq', main.BindingRequest(password='good-password-123'), self.request())
            args, kwargs = authorize.call_args
            self.assertTrue(kwargs['binding'])
            state = self.store.consume_external_state_context(args[1])
        self.assertEqual(self.account.id, state['account_id'])
        self.assertEqual(token_hash(self.session), state['session_hash'])
        self.assertNotIn('password', result['url'])

    def test_legacy_migration_is_idempotent_and_channel_specific(self):
        profile = {'upstreams': [{'upstream_type': 'qq', 'upstream_user_id': 'legacy'}]}
        with self.store.connect() as db:
            db.execute("INSERT INTO external_identities(account_id,provider,provider_subject,raw_profile,created_at) VALUES(?,'czl','czl:legacy',?,'2026-01-01')", (self.account.id, json.dumps(profile)))
        self.store = Store(self.store.database)
        self.store = Store(self.store.database)
        self.assertTrue(self.store.external_bindings(self.account.id)['bindings']['qq']['bound'])
        self.assertFalse(self.store.external_bindings(self.account.id)['legacy'])
        self.assertIsNone(self.store.external_account('wechat', 'czl:legacy', upstream_subject='upstream_user_id:legacy'))
        self.store.unlink_external(self.account.id, 'qq', self.session)
        self.assertIsNone(self.store.external_account('qq', 'czl:legacy', raw_profile=profile, upstream_subject='upstream_user_id:legacy'))

    def test_changed_upstream_cannot_use_signup_to_take_over_account(self):
        self.bind()
        ticket = self.store.create_external_signup('qq', 'czl:one', 'new', '/account', upstream_subject='openid:someone-else')
        with self.assertRaisesRegex(ValueError, '身份已变化'):
            self.store.complete_external_signup(ticket, 'Attacker', 'wrong')

    def test_http_roundtrip_cookie_scope_and_confirmation(self):
        client = TestClient(main.app, base_url='http://testserver')
        client.cookies.set('muxi_session', self.session)
        headers = {'Origin': 'http://testserver', 'X-Muxi-Account-Action': '1'}
        with patch.object(main, 'external_authorize_url', return_value='https://connect.czl.net/example') as auth:
            response = client.post('/api/account/external/qq/start', json={'password': 'good-password-123'}, headers=headers)
            self.assertEqual(200, response.status_code)
            state = auth.call_args.args[1]
        with patch.object(main, 'exchange_profile', return_value=ExternalProfile('qq', 'czl:one', '企鹅', {}, 'openid:one')):
            response = client.get('/external/czl/callback', params={'state': state, 'code': 'test-only-code'}, follow_redirects=False)
        self.assertEqual(303, response.status_code)
        self.assertEqual('qq', client.get('/api/account/external/pending').json()['pending']['provider'])
        self.assertEqual(403, client.post('/api/account/external/confirm', json={'action': 'confirm'}).status_code)
        self.assertEqual(200, client.post('/api/account/external/confirm', headers=headers, json={'action': 'confirm'}).status_code)
        self.assertIsNone(client.get('/api/account/external/pending').json()['pending'])
        self.assertTrue(client.get('/api/account/external').json()['bindings']['qq']['bound'])
        self.assertEqual(200, client.post('/api/account/external/qq/unlink', headers=headers, json={'password': 'good-password-123'}).status_code)
        self.assertFalse(client.get('/api/account/external').json()['bindings']['qq']['bound'])

    def test_unknown_legacy_is_preserved_not_guessed(self):
        with self.store.connect() as db:
            db.execute("INSERT INTO external_identities(account_id,provider,provider_subject,raw_profile,created_at) VALUES(?,'czl','czl:unknown','{}','2026-01-01')", (self.account.id,))
        upgraded = Store(self.store.database)
        self.assertTrue(upgraded.external_bindings(self.account.id)['legacy'])
        with self.assertRaisesRegex(ValueError, '历史'):
            upgraded.binding_snapshot(self.account.id, 'qq', False)

    def test_old_state_schema_upgrade_keeps_login_state(self):
        with self.store.connect() as db:
            db.execute('DROP TABLE external_oauth_states')
            db.execute('CREATE TABLE external_oauth_states(state_hash TEXT PRIMARY KEY,provider TEXT,code_verifier TEXT,continue_to TEXT,created_at TEXT,expires_at TEXT)')
            db.execute("INSERT INTO external_oauth_states VALUES(?,'qq','verifier','/account','2026-01-01','2099-01-01T00:00:00+00:00')", (token_hash('old-state'),))
        upgraded = Store(self.store.database)
        self.assertEqual(('qq', 'verifier', '/account'), upgraded.consume_external_state('old-state'))

    def test_late_callback_cannot_overwrite_new_binding(self):
        state, _ = self.store.create_external_state('qq', '/account', account_id=self.account.id, session=self.session)
        context = self.store.consume_external_state_context(state)
        self.bind()
        late = self.store.prepare_external_binding(context, {'subject': 'czl:late', 'upstream_subject': 'openid:late', 'nickname': '迟到'})
        with self.assertRaisesRegex(ValueError, '状态已变化'):
            self.store.finish_external_binding(late, self.account.id, self.session)
        self.assertIsNotNone(self.store.external_account('qq', 'czl:one', upstream_subject='openid:one'))

    def test_conflicting_replacement_preserves_old_binding(self):
        self.bind()
        second, _ = self.store.register('two@example.com', 'PlayerTwo', '另一个', 'good-password-123')
        session = self.store.create_web_session(second.id, 30)
        self.bind(account=second, session=session, subject='czl:taken', upstream='openid:taken')
        ticket = self.pending(subject='czl:taken', upstream='openid:taken', replacing=True)
        with self.assertRaises(ValueError):
            self.store.finish_external_binding(ticket, self.account.id, self.session)
        self.assertIsNotNone(self.store.external_account('qq', 'czl:one', upstream_subject='openid:one'))


if __name__ == '__main__': unittest.main()
