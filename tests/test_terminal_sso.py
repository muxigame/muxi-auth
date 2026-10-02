import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import main
from app.security import pkce_s256, token_hash, utc_now
from app.store import Store, iso
from app.terminal_sso import TerminalSsoStore, TICKET_SECONDS, PROOF_SECONDS, BOOTSTRAP_SECONDS, TARGET


class TerminalSsoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="terminal-sso-")
        self.db = Path(self.tmp.name)/"test.db"
        self.store = Store(self.db)
        self.sso = TerminalSsoStore(self.store)
        self.client_id = main.settings.bmc_launcher_client_id
        self.web_secret="synthetic-platform-secret-32-characters"
        self.store.seed_client(main.settings.bmc_web_client_id,"Website","confidential",["https://mc.muxigame.com/api/v1/auth/callback"],["openid","profile"],self.web_secret)
        self.web_auth="Basic "+base64.b64encode((main.settings.bmc_web_client_id+":"+self.web_secret).encode()).decode()
        self.store.seed_client(self.client_id, "Native", "public", ["http://127.0.0.1/callback"], ["openid", "profile"])
        account, verify = self.store.register("test@example.com", "Player_1", "Player", "correct-horse-battery")
        self.account = self.store.verify_email(verify)
        self.access = "synthetic-access-token-for-isolated-test"
        now = utc_now()
        with self.store.connect() as db:
            db.execute("INSERT INTO access_tokens VALUES(?,?,?,?,?,?,NULL)",
                (token_hash(self.access), account.id, self.client_id, "openid profile", iso(now), iso(now+timedelta(hours=2))))
        self.settings = replace(main.settings, terminal_sso_enabled=True, issuer="https://account.muxigame.com", minecraft_profile_key="s"*32, terminal_sso_server_key="t"*32)
        self.patches = [patch.object(main, "store", self.store), patch.object(main, "terminal_sso", self.sso), patch.object(main, "settings", self.settings)]
        for item in self.patches: item.start()
        self.client = TestClient(main.app, base_url=self.settings.issuer)
        self.request_id = str(uuid.uuid4())
        self.game_session = str(uuid.uuid4())
        self.verifier = "v"*43
        self.bootstrap = self.sso.bootstrap(account.id, self.access)

    def tearDown(self):
        self.client.close()
        for item in reversed(self.patches): item.stop()
        self.tmp.cleanup()

    def proof(self):
        return self.sso.proof(self.bootstrap, pkce_s256(self.verifier), self.request_id)

    def ticket(self):
        return self.sso.ticket(self.proof(), self.account.uid, self.request_id, self.game_session, self.settings.terminal_sso_server_key)

    def exchange(self, ticket, **headers):
        return self.client.post("/api/internal/terminal/exchange", json={"ticket":ticket,"verifier":self.verifier,"requestId":self.request_id,"target":TARGET},
            headers={"Authorization":self.web_auth,**headers})

    def test_real_http_chain_returns_platform_claims_without_auth_cookie(self):
        boot = self.client.post("/api/launcher/minecraft/terminal-bootstrap", headers={"Authorization":"Bearer "+self.access})
        self.assertEqual(200, boot.status_code)
        self.assertEqual(self.account.uid, boot.json()["uid"])
        self.assertEqual(43, len(boot.json()["credential"]))
        proof = self.client.post("/api/launcher/minecraft/terminal-proof", json={"challenge":pkce_s256(self.verifier),"requestId":self.request_id},
            headers={"Authorization":"MuxiTerminal "+boot.json()["credential"]})
        self.assertEqual(200, proof.status_code)
        ticket = self.client.post("/api/internal/minecraft/terminal-ticket", json={"proof":proof.json()["proof"],"uid":self.account.uid,
            "requestId":self.request_id,"gameSession":self.game_session}, headers={"X-Muxi-Server-Key":self.settings.terminal_sso_server_key})
        self.assertEqual(200, ticket.status_code)
        response = self.exchange(ticket.json()["ticket"])
        self.assertEqual(200, response.status_code)
        self.assertNotIn("set-cookie",response.headers)
        self.assertEqual(self.account.uid,response.json()["user"]["muxi_uid"])
        self.assertEqual(self.account.role,response.json()["user"]["role"])
        self.assertEqual(TARGET,response.json()["target"])
        self.assertEqual(main.settings.bmc_web_client_id,response.json()["audience"])
        self.assertEqual("no-store", response.headers["cache-control"])

    def test_arbitrary_uid_or_legacy_join_grant_cannot_authorize_sso(self):
        response = self.client.post("/api/internal/minecraft/terminal-ticket", json={"proof":"x"*43,"uid":self.account.uid,
            "requestId":self.request_id,"gameSession":self.game_session}, headers={"X-Muxi-Server-Key":self.settings.terminal_sso_server_key})
        self.assertEqual(401, response.status_code)

    def test_wrong_account_cannot_consume_proof(self):
        proof = self.proof()
        with self.assertRaises(ValueError): self.sso.ticket(proof, self.account.uid+1, self.request_id, self.game_session, "s"*32)
        self.assertEqual(43, len(self.sso.ticket(proof, self.account.uid, self.request_id, self.game_session, "s"*32)))

    def test_proof_is_single_use(self):
        proof = self.proof()
        self.sso.ticket(proof, self.account.uid, self.request_id, self.game_session, "s"*32)
        with self.assertRaises(ValueError): self.sso.ticket(proof, self.account.uid, self.request_id, self.game_session, "s"*32)

    def test_ticket_is_single_use(self):
        ticket = self.ticket()
        self.assertEqual(200, self.exchange(ticket).status_code)
        self.assertEqual(401, self.exchange(ticket).status_code)

    def test_pkce_and_request_id_are_required(self):
        ticket = self.ticket()
        with self.assertRaises(ValueError): self.sso.exchange(ticket, "w"*43, self.request_id)
        with self.assertRaises(ValueError): self.sso.exchange(ticket, self.verifier, str(uuid.uuid4()))
        self.assertEqual(self.account.id, self.sso.exchange(ticket, self.verifier, self.request_id).id)

    def test_wrong_request_does_not_consume_proof(self):
        proof = self.proof()
        with self.assertRaises(ValueError): self.sso.ticket(proof, self.account.uid, str(uuid.uuid4()), self.game_session, "s"*32)

    def test_expired_bootstrap_fails(self):
        with patch("app.terminal_sso.utc_now", return_value=utc_now()+timedelta(seconds=BOOTSTRAP_SECONDS+1)):
            with self.assertRaises(ValueError): self.proof()

    def test_expired_proof_fails(self):
        proof = self.proof()
        with patch("app.terminal_sso.utc_now", return_value=utc_now()+timedelta(seconds=PROOF_SECONDS+1)):
            with self.assertRaises(ValueError): self.sso.ticket(proof, self.account.uid, self.request_id, self.game_session, "s"*32)

    def test_expired_ticket_fails(self):
        ticket = self.ticket()
        with patch("app.terminal_sso.utc_now", return_value=utc_now()+timedelta(seconds=TICKET_SECONDS+1)):
            with self.assertRaises(ValueError): self.sso.exchange(ticket, self.verifier, self.request_id)

    def test_confidential_platform_client_required_before_consumption(self):
        ticket=self.ticket()
        self.assertEqual(401,self.exchange(ticket,Authorization="").status_code)
        self.assertEqual(401,self.exchange(ticket,Authorization="Basic invalid").status_code)
        self.assertEqual(403,self.exchange(ticket,Origin="https://attacker.example").status_code)
        self.assertEqual(200,self.exchange(ticket).status_code)
        self.assertEqual(405,self.client.get("/api/internal/terminal/exchange").status_code)

    def test_server_key_required_before_proof_consumption(self):
        proof = self.proof()
        body = {"proof":proof,"uid":self.account.uid,"requestId":self.request_id,"gameSession":self.game_session}
        self.assertEqual(401, self.client.post("/api/internal/minecraft/terminal-ticket", json=body).status_code)
        self.assertEqual(200, self.client.post("/api/internal/minecraft/terminal-ticket",json=body,
            headers={"X-Muxi-Server-Key":self.settings.terminal_sso_server_key}).status_code)

    def test_source_token_revocation_disables_exchange(self):
        ticket = self.ticket()
        with self.store.connect() as db: db.execute("UPDATE access_tokens SET revoked_at=? WHERE token_hash=?", (iso(utc_now()),token_hash(self.access)))
        self.assertEqual(401, self.exchange(ticket).status_code)
        with self.assertRaises(ValueError): self.proof()

    def test_source_token_expiration_disables_exchange(self):
        ticket = self.ticket()
        with self.store.connect() as db: db.execute("UPDATE access_tokens SET expires_at=? WHERE token_hash=?", (iso(utc_now()-timedelta(seconds=1)),token_hash(self.access)))
        self.assertEqual(401, self.exchange(ticket).status_code)

    def test_disconnect_revokes_only_that_server_session(self):
        ticket = self.ticket()
        self.sso.disconnect(self.game_session, "different-server-key")
        self.sso.disconnect(str(uuid.uuid4()), self.settings.terminal_sso_server_key)
        self.sso.disconnect(self.game_session, self.settings.terminal_sso_server_key)
        self.assertEqual(401, self.exchange(ticket).status_code)

    def test_disconnect_before_delayed_issuance_fails_closed(self):
        proof=self.proof()
        self.sso.disconnect(self.game_session,self.settings.terminal_sso_server_key)
        with self.assertRaises(ValueError):
            self.sso.ticket(proof,self.account.uid,self.request_id,self.game_session,self.settings.terminal_sso_server_key)

    def test_purpose_and_target_are_fixed(self):
        for field, value in (("target","/admin"),("purpose","other-login")):
            ticket = self.ticket()
            with self.store.connect() as db: db.execute(f"UPDATE terminal_tickets SET {field}=? WHERE ticket_hash=?",(value,token_hash(ticket)))
            self.assertEqual(401, self.exchange(ticket).status_code)

    def test_new_request_invalidates_old_ticket(self):
        ticket = self.ticket()
        self.proof()
        self.assertEqual(401, self.exchange(ticket).status_code)

    def test_cross_worker_concurrent_exchange_has_one_winner(self):
        ticket = self.ticket()
        workers = [TerminalSsoStore(Store(self.db)) for _ in range(8)]
        def exchange(worker):
            try: return worker.exchange(ticket, self.verifier, self.request_id)
            except ValueError: return None
        with ThreadPoolExecutor(max_workers=8) as pool: results = list(pool.map(exchange, workers))
        self.assertEqual(1, sum(value is not None for value in results))

    def test_bootstrap_revocation_cascades_to_ticket(self):
        ticket=self.ticket()
        response=self.client.post("/api/launcher/minecraft/terminal-bootstrap/revoke",headers={"Authorization":"MuxiTerminal "+self.bootstrap})
        self.assertEqual(200,response.status_code)
        self.assertEqual(401,self.exchange(ticket).status_code)
        with self.assertRaises(ValueError): self.proof()

    def test_secrets_are_hashed_and_never_in_redirects(self):
        proof = self.proof()
        ticket = self.sso.ticket(proof,self.account.uid,self.request_id,self.game_session,"s"*32)
        with self.store.connect() as db: dump = "\n".join(db.iterdump())
        for raw in (self.bootstrap, proof, ticket, self.verifier, self.access): self.assertNotIn(raw,dump)
        page = self.client.get("/account")
        for raw in (self.bootstrap, proof, ticket, self.verifier): self.assertNotIn(raw,page.text)

    def test_disabled_feature_falls_back_without_affecting_account_login(self):
        with patch.object(main,"settings",replace(self.settings,terminal_sso_enabled=False)):
            self.assertEqual(404,self.client.post("/api/launcher/minecraft/terminal-bootstrap").status_code)
            self.assertEqual(200,self.client.get("/account").status_code)

    def test_bootstrap_requires_launcher_authentication(self):
        self.assertEqual(401,self.client.post("/api/launcher/minecraft/terminal-bootstrap").status_code)
        with patch.object(main.store,"access_token",return_value=(self.account,"untrusted-client","openid")):
            self.assertEqual(401,self.client.post("/api/launcher/minecraft/terminal-bootstrap",headers={"Authorization":"Bearer "+self.access}).status_code)
