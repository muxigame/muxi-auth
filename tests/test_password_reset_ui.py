from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
APP_JS = WEB / "static" / "app.js"


class Page(HTMLParser):
    def __init__(self, name):
        super().__init__()
        self.tags = []
        self.source = (WEB / name).read_text(encoding="utf-8")
        self.feed(self.source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def one(self, tag, **attrs):
        return next(a for t, a in self.tags if t == tag and all(k in a and a[k] == v for k, v in attrs.items()))


NODE_HARNESS = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const config = JSON.parse(process.argv[2]);
const source = fs.readFileSync(process.argv[1], 'utf8');
const ids = {};
const events = {};
const calls = [];
const histories = [];
const links = [{
  href: '/login', getAttribute() { return '/login'; }, addEventListener() {},
}];
const location = {
  origin: 'https://account.muxigame.com', pathname: config.reset ? '/reset-password' : '/forgot-password',
  search: config.search || '', hash: config.hash || '', href: 'unchanged',
};
function element() {
  return {hidden: true, disabled: false, textContent: '', classList: {toggle() {}}};
}
ids.message = element();
ids['auth-context'] = element();
ids['reset-password-done'] = element();
const button = element();
const form = element();
form.fields = config.fields || {};
form.querySelector = () => button;
form.reset = () => { for (const key of Object.keys(form.fields)) form.fields[key] = ''; };
ids[config.reset ? 'reset-password-form' : 'forgot-password-form'] = form;
const responses = config.responses || [];
const context = {
  URL, URLSearchParams, Array, Object, JSON, Error, location,
  document: {
    getElementById(id) { return ids[id] || null; },
    querySelectorAll(selector) { return selector === '[data-preserve-continue]' ? links : []; },
  },
  window: { addEventListener(name, fn) { (events[name] ||= []).push(fn); } },
  history: { replaceState(state, title, url) { histories.push(url); location.hash = ''; } },
  FormData: function (el) { return Object.entries(el.fields); },
  navigator: { sendBeacon() { throw new Error('Unexpected beacon'); } },
  fetch: async (path, options) => {
    assert.equal(location.hash, '', 'fragment must be cleared before requests');
    calls.push({path, options, payload: JSON.parse(options.body)});
    const response = responses.shift() || {status: 200, body: {ok: true}};
    if (response.networkError) throw new Error('simulated network failure');
    return {ok: response.status >= 200 && response.status < 300,
      status: response.status, json: async () => response.body || {}};
  },
};
for (const name of ['localStorage', 'sessionStorage']) {
  Object.defineProperty(context, name, {get() { throw new Error('Storage must not be used'); }});
}
vm.createContext(context);
vm.runInContext(source, context, {filename: 'app.js'});
const event = {preventDefault() {}, currentTarget: form};
async function submit() { await form.onsubmit(event); }
function assertRequest(call, expectedPath) {
  assert.equal(call.path, expectedPath);
  assert.equal(call.options.method, 'POST');
  assert.equal(call.options.cache, 'no-store');
  assert.equal(call.options.referrerPolicy, 'no-referrer');
  assert.equal(call.options.headers['X-Muxi-Account-Action'], '1');
  assert.equal(call.options.headers['Content-Type'], 'application/json');
}
(async () => {
  if (config.scenario === 'missing') {
    assert.equal(form.hidden, true);
    assert.equal(button.disabled, true);
    await submit();
    assert.equal(calls.length, 0);
    assert.equal(ids.message.textContent, '链接已失效或已使用，请重新申请');
  } else if (config.scenario === 'request') {
    const first = form.onsubmit(event);
    await submit();
    await first;
    assert.equal(calls.length, 1, 'busy form must not submit twice');
    assertRequest(calls[0], '/api/account/password-reset/request');
    assert.deepEqual(calls[0].payload, {email: 'player@example.test'});
    assert.equal(ids.message.textContent, '如果该邮箱关联可找回的账户，我们会发送一封邮件。请稍后检查收件箱和垃圾邮件。');
    assert.equal(button.disabled, false);
  } else if (config.scenario === 'reset') {
    assert.deepEqual(histories, ['/reset-password' + location.search]);
    assert.equal(vm.runInContext('typeof token', context), 'undefined');
    assert.equal(form.hidden, false);
    const first = form.onsubmit(event);
    await submit();
    await first;
    assert.equal(calls.length, 1);
    assertRequest(calls[0], '/api/account/password-reset/confirm');
    assert.deepEqual(calls[0].payload, {token: 'mail-proof-only', password: '  new password  ', password_confirm: '  new password  '});
    assert.equal(form.hidden, true);
    assert.equal(ids['reset-password-done'].hidden, false);
    assert.equal(form.fields.password, '');
    assert.equal(form.fields.password_confirm, '');
    assert.equal(button.disabled, true);
    await submit();
    assert.equal(calls.length, 1, 'successful reset must not be replayed');
    assert.equal(location.href, 'unchanged', 'reset must not automatically log in or redirect');
  } else if (config.scenario === 'retry') {
    await submit();
    assert.equal(button.disabled, false);
    assert.equal(ids.message.textContent, '暂时无法更新密码，请稍后重试。');
    await submit();
    assert.equal(calls.length, 2);
    assert.equal(calls[1].payload.token, 'mail-proof-only', 'manual network retry keeps the proof in memory');
    assert.equal(ids['reset-password-done'].hidden, false);
  } else if (config.scenario === 'invalid') {
    await submit();
    assert.equal(ids.message.textContent, '链接已失效或已使用，请重新申请');
    assert.equal(ids['reset-password-done'].hidden, true);
    assert.equal(location.href, 'unchanged');
  } else if (config.scenario === 'validation') {
    await submit();
    assert.equal(calls.length, 0);
    assert.equal(ids.message.textContent, config.expectedMessage);
  } else if (config.scenario === 'leaving') {
    for (const handler of events.pagehide || []) handler({});
    await submit();
    assert.equal(calls.length, 0);
    assert.equal(form.fields.password, '');
    assert.equal(button.disabled, true);
  } else if (config.scenario === 'navigation') {
    assert.equal(links[0].href, config.expectedHref);
  }
  process.stdout.write('ok');
})().catch(error => { process.stderr.write(error.stack); process.exitCode = 1; });
"""


class PasswordResetPageTests(unittest.TestCase):
    def test_login_has_recovery_link_and_versioned_script(self):
        page = Page("login.html")
        page.one("a", href="/forgot-password", **{"data-preserve-continue": None})
        self.assertIn("找回密码", page.source)
        self.assertIn("?v=identity-20261116", page.one("script")["src"])

    def test_recovery_pages_only_use_same_origin_resources_and_private_metadata(self):
        for name in ("forgot-password.html", "reset-password.html"):
            with self.subTest(page=name):
                page = Page(name)
                page.one("meta", name="referrer", content="no-referrer")
                page.one("meta", **{"http-equiv": "Cache-Control", "content": "no-store"})
                for tag, attrs in page.tags:
                    if tag in ("script", "link", "img", "iframe"):
                        url = attrs.get("src") or attrs.get("href", "")
                        self.assertTrue(url.startswith("/static/") and not url.startswith("//"), url)
                self.assertNotIn('name="token"', page.source)
                self.assertIn('method="post"', page.source)
                self.assertNotIn("data-provider", page.source)

    def test_reset_password_fields_and_success_screen(self):
        page = Page("reset-password.html")
        page.one("form", id="reset-password-form", hidden=None)
        for name in ("password", "password_confirm"):
            field = page.one("input", name=name)
            self.assertEqual(field["type"], "password")
            self.assertEqual(field["minlength"], "10")
            self.assertEqual(field["maxlength"], "128")
            self.assertEqual(field["autocomplete"], "new-password")
        page.one("div", id="reset-password-done", hidden=None)
        self.assertIn("原账户登录状态已失效", page.source)
        page.one("a", href="/login", **{"data-preserve-continue": None})


@unittest.skipUnless(shutil.which("node"), "Node is required to execute the browser script contract")
class PasswordResetScriptTests(unittest.TestCase):
    def run_script(self, **config):
        result = subprocess.run(
            [shutil.which("node"), "-e", NODE_HARNESS, str(APP_JS), json.dumps(config)],
            capture_output=True, text=True, encoding="utf-8", timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok")

    def reset(self, scenario, **extra):
        self.run_script(reset=True, scenario=scenario, hash="#token=mail-proof-only",
                        fields={"password": "  new password  ", "password_confirm": "  new password  "}, **extra)

    def test_request_is_private_and_uses_generic_response(self):
        self.run_script(scenario="request", fields={"email": "player@example.test"}, responses=[{
            "status": 202, "body": {"ok": True, "message": "如果该邮箱关联可找回的账户，我们会发送一封邮件。请稍后检查收件箱和垃圾邮件。"},
        }])

    def test_missing_or_query_only_proof_cannot_submit(self):
        for search in ("", "?token=mail-proof-only"):
            with self.subTest(search=search):
                self.run_script(reset=True, scenario="missing", search=search)

    def test_reset_preserves_password_whitespace_and_cannot_replay_success(self):
        self.reset("reset")

    def test_network_error_allows_manual_retry_without_reloading_proof(self):
        self.reset("retry", responses=[{"networkError": True}, {"status": 200, "body": {"ok": True}}])

    def test_invalid_link_uses_generic_message(self):
        self.reset("invalid", responses=[{"status": 400, "body": {"detail": "private server detail"}}])

    def test_validation_prevents_invalid_or_mismatched_password_requests(self):
        for password, confirmation, message in (
            ("short", "short", "新密码须为 10–128 位。"),
            ("x" * 129, "x" * 129, "新密码须为 10–128 位。"),
            ("new password", "other password", "两次输入的密码不一致。"),
        ):
            with self.subTest(length=len(password)):
                self.run_script(reset=True, scenario="validation", hash="#token=mail-proof-only",
                                fields={"password": password, "password_confirm": confirmation}, expectedMessage=message)

    def test_leaving_clears_sensitive_form_and_memory(self):
        self.reset("leaving")

    def test_continue_links_preserve_safe_paths_and_reject_external_targets(self):
        for target, expected in (
            ("/oauth/authorize?client_id=better-mc-web&scope=openid", "/oauth/authorize?client_id=better-mc-web&scope=openid"),
            ("//outside.example", "/account"),
            ("/\\outside.example", "/account"),
            ("/\n/outside.example", "/account"),
        ):
            from urllib.parse import quote
            with self.subTest(target=target):
                self.run_script(scenario="navigation", search="?continue=" + quote(target, safe=""),
                                expectedHref="/login?continue=" + quote(expected, safe="~()*!.'-"))


if __name__ == "__main__":
    unittest.main()
