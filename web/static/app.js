'use strict';

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  let body = {};
  try { body = await response.json(); } catch {}
  if (!response.ok) throw new Error(body.detail || body.error_description || '请求失败');
  return body;
}

function showMessage(text, error = false) {
  const el = $('message');
  if (!el) return;
  el.textContent = text;
  el.classList.toggle('error', error);
  el.hidden = false;
}

function continueTarget() {
  const value = new URLSearchParams(location.search).get('continue') || '/account';
  return value.startsWith('/') && !value.startsWith('//') ? value : '/account';
}

function continueQuery() { return encodeURIComponent(continueTarget()); }

function clientLabel() {
  try {
    const target = new URL(continueTarget(), location.origin);
    if (target.pathname !== '/oauth/authorize') return '';
    const client = target.searchParams.get('client_id');
    if (client === 'better-mc-launcher') return 'Better MC Launcher';
    if (client === 'better-mc-web') return 'Better MC';
  } catch {}
  return '';
}

function wireAuthContext() {
  const client = clientLabel();
  const context = $('auth-context');
  if (context && client) {
    context.textContent = `继续使用 ${client}`;
    context.hidden = false;
  }
  document.querySelectorAll('[data-preserve-continue]').forEach((link) => {
    const base = link.getAttribute('href').split('?')[0];
    link.href = `${base}?continue=${continueQuery()}`;
  });
}

async function wireExternalProviders() {
  const buttons = [...document.querySelectorAll('[data-provider]')];
  if (!buttons.length) return;
  let providers = {};
  try {
    providers = (await api('/api/external/providers')).providers || {};
  } catch {}
  for (const button of buttons) {
    const provider = button.dataset.provider;
    const enabled = !!providers[provider];
    button.setAttribute('aria-disabled', enabled ? 'false' : 'true');
    if (enabled) {
      button.href = `/external/${provider}/start?continue_to=${continueQuery()}`;
    } else {
      button.href = '#';
      button.title = '管理员尚未配置该第三方登录方式';
      button.addEventListener('click', (event) => {
        event.preventDefault();
        showMessage(`${provider === 'qq' ? 'QQ' : '微信'} 登录尚未配置`, true);
      });
    }
  }
}

async function loadAccount() {
  try {
    const { user } = await api('/api/account/me');
    if ($('nickname')) $('nickname').textContent = user.nickname || user.username;
    if ($('username')) $('username').textContent = `@${user.username}`;
    if ($('uid')) $('uid').textContent = user.uid;
    if ($('profile-uid')) $('profile-uid').textContent = user.uid;
    if ($('game-name')) $('game-name').textContent = user.gameName;
    if ($('email')) $('email').textContent = user.email || '未绑定';
    if ($('role')) $('role').textContent = user.role;
    if ($('created')) $('created').textContent = new Date(user.createdAt).toLocaleString('zh-CN');
    if ($('profile-nickname')) $('profile-nickname').value = user.nickname || '';
    if ($('profile-username')) $('profile-username').value = user.username || '';
    return user;
  } catch {
    if (location.pathname === '/account') location.href = '/login?continue=%2Faccount';
    return null;
  }
}

if ($('login-form')) {
  $('login-form').onsubmit = async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.currentTarget));
    try {
      await api('/api/account/login', { method: 'POST', body: JSON.stringify(form) });
      location.href = continueTarget();
    } catch (error) {
      showMessage(error.message, true);
    }
  };
  const params = new URLSearchParams(location.search);
  const verified = params.get('verified');
  if (verified) {
    showMessage(
      verified === '1' ? '邮箱验证完成。请登录以继续。' : '验证链接无效或已经过期。',
      verified !== '1',
    );
  }
  if (params.get('external')) showMessage('第三方登录没有完成，请重试。', true);
  wireAuthContext();
  wireExternalProviders();
}

if ($('register-form')) {
  $('register-form').onsubmit = async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.currentTarget));
    try {
      const result = await api(`/api/account/register?continue_to=${continueQuery()}`, {
        method: 'POST',
        body: JSON.stringify(form),
      });
      showMessage(result.message);
      if (result.verificationUrl) {
        const a = document.createElement('a');
        a.href = result.verificationUrl;
        a.textContent = ' 开发模式：立即验证';
        a.style.marginLeft = '8px';
        $('message').appendChild(a);
      }
      event.currentTarget.reset();
    } catch (error) {
      showMessage(error.message, true);
    }
  };
  wireAuthContext();
  wireExternalProviders();
}

if ($('external-complete-form')) {
  const params = new URLSearchParams(location.search);
  const ticket = params.get('ticket') || '';
  (async () => {
    try {
      const signup = await api(`/api/external/signup?ticket=${encodeURIComponent(ticket)}`);
      $('external-provider').textContent = signup.provider === 'qq' ? 'QQ 账户' : '微信账户';
      $('external-nickname').value = signup.nickname || '';
    } catch (error) {
      showMessage(error.message, true);
      $('external-complete-form').hidden = true;
    }
  })();
  $('external-complete-form').onsubmit = async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.currentTarget));
    form.ticket = ticket;
    try {
      const result = await api('/api/external/complete', {
        method: 'POST',
        body: JSON.stringify(form),
      });
      location.href = result.continue || '/account';
    } catch (error) {
      showMessage(error.message, true);
    }
  };
}

if ($('profile-form')) {
  loadAccount();
  $('profile-form').onsubmit = async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.currentTarget));
    try {
      const result = await api('/api/account/profile', {
        method: 'PATCH',
        body: JSON.stringify(form),
      });
      showMessage('资料已保存。Minecraft 游戏名保持不变。');
      const user = result.user;
      $('nickname').textContent = user.nickname;
      $('username').textContent = `@${user.username}`;
    } catch (error) {
      showMessage(error.message, true);
    }
  };
}

if ($('logout')) {
  $('logout').onclick = async () => {
    await api('/api/account/logout', { method: 'POST' });
    location.href = '/login';
  };
}
