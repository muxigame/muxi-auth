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

let launcherFlow = null;
let launcherFlowLeaving = false;

function launcherFlowFromTarget(target) {
  try {
    const url = new URL(target, location.origin);
    if (url.pathname !== '/oauth/authorize') return null;
    const flow = url.searchParams.get('launcher_flow');
    const secret = url.searchParams.get('launcher_flow_secret');
    return flow && secret ? { flow, secret } : null;
  } catch {
    return null;
  }
}

async function resumeLauncherFlow(target = continueTarget()) {
  const info = launcherFlowFromTarget(target);
  if (!info) return;
  launcherFlow = info;
  launcherFlowLeaving = false;
  try {
    const response = await fetch(
      `/api/launcher/auth-flow/${encodeURIComponent(info.flow)}/resume?secret=${encodeURIComponent(info.secret)}`,
      { method: 'POST', cache: 'no-store' },
    );
    if (!response.ok) launcherFlow = null;
  } catch {}
}

function markLauncherFlowLeaving() {
  launcherFlowLeaving = true;
}

function cancelLauncherFlowOnPageHide() {
  if (!launcherFlow || launcherFlowLeaving) return;
  const url = `/api/launcher/auth-flow/${encodeURIComponent(launcherFlow.flow)}/cancel?secret=${encodeURIComponent(launcherFlow.secret)}`;
  try { navigator.sendBeacon(url); } catch {}
}

window.addEventListener('pagehide', cancelLauncherFlowOnPageHide);

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
  resumeLauncherFlow();
  const client = clientLabel();
  const context = $('auth-context');
  if (context && client) {
    context.textContent = `继续使用 ${client}`;
    context.hidden = false;
  }
  document.querySelectorAll('[data-preserve-continue]').forEach((link) => {
    const base = link.getAttribute('href').split('?')[0];
    link.href = `${base}?continue=${continueQuery()}`;
    link.addEventListener('click', markLauncherFlowLeaving);
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
      button.addEventListener('click', markLauncherFlowLeaving);
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

let account = null;

async function loadAccount() {
  try {
    const { user } = await api('/api/account/me');
    account = user;
    renderAccount(user);
    return user;
  } catch {
    if (location.pathname === '/account') location.href = '/login?continue=%2Faccount';
    return null;
  }
}

function setText(id, value) { const el = $(id); if (el) el.textContent = value; }

function renderAccount(user) {
  setText('nickname', user.nickname || user.username);
  setText('username', `@${user.username}`);
  setText('uid', user.uid);
  setText('game-name', user.gameName);
  setText('role', user.role);
  setText('role-tag', user.role);
  setText('danger-uid', user.uid);
  setText('delete-hint', user.username);
  setText('created', new Date(user.createdAt).toLocaleString('zh-CN'));
  if ($('profile-nickname')) $('profile-nickname').value = user.nickname || '';
  if ($('profile-username')) $('profile-username').value = user.username || '';
  renderAvatar(user);
  renderEmail(user);
}

function renderAvatar(user) {
  const img = $('avatar-img');
  const initial = $('avatar-initial');
  if (!img || !initial) return;
  if (user.avatarUrl) {
    img.src = user.avatarUrl;
    img.hidden = false;
    initial.hidden = true;
  } else {
    img.hidden = true;
    initial.hidden = false;
    // 没有头像就用昵称首字。用 Array.from 取，否则 emoji 和部分汉字会被从中间切断。
    initial.textContent = Array.from(user.nickname || user.username || '?')[0].toUpperCase();
  }
  if ($('avatar-clear')) $('avatar-clear').hidden = !user.avatarUrl;
}

// 邮箱有三种状态，各给一套界面。原先只有一句"未绑定"，用 QQ/微信 注册的人无处可去。
function renderEmail(user) {
  const none = $('email-none');
  if (!none) return;
  const pending = !!user.email && !user.verified;
  const verified = !!user.email && !!user.verified;
  none.hidden = !!user.email;
  $('email-pending').hidden = !pending;
  $('email-verified').hidden = !verified;
  if (pending) setText('email-pending-address', user.email);
  if (verified) setText('email-verified-address', user.email);
  if ($('verify-tag')) $('verify-tag').hidden = !pending;
}

function wireAvatar() {
  const picker = $('avatar-file');
  if (!picker) return;
  $('avatar-pick').onclick = () => picker.click();
  picker.onchange = async () => {
    const file = picker.files && picker.files[0];
    // 每次都清空：选同一个文件两次不会触发 change，用户会以为按钮坏了。
    picker.value = '';
    if (!file) return;
    const body = new FormData();
    body.append('file', file);
    try {
      // 这里不能带 Content-Type：交给浏览器自己填，它要在里面塞 multipart 的 boundary。
      const response = await fetch('/api/account/avatar', { method: 'POST', body });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.detail || '头像上传失败');
      showMessage('头像已更新。');
      await loadAccount();
    } catch (error) {
      showMessage(error.message, true);
    }
  };
  $('avatar-clear').onclick = async () => {
    try {
      await api('/api/account/avatar', { method: 'DELETE' });
      showMessage('头像已移除。');
      await loadAccount();
    } catch (error) {
      showMessage(error.message, true);
    }
  };
}

function wireEmail() {
  const form = $('email-form');
  if (!form) return;
  form.onsubmit = async (event) => {
    event.preventDefault();
    const element = event.currentTarget;
    const body = JSON.stringify(Object.fromEntries(new FormData(element)));
    try {
      const result = await api('/api/account/email', { method: 'POST', body });
      showMessage(`验证邮件已发往 ${result.email}，24 小时内点击信里的链接即可完成绑定。`);
      await loadAccount();
    } catch (error) {
      showMessage(error.message, true);
    }
  };
  $('email-resend').onclick = async () => {
    if (!account || !account.email) return;
    try {
      const result = await api('/api/account/verification/resend', {
        method: 'POST',
        body: JSON.stringify({ email: account.email }),
      });
      showMessage(result.message);
    } catch (error) {
      showMessage(error.message, true);
    }
  };
  // 换邮箱就是回到"没绑"那一屏重填一次；服务端允许覆盖还没验证的地址。
  $('email-change').onclick = () => {
    $('email-pending').hidden = true;
    $('email-none').hidden = false;
    $('email-input').value = '';
    $('email-input').focus();
  };
}

function wireDeleteAccount() {
  const open = $('delete-open');
  if (!open) return;
  const form = $('delete-form');
  open.onclick = () => { open.hidden = true; form.hidden = false; $('delete-username').focus(); };
  $('delete-cancel').onclick = () => { form.hidden = true; open.hidden = false; $('delete-username').value = ''; };
  form.onsubmit = async (event) => {
    event.preventDefault();
    const body = JSON.stringify(Object.fromEntries(new FormData(event.currentTarget)));
    try {
      await api('/api/account', { method: 'DELETE', body });
      // 账号没了，留在这一页只会看到一串请求失败。
      location.href = '/?deleted=1';
    } catch (error) {
      showMessage(error.message, true);
    }
  };
}

if ($('login-form')) {
  $('login-form').onsubmit = async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.currentTarget));
    try {
      await api('/api/account/login', { method: 'POST', body: JSON.stringify(form) });
      markLauncherFlowLeaving();
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

// 注册成功：把表单换成"去收信"。只清空表单的话，页面和没提交过长得一样。
function showRegisterDone(result) {
  const done = $('register-done');
  if (!done) { showMessage(result.message); return; }
  $('register-form').hidden = true;
  document.querySelectorAll('.identity-divider, .identity-social').forEach((el) => { el.hidden = true; });
  $('message').hidden = true;
  $('register-done-email').textContent = result.email || '你的邮箱';
  done.hidden = false;
  registeredEmail = result.email || '';
  if (result.verificationUrl) {
    const link = document.createElement('a');
    link.href = result.verificationUrl;
    link.textContent = '开发模式：立即验证';
    link.className = 'identity-secondary';
    link.addEventListener('click', markLauncherFlowLeaving);
    done.querySelector('.identity-actions').appendChild(link);
  }
}

let registeredEmail = '';

if ($('register-form')) {
  $('register-form').onsubmit = async (event) => {
    event.preventDefault();
    // 先把表单元素接出来再 await。event.currentTarget 只在事件派发期间有效，
    // async 处理器一让出就被置成 null —— 这里原本在 await 之后直接拿它调 reset()，
    // 抛 "Cannot read properties of null"，又被下面的 catch 当成错误显示出来。
    // 结果是注册其实成功了、验证邮件也发了，用户看到的却是一条报错。
    const element = event.currentTarget;
    const form = Object.fromEntries(new FormData(element));
    try {
      const result = await api(`/api/account/register?continue_to=${continueQuery()}`, {
        method: 'POST',
        body: JSON.stringify(form),
      });
      element.reset();
      showRegisterDone(result);
    } catch (error) {
      showMessage(error.message, true);
    }
  };
  $('register-resend').onclick = async () => {
    if (!registeredEmail) return;
    try {
      const result = await api('/api/account/verification/resend', {
        method: 'POST',
        body: JSON.stringify({ email: registeredEmail }),
      });
      showMessage(result.message);
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
      if (signup.continue) resumeLauncherFlow(signup.continue);
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
      markLauncherFlowLeaving();
      location.href = result.continue || '/account';
    } catch (error) {
      showMessage(error.message, true);
    }
  };
}

if ($('profile-form')) {
  loadAccount();
  wireAvatar();
  wireEmail();
  wireDeleteAccount();
  $('profile-form').onsubmit = async (event) => {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.currentTarget));
    try {
      const result = await api('/api/account/profile', {
        method: 'PATCH',
        body: JSON.stringify(form),
      });
      showMessage('资料已保存。游戏登录 UID 不变，在线昵称会自动同步。');
      account = result.user;
      renderAccount(result.user);
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
