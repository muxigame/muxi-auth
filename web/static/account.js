// 账户中心的页面层：分页导航、外观切换、概览、资料表单的扩展字段、复制 UID。
// 数据和所有写操作仍由 app.js 负责（保存资料时它会把整个 #profile-form 一起提交）；
// 这里只在 app.js 的 renderAccount / loadBindings 之后补充渲染。
(() => {
  if (!document.body.classList.contains('acct-body')) return;
  const byId = (id) => document.getElementById(id);
  const put = (id, value) => { const el = byId(id); if (el) el.textContent = value; };

  // ── 分页（#overview / #profile / …） ─────────────────────────
  const tabs = ['overview', 'profile', 'security', 'game', 'manage'];
  function show(tab) {
    if (!tabs.includes(tab)) tab = 'overview';
    document.querySelectorAll('.acct-page').forEach((page) => { page.hidden = page.dataset.page !== tab; });
    document.querySelectorAll('.acct-nav a').forEach((link) => {
      if (link.dataset.tab === tab) {
        link.setAttribute('aria-current', 'page');
        link.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      } else link.removeAttribute('aria-current');
    });
  }
  // QQ / 微信授权回来是 /account?binding=…，没有 hash；确认面板在「登录与安全」里。
  show(location.hash.slice(1) || (new URLSearchParams(location.search).has('binding') ? 'security' : 'overview'));
  window.addEventListener('hashchange', () => { show(location.hash.slice(1)); window.scrollTo({ top: 0 }); });

  // ── 外观：跟随系统 / 浅色 / 深色 ─────────────────────────────
  const themeButtons = [...document.querySelectorAll('[data-theme-choice]')];
  function markTheme() {
    const current = window.muxiTheme ? window.muxiTheme.get() : 'system';
    themeButtons.forEach((b) => b.setAttribute('aria-checked', String(b.dataset.themeChoice === current)));
  }
  themeButtons.forEach((b) => {
    b.addEventListener('click', () => { if (window.muxiTheme) window.muxiTheme.set(b.dataset.themeChoice); markTheme(); });
  });
  markTheme();

  // ── 轻提示 ──────────────────────────────────────────────────
  const toast = document.createElement('div');
  toast.className = 'acct-toast';
  toast.setAttribute('role', 'status');
  document.body.append(toast);
  let toastTimer = 0;
  function notify(text) {
    toast.textContent = text;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 1800);
  }

  // ── 渲染补充 ────────────────────────────────────────────────
  let user = null;
  let bindings = null;
  const roles = { player: '玩家', user: '玩家', admin: '管理员', owner: '所有者' };
  const date = (value) => {
    if (!value) return '—';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' });
  };
  const when = (value) => {
    if (!value) return '—';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '—';
    const minutes = Math.round((Date.now() - d.getTime()) / 60000);
    if (minutes < 1) return '刚刚';
    if (minutes < 60) return `${minutes} 分钟前`;
    if (minutes < 1440) return `${Math.round(minutes / 60)} 小时前`;
    if (minutes < 1440 * 7) return `${Math.round(minutes / 1440)} 天前`;
    return date(value);
  };

  function avatarInto(imgId, initialId, u) {
    const img = byId(imgId);
    const letter = byId(initialId);
    if (!img || !letter) return;
    if (u.avatarUrl) {
      img.src = u.avatarUrl;
      img.hidden = false;
      letter.hidden = true;
    } else {
      img.hidden = true;
      letter.hidden = false;
      letter.textContent = Array.from(u.nickname || u.username || '?')[0].toUpperCase();
    }
  }

  const profileOf = (u) => ({ bio: '', birthday: null, gender: '', location: '', ...(u && u.profile) });

  function fillProfileForm(u) {
    const p = profileOf(u);
    if (byId('profile-bio')) byId('profile-bio').value = p.bio || '';
    if (byId('profile-birthday')) byId('profile-birthday').value = p.birthday || '';
    if (byId('profile-gender')) byId('profile-gender').value = p.gender || '';
    if (byId('profile-location')) byId('profile-location').value = p.location || '';
    updateBioCount();
  }

  function updateBioCount() {
    const bio = byId('profile-bio');
    if (bio) put('bio-count', Array.from(bio.value).length);
  }

  function renderUser(u) {
    user = u;
    const name = u.nickname || u.username;
    const role = roles[u.role] || u.role || '—';
    const p = profileOf(u);
    put('top-name', name);
    avatarInto('top-avatar-img', 'top-avatar-initial', u);
    avatarInto('profile-avatar-img', 'profile-avatar-initial', u);
    put('hero-email', u.email || '未绑定邮箱');
    const bio = byId('hero-bio');
    if (bio) {
      bio.textContent = p.bio || '还没有个性签名';
      bio.classList.toggle('empty', !p.bio);
    }
    put('role-tag', role);
    put('role', role);
    put('last-login', when(u.lastLoginAt));
    put('joined', date(u.createdAt));
    put('created', date(u.createdAt));
    put('tile-uid', u.uid);
    put('game-display', name);
    put('game-name', u.uid);
    fillProfileForm(u);
    renderMethods();
    renderChecks();
  }

  function renderMethods() {
    if (!user) return;
    const rows = [['email', user.email ? (user.verified ? '已验证' : '待验证') : '未绑定', user.email ? (user.verified ? 'ok' : 'warn') : '']];
    for (const provider of ['qq', 'wechat']) {
      const b = bindings && bindings.bindings && bindings.bindings[provider];
      rows.push([provider, b ? (b.bound ? (b.nickname || '已绑定') : '未绑定') : '—', b && b.bound ? 'ok' : '']);
    }
    let count = 0;
    for (const [method, text, state] of rows) {
      const pill = byId(`method-${method}`);
      if (pill) {
        pill.textContent = text;
        pill.title = text;
        pill.className = state ? `pill pill-${state}` : 'pill';
      }
      if (state === 'ok') count += 1;
    }
    put('methods-summary', count ? `${count} 种` : '仅密码');
  }

  function renderChecks() {
    const list = byId('check-list');
    if (!list || !user) return;
    const bound = bindings ? ['qq', 'wechat'].filter((p) => bindings.bindings && bindings.bindings[p] && bindings.bindings[p].bound).length : 0;
    const methodCount = (user.email && user.verified ? 1 : 0) + bound;
    const p = profileOf(user);
    const checks = [
      { ok: !!(user.email && user.verified), title: '邮箱已验证', okText: '可以用邮箱登录和找回密码', todoText: user.email ? '验证邮件已发出，点击邮件里的链接完成绑定' : '绑定邮箱后才能找回账号', href: '#security', action: user.email ? '去验证' : '绑定邮箱' },
      { ok: methodCount >= 2, title: '备用登录方式', okText: '丢失一种方式时仍能登录', todoText: '再绑定一种 QQ / 微信 / 邮箱', href: '#security', action: '去绑定' },
      { ok: !!user.avatarUrl && !!p.bio, title: '完善资料', okText: '头像和个性签名都已设置', todoText: '设置头像和个性签名，让朋友更容易认出你', href: '#profile', action: '去完善' },
    ];
    list.replaceChildren(...checks.map((c) => {
      const row = document.createElement('div');
      row.className = `row ${c.ok ? 'check-ok' : 'check-todo'}`;
      const icon = document.createElement('span');
      icon.className = 'check-icon';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = c.ok ? '✓' : '!';
      const text = document.createElement('div');
      text.className = 'row-text';
      const title = document.createElement('div');
      title.className = 'row-title';
      title.textContent = c.title;
      const note = document.createElement('div');
      note.className = 'row-desc';
      note.textContent = c.ok ? c.okText : c.todoText;
      text.append(title, note);
      row.append(icon, text);
      if (!c.ok) {
        const link = document.createElement('a');
        link.className = 'acct-btn acct-btn-sm';
        link.href = c.href;
        link.textContent = c.action;
        row.append(link);
      }
      return row;
    }));
    const done = checks.filter((c) => c.ok).length;
    put('check-summary', done === checks.length ? '一切就绪。' : `已完成 ${done} / ${checks.length} 项。`);
  }

  function renderPasswordNote() {
    if (!bindings || !user) return;
    if (bindings.requiresPassword === false) {
      put('password-note', user.email && user.verified
        ? '这个账号还没有设置密码，可以通过已验证的邮箱设置一个。'
        : '这个账号还没有设置密码。先绑定并验证邮箱，再通过邮件设置密码。');
    }
  }

  async function refreshBindings() {
    try {
      const response = await fetch('/api/account/external', { headers: { Accept: 'application/json' } });
      if (!response.ok) return;
      bindings = await response.json();
      renderMethods();
      renderChecks();
      renderPasswordNote();
    } catch { /* 读不到就保持「—」，不影响其它部分 */ }
  }

  // 接在 app.js 的全局函数后面：它每次重画账户或绑定时，这里跟着补一次。
  if (typeof window.renderAccount === 'function') {
    const original = window.renderAccount;
    window.renderAccount = function (u) { original(u); try { renderUser(u); } catch {} };
  }
  if (typeof window.loadBindings === 'function') {
    const original = window.loadBindings;
    window.loadBindings = async function () { const result = await original(); refreshBindings(); return result; };
  }
  // app.js 用顶层 let 声明 account，它是脚本间共享的全局词法绑定，不在 window 上。
  // eslint-disable-next-line no-undef
  const loaded = typeof account !== 'undefined' ? account : null;
  if (loaded) renderUser(loaded);
  else {
    fetch('/api/account/me', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((body) => { if (body && body.user && !user) renderUser(body.user); })
      .catch(() => {});
  }
  refreshBindings();

  // ── 表单辅助 ────────────────────────────────────────────────
  const birthday = byId('profile-birthday');
  if (birthday) birthday.max = new Date().toISOString().slice(0, 10);
  if (byId('profile-bio')) byId('profile-bio').addEventListener('input', updateBioCount);
  if (byId('profile-reset')) {
    byId('profile-reset').addEventListener('click', () => {
      if (!user) return;
      byId('profile-nickname').value = user.nickname || '';
      byId('profile-username').value = user.username || '';
      fillProfileForm(user);
    });
  }

  // ── 页面按钮 ────────────────────────────────────────────────
  document.addEventListener('click', async (event) => {
    const target = event.target.closest('[data-copy-uid], [data-avatar-pick], [data-logout]');
    if (!target) return;
    if (target.hasAttribute('data-copy-uid')) {
      if (!user) return;
      try {
        await navigator.clipboard.writeText(String(user.uid));
        notify(`已复制 UID ${user.uid}`);
      } catch { notify('复制失败，请手动选择 UID'); }
    } else if (target.hasAttribute('data-avatar-pick')) {
      if (byId('avatar-file')) byId('avatar-file').click();
    } else if (target.hasAttribute('data-logout')) {
      if (byId('logout')) byId('logout').click();
    }
  });
})();
