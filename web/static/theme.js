// 尽早应用账户页保存的外观选择，避免先闪一下系统配色。只存在本机浏览器里。
(function () {
  var KEY = 'muxi-theme';
  function apply(value) {
    var root = document.documentElement;
    if (value === 'light' || value === 'dark') root.setAttribute('data-theme', value);
    else root.removeAttribute('data-theme');
  }
  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) {}
  apply(saved);
  window.muxiTheme = {
    get: function () {
      try { return localStorage.getItem(KEY) || 'system'; } catch (e) { return 'system'; }
    },
    set: function (value) {
      try {
        if (value === 'light' || value === 'dark') localStorage.setItem(KEY, value);
        else localStorage.removeItem(KEY);
      } catch (e) {}
      apply(value);
    },
  };
})();
