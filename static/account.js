/* SecurityWizard account module: login screen, "default credentials" reminder and credential change.
   Self-contained (own strings, own requests); styles live in app.css. All text is set with textContent. */
(function () {
  'use strict';

  var STR = {
    en: {
      loginTitle: 'Sign in to SecurityWizard', username: 'Username', password: 'Password', signIn: 'Sign in', signingIn: 'Signing in...',
      loginFailed: 'Wrong username or password.', tooMany: 'Too many attempts, please wait a minute.', failed: 'Something went wrong.',
      bannerText: 'You are using the default credentials. Please change them.', changeNow: 'Change now', later: 'Remind me later',
      account: 'Account', logout: 'Sign out', changeTitle: 'Change credentials', current: 'Current password', newUser: 'New username (optional)',
      newPass: 'New password (at least 8 characters)', confirmPass: 'Confirm new password', save: 'Save', cancel: 'Cancel',
      mismatch: 'The new passwords do not match.', saved: 'Credentials updated.', hint: 'Default credentials were printed in the server console when it first started.'
    },
    ar: {
      loginTitle: 'تسجيل الدخول إلى SecurityWizard', username: 'اسم المستخدم', password: 'كلمة المرور', signIn: 'دخول', signingIn: 'جارٍ الدخول...',
      loginFailed: 'اسم المستخدم أو كلمة المرور غير صحيحة.', tooMany: 'محاولات كثيرة، يرجى الانتظار دقيقة.', failed: 'حدث خطأ ما.',
      bannerText: 'أنت تستخدم بيانات الدخول الافتراضية. يُرجى تغييرها.', changeNow: 'غيّرها الآن', later: 'ذكّرني لاحقاً',
      account: 'الحساب', logout: 'تسجيل الخروج', changeTitle: 'تغيير بيانات الدخول', current: 'كلمة المرور الحالية', newUser: 'اسم مستخدم جديد (اختياري)',
      newPass: 'كلمة المرور الجديدة (8 أحرف على الأقل)', confirmPass: 'تأكيد كلمة المرور الجديدة', save: 'حفظ', cancel: 'إلغاء',
      mismatch: 'كلمتا المرور الجديدتان غير متطابقتين.', saved: 'تم تحديث بيانات الدخول.', hint: 'طُبعت بيانات الدخول الافتراضية في طرفية الخادم عند أول تشغيل.'
    }
  };

  var current = null;      // last /api/auth/state response
  var refreshers = [];     // functions that re-render text when the language changes

  function lang() { return document.documentElement.lang === 'ar' ? 'ar' : 'en'; }
  function s(key) { return STR[lang()][key]; }
  function el(tag, attrs) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) { return; }
      if (k === 'class') { node.className = v; } else if (k.indexOf('on') === 0) { node.addEventListener(k.slice(2), v); } else { node.setAttribute(k, v === true ? '' : v); }
    });
    for (var i = 2; i < arguments.length; i++) { if (arguments[i]) { node.appendChild(arguments[i]); } }
    return node;
  }
  function bind(node, key) { node.textContent = s(key); refreshers.push(function () { node.textContent = s(key); }); return node; }
  function session(key, value) { try { if (value === undefined) { return sessionStorage.getItem(key); } sessionStorage.setItem(key, value); } catch (e) { /* storage unavailable */ } return null; }

  function request(method, path, body) {
    var headers = { 'X-Requested-With': 'SecurityWizard', 'Accept': 'application/json' };
    var init = { method: method, headers: headers, credentials: 'same-origin' };
    if (body !== undefined) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    return fetch(path, init).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (data) { return { ok: resp.ok, status: resp.status, data: data || {} }; });
    });
  }

  function field(id, labelKey, type, autocomplete) {
    var input = el('input', { id: id, class: 'input', type: type, autocomplete: autocomplete || 'off' });
    var label = bind(el('label', { for: id }), labelKey);
    return { wrap: el('div', { class: 'field' }, label, input), input: input };
  }
  function errorText(r) {
    if (r.status === 429) { return s('tooMany'); }
    if (r.status === 401) { return s('loginFailed'); }
    return (r.data && r.data.detail && typeof r.data.detail === 'string') ? r.data.detail : s('failed');
  }

  // ---- login overlay -------------------------------------------------------------------------------
  var overlay = null;
  function showLogin() {
    if (overlay) { return; }
    var user = field('login-user', 'username', 'text', 'username');
    var pass = field('login-pass', 'password', 'password', 'current-password');
    var err = el('p', { class: 'form-error', role: 'alert' });
    var btn = el('button', { class: 'btn btn-primary', type: 'submit' });
    bind(btn, 'signIn');
    var title = bind(el('h2'), 'loginTitle');
    var hint = bind(el('p', { class: 'muted' }), 'hint');
    var form = el('form', { class: 'login-card', id: 'login-form' }, title, user.wrap, pass.wrap, err, btn, hint);
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      btn.disabled = true; btn.textContent = s('signingIn'); err.textContent = '';
      request('POST', '/api/login', { username: user.input.value.trim(), password: pass.input.value }).then(function (r) {
        btn.disabled = false; btn.textContent = s('signIn');
        if (!r.ok) { err.textContent = errorText(r); pass.input.value = ''; return; }
        hideLogin();
        refresh().then(function () { document.dispatchEvent(new CustomEvent('sw:authenticated')); });
      }).catch(function () { btn.disabled = false; btn.textContent = s('signIn'); err.textContent = s('failed'); });
    });
    overlay = el('div', { class: 'login-overlay' }, form);
    document.body.appendChild(overlay);
    user.input.focus();
  }
  function hideLogin() { if (overlay && overlay.parentNode) { overlay.parentNode.removeChild(overlay); } overlay = null; }

  // ---- default-credentials banner ---------------------------------------------------------------
  var banner = null;
  function renderBanner() {
    var show = current && current.authenticated && current.using_default_credentials && current.can_change_credentials && session('sw-cred-later') !== '1';
    if (!show) { if (banner && banner.parentNode) { banner.parentNode.removeChild(banner); } banner = null; return; }
    if (banner) { return; }
    var text = bind(el('span'), 'bannerText');
    var now = bind(el('button', { class: 'btn btn-small btn-primary', type: 'button', onclick: openChange }), 'changeNow');
    var later = bind(el('button', { class: 'btn btn-small', type: 'button', onclick: function () { session('sw-cred-later', '1'); renderBanner(); } }), 'later');
    banner = el('div', { class: 'cred-banner', role: 'status' }, text, now, later);
    document.body.insertBefore(banner, document.body.firstChild);
  }

  // ---- account buttons -------------------------------------------------------------------------------
  var slotBuilt = false;
  function renderAccountButtons() {
    var slot = document.getElementById('account-slot');
    if (!slot || slotBuilt || !current || !current.auth_required || !current.authenticated) { return; }
    slotBuilt = true;
    if (current.can_change_credentials) { slot.appendChild(bind(el('button', { class: 'btn btn-ghost', type: 'button', id: 'account-btn', onclick: openChange }), 'account')); }
    slot.appendChild(bind(el('button', { class: 'btn btn-ghost', type: 'button', id: 'logout-btn', onclick: logout }), 'logout'));
  }
  function logout() { request('POST', '/api/logout').then(function () { window.location.reload(); }); }

  // ---- change credentials dialog -------------------------------------------------------------------------
  function openChange() {
    var cur = field('chg-current', 'current', 'password', 'current-password');
    var nu = field('chg-user', 'newUser', 'text', 'username');
    var np = field('chg-new', 'newPass', 'password', 'new-password');
    var cp = field('chg-confirm', 'confirmPass', 'password', 'new-password');
    var err = el('p', { class: 'form-error', role: 'alert' });
    var dialog = el('dialog', { class: 'dialog', 'aria-labelledby': 'chg-title' });
    var save = bind(el('button', { class: 'btn btn-primary', type: 'submit' }), 'save');
    var cancel = bind(el('button', { class: 'btn', type: 'button', onclick: function () { dialog.close(); } }), 'cancel');
    var head = el('div', { class: 'dialog-head' }, bind(el('h3', { id: 'chg-title' }), 'changeTitle'));
    var form = el('form', { class: 'dialog-body' }, cur.wrap, nu.wrap, np.wrap, cp.wrap, err, el('div', { class: 'form-actions' }, cancel, save));
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      err.textContent = '';
      if (np.input.value !== cp.input.value) { err.textContent = s('mismatch'); return; }
      var body = { current_password: cur.input.value, new_password: np.input.value };
      if (nu.input.value.trim()) { body.new_username = nu.input.value.trim(); }
      save.disabled = true;
      request('POST', '/api/account/change', body).then(function (r) {
        save.disabled = false;
        if (!r.ok) { err.textContent = errorText(r); return; }
        dialog.close();
        refresh();
      }).catch(function () { save.disabled = false; err.textContent = s('failed'); });
    });
    dialog.appendChild(head);
    dialog.appendChild(form);
    dialog.addEventListener('close', function () { if (dialog.parentNode) { dialog.parentNode.removeChild(dialog); } });
    document.body.appendChild(dialog);
    dialog.showModal();
    cur.input.focus();
  }

  // ---- state -------------------------------------------------------------------------------------------------------
  function refresh() {
    return request('GET', '/api/auth/state').then(function (r) {
      if (!r.ok) { return; }
      current = r.data;
      if (current.auth_required && !current.authenticated) { showLogin(); } else { hideLogin(); }
      renderBanner();
      renderAccountButtons();
    }).catch(function () { /* offline: leave the page as it is */ });
  }

  function init() {
    document.addEventListener('sw:unauthorized', function () { if (!overlay) { showLogin(); } });
    new MutationObserver(function () { refreshers.forEach(function (fn) { fn(); }); }).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
    refresh();
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
}());
