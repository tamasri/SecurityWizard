/* SecurityWizard dashboard. Plain JavaScript, no libraries, no external requests.
   All server data is inserted with textContent / createElement, never innerHTML. */
(function () {
  'use strict';

  var I18N = {
    en: {
      'app.title': 'SecurityWizard', 'lang.toggle': 'العربية', 'theme.toggle': 'Theme',
      'score.title': 'Security score', 'score.notScanned': 'Not scanned yet',
      'score.hint': 'Run a scan to see how this server is doing.', 'score.how': 'How is this calculated?',
      'score.formulaIntro': 'Each scored check counts once: PASS = 1, WARNING = 0.5, CRITICAL = 0. INFO and SKIPPED checks are left out. The score is the sum divided by the number of scored checks.',
      'score.noScored': 'No scored checks', 'score.good': 'Good', 'score.fair': 'Needs attention', 'score.poor': 'At risk',
      'scan.run': 'Run scan', 'scan.running': 'Scanning', 'scan.done': 'Scan finished', 'scan.failed': 'Scan failed',
      'export.title': 'Export', 'search.placeholder': 'Search checks',
      'sev.critical': 'Critical', 'sev.warning': 'Warning', 'sev.info': 'Info', 'sev.pass': 'Pass', 'sev.skipped': 'Skipped',
      'results.title': 'Results', 'results.empty': 'No results yet. Run a scan to start.', 'results.noMatch': 'No checks match the current filters.',
      'col.id': 'ID', 'col.check': 'Check', 'col.status': 'Status', 'col.why': 'Why it matters', 'col.current': 'Current value', 'col.actions': 'Actions',
      'cat.all': 'All', 'details': 'Details', 'preview': 'Preview fix', 'noFix': 'No automatic fix',
      'history.title': 'Scan history', 'history.empty': 'No saved scans yet.', 'history.older': 'Older', 'history.newer': 'Newer', 'history.compare': 'Compare',
      'history.load': 'Open', 'history.score': 'Score', 'history.pickTwo': 'Pick two different scans to compare.',
      'diff.new': 'New findings', 'diff.resolved': 'Resolved', 'diff.changed': 'Changed status', 'diff.delta': 'Score change', 'diff.none': 'None',
      'backups.title': 'Backups and rollback', 'backups.empty': 'No backups yet. A backup is created automatically before every change.',
      'backups.rollback': 'Roll back', 'backups.confirm': 'Restore the files from this backup?',
      'common.close': 'Close', 'common.copy': 'Copy', 'common.copied': 'Copied',
      'detail.what': 'What it checks', 'detail.risk': 'Why it matters', 'detail.current': 'Current value', 'detail.recommended': 'Recommended value',
      'detail.evidence': 'Evidence', 'detail.accepted': 'Accepted risk (from the configuration)', 'detail.command': 'Command used', 'detail.manual': 'Manual command', 'detail.refs': 'References',
      'fix.title': 'Fix preview', 'fix.confirm': 'I reviewed the changes and want to apply them.', 'fix.apply': 'Apply fix', 'fix.keep': 'Keep this change',
      'fix.blocked': 'This fix cannot be applied', 'fix.warnings': 'Warnings', 'fix.commands': 'Commands that will run', 'fix.files': 'File changes',
      'fix.perms': 'Permission changes', 'fix.noChanges': 'No file or command changes.', 'fix.result': 'Result', 'fix.applied': 'Applied. A backup was created.',
      'fix.dryRunOnly': 'Apply is disabled: the server runs in dry-run-only mode (SECURITYWIZARD_DRY_RUN_ONLY=1).',
      'fix.readOnly': 'Apply is disabled: the server runs in read-only mode.', 'fix.needRoot': 'Applying needs root privileges.',
      'fix.deadman': 'Safety timer: this change will be reverted automatically in {time} unless you keep it.',
      'fix.deadmanExpired': 'The safety timer expired: the change was reverted.', 'fix.kept': 'The change was kept.',
      'mode.dryRun': 'Dry-run only: fixes can be previewed but not applied.', 'mode.readOnly': 'Read-only mode: changes and rollbacks are disabled.',
      'mode.notRoot': 'Not running as root: some checks will be skipped or incomplete.', 'mode.authOff': 'Authentication is disabled.',
      'err.generic': 'Something went wrong', 'err.rate': 'Too many requests, please wait a moment.',
      'status.skippedReason': 'Skipped'
    },
    ar: {
      'app.title': 'SecurityWizard', 'lang.toggle': 'English', 'theme.toggle': 'المظهر',
      'score.title': 'درجة الأمان', 'score.notScanned': 'لم يتم الفحص بعد',
      'score.hint': 'شغّل فحصاً لمعرفة حالة هذا الخادم.', 'score.how': 'كيف تُحسب الدرجة؟',
      'score.formulaIntro': 'كل فحص محتسب يُعدّ مرة واحدة: ناجح = 1، تحذير = 0.5، حرج = 0. تُستثنى الفحوص المعلوماتية والمتخطاة. الدرجة هي المجموع مقسوماً على عدد الفحوص المحتسبة.',
      'score.noScored': 'لا توجد فحوص محتسبة', 'score.good': 'جيدة', 'score.fair': 'تحتاج اهتماماً', 'score.poor': 'معرّضة للخطر',
      'scan.run': 'ابدأ الفحص', 'scan.running': 'جارٍ الفحص', 'scan.done': 'اكتمل الفحص', 'scan.failed': 'فشل الفحص',
      'export.title': 'تصدير', 'search.placeholder': 'ابحث في الفحوص',
      'sev.critical': 'حرج', 'sev.warning': 'تحذير', 'sev.info': 'معلومة', 'sev.pass': 'ناجح', 'sev.skipped': 'متخطى',
      'results.title': 'النتائج', 'results.empty': 'لا توجد نتائج بعد. ابدأ فحصاً.', 'results.noMatch': 'لا توجد فحوص تطابق عوامل التصفية الحالية.',
      'col.id': 'المعرّف', 'col.check': 'الفحص', 'col.status': 'الحالة', 'col.why': 'سبب الأهمية', 'col.current': 'القيمة الحالية', 'col.actions': 'إجراءات',
      'cat.all': 'الكل', 'details': 'التفاصيل', 'preview': 'معاينة الإصلاح', 'noFix': 'لا يوجد إصلاح تلقائي',
      'history.title': 'سجل الفحوص', 'history.empty': 'لا توجد فحوص محفوظة بعد.', 'history.older': 'الأقدم', 'history.newer': 'الأحدث', 'history.compare': 'قارن',
      'history.load': 'فتح', 'history.score': 'الدرجة', 'history.pickTwo': 'اختر فحصين مختلفين للمقارنة.',
      'diff.new': 'نتائج جديدة', 'diff.resolved': 'تمت معالجتها', 'diff.changed': 'تغيّرت حالتها', 'diff.delta': 'تغيّر الدرجة', 'diff.none': 'لا شيء',
      'backups.title': 'النسخ الاحتياطية والتراجع', 'backups.empty': 'لا توجد نسخ احتياطية بعد. تُنشأ نسخة تلقائياً قبل كل تغيير.',
      'backups.rollback': 'تراجع', 'backups.confirm': 'استعادة الملفات من هذه النسخة؟',
      'common.close': 'إغلاق', 'common.copy': 'نسخ', 'common.copied': 'تم النسخ',
      'detail.what': 'ما الذي يفحصه', 'detail.risk': 'سبب الأهمية', 'detail.current': 'القيمة الحالية', 'detail.recommended': 'القيمة الموصى بها',
      'detail.evidence': 'الأدلة', 'detail.accepted': 'مخاطرة مقبولة (من ملف الإعدادات)', 'detail.command': 'الأمر المستخدم', 'detail.manual': 'الأمر اليدوي', 'detail.refs': 'المراجع',
      'fix.title': 'معاينة الإصلاح', 'fix.confirm': 'راجعت التغييرات وأريد تطبيقها.', 'fix.apply': 'طبّق الإصلاح', 'fix.keep': 'أبقِ هذا التغيير',
      'fix.blocked': 'لا يمكن تطبيق هذا الإصلاح', 'fix.warnings': 'تحذيرات', 'fix.commands': 'الأوامر التي ستُنفَّذ', 'fix.files': 'تغييرات الملفات',
      'fix.perms': 'تغييرات الصلاحيات', 'fix.noChanges': 'لا توجد تغييرات في الملفات أو الأوامر.', 'fix.result': 'النتيجة', 'fix.applied': 'تم التطبيق. أُنشئت نسخة احتياطية.',
      'fix.dryRunOnly': 'التطبيق معطّل: الخادم يعمل في وضع المعاينة فقط (SECURITYWIZARD_DRY_RUN_ONLY=1).',
      'fix.readOnly': 'التطبيق معطّل: الخادم يعمل في وضع القراءة فقط.', 'fix.needRoot': 'التطبيق يتطلب صلاحيات الجذر.',
      'fix.deadman': 'مؤقّت أمان: سيتم التراجع عن هذا التغيير تلقائياً خلال {time} ما لم تُبقِه.',
      'fix.deadmanExpired': 'انتهى مؤقّت الأمان: جرى التراجع عن التغيير.', 'fix.kept': 'تم الإبقاء على التغيير.',
      'mode.dryRun': 'وضع المعاينة فقط: يمكن معاينة الإصلاحات دون تطبيقها.', 'mode.readOnly': 'وضع القراءة فقط: التغييرات والتراجع معطّلة.',
      'mode.notRoot': 'لا يعمل بصلاحيات الجذر: ستُتخطى بعض الفحوص أو تكون ناقصة.', 'mode.authOff': 'المصادقة معطّلة.',
      'err.generic': 'حدث خطأ ما', 'err.rate': 'طلبات كثيرة، يرجى الانتظار قليلاً.',
      'status.skippedReason': 'متخطى'
    }
  };

  var REFERENCES = {
    _default: [
      ['CIS Benchmarks', 'https://www.cisecurity.org/cis-benchmarks'],
      ['NIST SP 800-53', 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final']
    ],
    docker: [['CIS Docker Benchmark', 'https://www.cisecurity.org/benchmark/docker'], ['NIST SP 800-190', 'https://csrc.nist.gov/pubs/sp/800/190/final']],
    ssh: [['CIS Distribution Independent Linux', 'https://www.cisecurity.org/benchmark/distribution_independent_linux'], ['NIST SP 800-53 AC-17', 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final']]
  };

  var SEVERITIES = ['CRITICAL', 'WARNING', 'INFO', 'PASS', 'SKIPPED'];
  var state = {
    lang: 'en', status: null, result: null, scanId: null, tab: 'all', search: '',
    severities: { CRITICAL: true, WARNING: true, INFO: true, PASS: true, SKIPPED: true },
    scanning: false, pollTimer: null, fix: null, deadmanTimer: null
  };

  // ---- helpers -----------------------------------------------------------------------------
  function $(id) { return document.getElementById(id); }
  function t(key, vars) {
    var s = (I18N[state.lang] && I18N[state.lang][key]) || I18N.en[key] || key;
    if (vars) { Object.keys(vars).forEach(function (k) { s = s.replace('{' + k + '}', vars[k]); }); }
    return s;
  }
  function el(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) { return; }
        if (k === 'class') { node.className = v; }
        else if (k === 'text') { node.textContent = v; }
        else if (k.indexOf('on') === 0) { node.addEventListener(k.slice(2), v); }
        else { node.setAttribute(k, v === true ? '' : v); }
      });
    }
    var add = function (child) {
      if (child === null || child === undefined || child === false) { return; }
      if (Array.isArray(child)) { child.forEach(add); return; }
      node.appendChild(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
    };
    for (var i = 2; i < arguments.length; i++) { add(arguments[i]); }
    return node;
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function store(key, value) { try { if (value === undefined) { return localStorage.getItem(key); } localStorage.setItem(key, value); } catch (e) { /* storage unavailable */ } return null; }

  function notice(message, kind) {
    var area = $('notice-area');
    var node = el('div', { class: 'notice ' + (kind || ''), text: message });
    area.appendChild(node);
    setTimeout(function () { if (node.parentNode) { node.parentNode.removeChild(node); } }, 5000);
  }

  function api(method, path, body) {
    var headers = { 'X-Requested-With': 'SecurityWizard', 'Accept': 'application/json' };
    var init = { method: method, headers: headers, credentials: 'same-origin' };
    if (body !== undefined) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    return fetch(path, init).then(function (resp) {
      return resp.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (resp.status === 401) { document.dispatchEvent(new CustomEvent('sw:unauthorized')); }
        if (!resp.ok) {
          var detail = data && data.detail;
          if (resp.status === 429) { detail = t('err.rate'); }
          if (Array.isArray(detail)) { detail = detail.map(function (d) { return d.msg || ''; }).join('; '); }
          var err = new Error(detail || t('err.generic'));
          err.status = resp.status;
          throw err;
        }
        return data;
      });
    });
  }
  function fail(err) { notice(err && err.message ? err.message : t('err.generic'), 'error'); }

  // ---- language and theme ------------------------------------------------------------------
  function applyI18n() {
    document.documentElement.lang = state.lang;
    document.documentElement.dir = state.lang === 'ar' ? 'rtl' : 'ltr';
    document.querySelectorAll('[data-i18n]').forEach(function (n) { n.textContent = t(n.getAttribute('data-i18n')); });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (n) { n.setAttribute('placeholder', t(n.getAttribute('data-i18n-placeholder'))); });
    renderAll();
  }
  function setLang(lang) { state.lang = lang === 'ar' ? 'ar' : 'en'; store('sw-lang', state.lang); applyI18n(); }
  function initTheme() {
    var saved = store('sw-theme');
    if (saved === 'dark' || saved === 'light') { document.documentElement.setAttribute('data-theme', saved); }
  }
  function toggleTheme() {
    var cur = document.documentElement.getAttribute('data-theme');
    if (!cur) { cur = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    store('sw-theme', next);
  }

  // ---- status banner and version --------------------------------------------------------------
  function renderMode() {
    var box = $('mode-banner');
    var s = state.status;
    var msgs = [];
    if (s) {
      if (s.readonly) { msgs.push(t('mode.readOnly')); }
      else if (s.dry_run_only) { msgs.push(t('mode.dryRun')); }
      if (s.is_root === false) { msgs.push(t('mode.notRoot')); }
      if (s.auth_enabled === false) { msgs.push(t('mode.authOff')); }
    }
    box.hidden = msgs.length === 0;
    box.textContent = msgs.join(' ');
    box.className = 'mode-banner' + (s && (s.readonly || s.dry_run_only) ? '' : ' warn');
  }
  function loadStatus() {
    return api('GET', '/api/status').then(function (s) { state.status = s; renderMode(); }).catch(function () { /* login may be required */ });
  }
  function loadVersion() {
    fetch('/api/version', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
      if (d && d.version) { $('app-version').textContent = 'v' + d.version; }
    }).catch(function () { /* keep the built-in text */ });
  }

  // ---- score -----------------------------------------------------------------------------------
  function renderScore() {
    var ring = $('score-ring'), value = $('score-value'), label = $('score-state'), hint = $('score-hint');
    var counts = $('score-counts'), formula = $('score-formula');
    clear(counts);
    var r = state.result;
    if (!r) {
      ring.setAttribute('data-state', 'empty'); ring.style.setProperty('--pct', '0');
      value.textContent = '–'; label.textContent = t('score.notScanned'); hint.hidden = false; counts.hidden = true; formula.textContent = '';
      return;
    }
    hint.hidden = true;
    if (typeof r.score !== 'number') {
      ring.setAttribute('data-state', 'empty'); ring.style.setProperty('--pct', '0');
      value.textContent = '–'; label.textContent = t('score.noScored');
    } else {
      var level = r.score >= 80 ? 'good' : (r.score >= 50 ? 'fair' : 'poor');
      ring.setAttribute('data-state', level); ring.style.setProperty('--pct', String(r.score));
      value.textContent = String(r.score);
      label.textContent = t('score.' + level);
    }
    formula.textContent = r.formula || '';
    var c = r.counts || {};
    counts.hidden = false;
    SEVERITIES.forEach(function (sev) {
      if (c[sev] !== undefined) { counts.appendChild(el('li', null, el('span', { class: 'badge ' + sev, text: t('sev.' + sev.toLowerCase()) + ': ' + c[sev] }))); }
    });
  }

  // ---- results -----------------------------------------------------------------------------------
  function checks() { return (state.result && state.result.checks) || []; }
  function categories() {
    var seen = [];
    checks().forEach(function (c) { if (seen.indexOf(c.category) < 0) { seen.push(c.category); } });
    return seen;
  }
  function renderTabs() {
    var box = $('category-tabs');
    clear(box);
    var cats = categories();
    if (!cats.length) { return; }
    [['all', t('cat.all')]].concat(cats.map(function (c) { return [c, c.charAt(0).toUpperCase() + c.slice(1)]; })).forEach(function (pair) {
      box.appendChild(el('button', {
        type: 'button', class: 'tab', role: 'tab', 'aria-selected': state.tab === pair[0] ? 'true' : 'false', text: pair[1],
        onclick: function () { state.tab = pair[0]; renderTabs(); renderResults(); }
      }));
    });
  }
  function matches(c) {
    if (!state.severities[c.status]) { return false; }
    if (state.tab !== 'all' && c.category !== state.tab) { return false; }
    if (state.search) {
      var hay = [c.id, c.title, c.what_it_checks, c.risk, c.current_value, (c.details || []).join(' ')].join(' ').toLowerCase();
      if (hay.indexOf(state.search) < 0) { return false; }
    }
    return true;
  }
  function badge(status) { return el('span', { class: 'badge ' + status, text: t('sev.' + status.toLowerCase()) }); }

  function renderResults() {
    var table = $('results'), body = $('results-body'), empty = $('results-empty');
    clear(body);
    var all = checks();
    if (!all.length) { table.hidden = true; empty.hidden = false; empty.textContent = t('results.empty'); return; }
    var rows = all.filter(matches);
    table.hidden = rows.length === 0;
    empty.hidden = rows.length !== 0;
    empty.textContent = t('results.noMatch');
    rows.forEach(function (c) {
      var actions = el('td', { class: 'cell-actions' }, el('button', { type: 'button', class: 'btn btn-small', text: t('details'), onclick: function () { openDetail(c); } }));
      if (c.remediation_id) {
        actions.appendChild(el('button', { type: 'button', class: 'btn btn-small', text: t('preview'), onclick: function () { openFix(c); } }));
      } else if (c.status === 'CRITICAL' || c.status === 'WARNING') {
        actions.appendChild(el('span', { class: 'muted', text: t('noFix') }));
      }
      body.appendChild(el('tr', null,
        el('td', { class: 'cell-id', text: c.id }),
        el('td', { class: 'cell-title' }, c.title || '', el('div', { class: 'muted', text: c.category || '' })),
        el('td', null, badge(c.status)),
        el('td', { class: 'cell-why', text: c.risk || '' }),
        el('td', { class: 'cell-value', text: String(c.current_value === undefined ? '' : c.current_value).slice(0, 200) }),
        actions));
    });
  }
  function renderAll() { renderMode(); renderScore(); renderTabs(); renderResults(); renderHistory(); renderBackups(); }

  // ---- detail dialog ---------------------------------------------------------------------------------
  function kv(label, value, mono) {
    if (value === undefined || value === null || value === '') { return null; }
    return el('div', { class: 'kv' }, el('span', { class: 'k', text: label }), el('div', { class: mono ? 'mono' : '', text: String(value) }));
  }
  function copyButton(text) {
    return el('button', {
      type: 'button', class: 'btn btn-small', text: t('common.copy'), onclick: function (ev) {
        var btn = ev.currentTarget;
        var done = function () { btn.textContent = t('common.copied'); setTimeout(function () { btn.textContent = t('common.copy'); }, 1500); };
        if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(done, function () { /* clipboard blocked */ }); }
      }
    });
  }
  function openDetail(c) {
    $('detail-title').textContent = c.id + ' — ' + (c.title || '');
    var body = $('detail-body');
    clear(body);
    body.appendChild(el('div', null, badge(c.status)));
    [kv(t('detail.what'), c.what_it_checks), kv(t('detail.risk'), c.risk), kv(t('detail.current'), c.current_value, true),
      kv(t('detail.recommended'), c.recommended_value, true)].forEach(function (n) { if (n) { body.appendChild(n); } });
    if (c.details && c.details.length) {
      body.appendChild(el('div', { class: 'kv' }, el('span', { class: 'k', text: t('detail.evidence') }), el('pre', { class: 'code', text: c.details.join('\n') })));
    }
    if (c.accepted_risk) {
      body.appendChild(kv(t('detail.accepted'), c.accepted_risk.reason + (c.accepted_risk.expires ? ' (' + c.accepted_risk.expires + ')' : '') + ' [' + c.accepted_risk.original_status + ']'));
    }
    if (c.command) { body.appendChild(el('div', { class: 'kv' }, el('span', { class: 'k', text: t('detail.command') }), el('pre', { class: 'code', text: c.command }))); }
    if (c.manual_command) {
      body.appendChild(el('div', { class: 'kv' }, el('span', { class: 'k', text: t('detail.manual') }),
        el('div', { class: 'cmd-row' }, el('pre', { class: 'code', text: c.manual_command }), copyButton(c.manual_command))));
    }
    var refs = REFERENCES[c.category] || REFERENCES._default;
    body.appendChild(el('div', { class: 'kv' }, el('span', { class: 'k', text: t('detail.refs') }),
      el('div', { class: 'refs' }, refs.map(function (r) { return el('a', { href: r[1], target: '_blank', rel: 'noopener noreferrer', text: r[0] }); }))));
    $('detail').showModal();
  }

  // ---- fix preview / apply -----------------------------------------------------------------------------------
  function diffNode(text) {
    var pre = el('pre', { class: 'code diff' });
    String(text || '').split('\n').forEach(function (line) {
      var cls = line.charAt(0) === '+' && line.indexOf('+++') !== 0 ? 'add' : (line.charAt(0) === '-' && line.indexOf('---') !== 0 ? 'del' : '');
      pre.appendChild(el('span', { class: cls, text: line + '\n' }));
    });
    return pre;
  }
  function section(title, content) { return el('div', { class: 'kv' }, el('span', { class: 'k', text: title }), content); }

  function applyDisabledReason() {
    var s = state.status || {};
    if (s.readonly) { return t('fix.readOnly'); }
    if (s.dry_run_only) { return t('fix.dryRunOnly'); }
    return '';
  }
  function openFix(c) {
    state.fix = { check: c, preview: null };
    $('fix-title').textContent = t('fix.title') + ' — ' + c.id;
    var body = $('fix-body');
    clear(body);
    stopDeadman();
    $('deadman').hidden = true;
    $('fix-confirm').checked = false;
    $('fix-confirm-line').hidden = true;
    $('fix-apply').hidden = true;
    body.appendChild(el('p', { class: 'muted', text: '...' }));
    $('fix-modal').showModal();
    api('POST', '/api/dry-run', { remediation_id: c.remediation_id }).then(function (p) {
      state.fix.preview = p;
      renderPreview(p);
    }).catch(function (e) { clear(body); body.appendChild(el('p', { class: 'form-error', text: e.message })); });
  }
  function renderPreview(p) {
    var body = $('fix-body');
    clear(body);
    if (p.title) { body.appendChild(el('h4', { text: p.title })); }
    if (p.description) { body.appendChild(el('p', { class: 'muted', text: p.description })); }
    var reason = applyDisabledReason();
    if (p.blocked) { body.appendChild(el('p', { class: 'form-error', text: t('fix.blocked') + ': ' + (p.blocked_reason || '') })); }
    if (p.warnings && p.warnings.length) { body.appendChild(section(t('fix.warnings'), el('pre', { class: 'code', text: p.warnings.join('\n') }))); }
    var any = false;
    if (p.commands && p.commands.length) { any = true; body.appendChild(section(t('fix.commands'), el('pre', { class: 'code', text: p.commands.join('\n') }))); }
    if (p.diffs && p.diffs.length) {
      any = true;
      p.diffs.forEach(function (d) { body.appendChild(section(t('fix.files') + ': ' + d.path, diffNode(d.unified_diff))); });
    }
    if (p.perm_changes && p.perm_changes.length) {
      any = true;
      body.appendChild(section(t('fix.perms'), el('pre', { class: 'code', text: p.perm_changes.map(function (x) { return x.path + ': ' + x.current_mode + ' → ' + x.new_mode; }).join('\n') })));
    }
    if (!any && !p.blocked) { body.appendChild(el('p', { class: 'muted', text: t('fix.noChanges') })); }
    if (reason) { body.appendChild(el('p', { class: 'form-error', text: reason })); }
    var canApply = !p.blocked && !reason;
    $('fix-confirm-line').hidden = !canApply;
    var btn = $('fix-apply');
    btn.hidden = false;
    btn.disabled = true;
    btn.title = reason;
    if (!canApply) { btn.hidden = !reason; }
  }
  function doApply() {
    var f = state.fix;
    if (!f || !$('fix-confirm').checked) { return; }
    var btn = $('fix-apply');
    btn.disabled = true;
    api('POST', '/api/remediate', { remediation_id: f.check.remediation_id, confirm: true }).then(function (r) {
      var body = $('fix-body');
      body.appendChild(section(t('fix.result'), el('pre', { class: 'code', text: (r.message || '') + (r.output && r.output.length ? '\n' + r.output.join('\n') : '') })));
      notice(r.ok ? t('fix.applied') : (r.message || t('err.generic')), r.ok ? 'ok' : 'error');
      if (r.ok && r.deadman_token && r.deadline) { startDeadman(r.deadman_token, r.deadline); }
      loadBackups();
    }).catch(function (e) { fail(e); btn.disabled = false; });
  }
  function fmtTime(seconds) { var m = Math.floor(seconds / 60), s = Math.max(0, Math.floor(seconds % 60)); return m + ':' + (s < 10 ? '0' : '') + s; }
  function stopDeadman() { if (state.deadmanTimer) { clearInterval(state.deadmanTimer); state.deadmanTimer = null; } }
  function startDeadman(token, deadline) {
    stopDeadman();
    var box = $('deadman'), text = $('deadman-text'), btn = $('deadman-confirm');
    box.hidden = false;
    btn.disabled = false;
    btn.setAttribute('data-token', token);
    var tick = function () {
      var left = deadline - Date.now() / 1000;
      if (left <= 0) { stopDeadman(); text.textContent = t('fix.deadmanExpired'); btn.disabled = true; return; }
      text.textContent = t('fix.deadman', { time: fmtTime(left) });
    };
    tick();
    state.deadmanTimer = setInterval(tick, 1000);
  }
  function confirmDeadman() {
    var token = $('deadman-confirm').getAttribute('data-token');
    api('POST', '/api/deadman/confirm', { token: token }).then(function () {
      stopDeadman();
      $('deadman-text').textContent = t('fix.kept');
      $('deadman-confirm').disabled = true;
    }).catch(fail);
  }

  // ---- scan ------------------------------------------------------------------------------------------------------
  function setScanning(on) {
    state.scanning = on;
    $('scan-btn').disabled = on;
    $('scan-progress').hidden = !on;
    if (!on) { $('scan-status').textContent = ''; }
  }
  function applyScanState(s) {
    if (s.status === 'running') {
      setScanning(true);
      var p = s.progress || { done: 0, total: 1 };
      $('scan-progress').max = Math.max(1, p.total);
      $('scan-progress').value = p.done;
      $('scan-status').textContent = t('scan.running') + (p.current ? ': ' + p.current : '');
      return false;
    }
    setScanning(false);
    if (s.status === 'finished') {
      if (s.error) { notice(t('scan.failed') + ': ' + s.error, 'error'); }
      else if (s.result) {
        state.result = s.result; state.scanId = s.scan_id || null;
        if (state.tab !== 'all' && categories().indexOf(state.tab) < 0) { state.tab = 'all'; }
        renderScore(); renderTabs(); renderResults();
        loadHistory();
      }
    }
    return true;
  }
  function poll() {
    api('GET', '/api/scan/status').then(function (s) {
      if (!applyScanState(s)) { state.pollTimer = setTimeout(poll, 1000); }
      else { state.pollTimer = null; }
    }).catch(function (e) { setScanning(false); fail(e); });
  }
  function startScan() {
    setScanning(true);
    api('POST', '/api/scan', {}).then(function () { poll(); }).catch(function (e) { setScanning(false); fail(e); });
  }

  // ---- history, diff, backups ---------------------------------------------------------------------------------------
  var historyItems = [], backupItems = [];
  function loadHistory() { return api('GET', '/api/history').then(function (d) { historyItems = d.scans || []; renderHistory(); }).catch(function () { /* not authorised yet */ }); }
  function loadBackups() { return api('GET', '/api/backups').then(function (d) { backupItems = d.backups || []; renderBackups(); }).catch(function () { /* not authorised yet */ }); }
  function fmtDate(v) { try { var d = new Date(v); return isNaN(d.getTime()) ? String(v || '') : d.toLocaleString(state.lang === 'ar' ? 'ar' : undefined); } catch (e) { return String(v || ''); } }

  function renderHistory() {
    var list = $('history-list'), empty = $('history-empty');
    clear(list);
    empty.hidden = historyItems.length > 0;
    var oldSel = $('diff-old'), newSel = $('diff-new');
    var keepOld = oldSel.value, keepNew = newSel.value;
    clear(oldSel); clear(newSel);
    historyItems.forEach(function (h, i) {
      var label = fmtDate(h.timestamp) + ' — ' + (h.score === null || h.score === undefined ? '–' : h.score);
      oldSel.appendChild(el('option', { value: h.scan_id, text: label }));
      newSel.appendChild(el('option', { value: h.scan_id, text: label }));
      list.appendChild(el('li', null,
        el('span', null, fmtDate(h.timestamp) + ' · ' + t('history.score') + ': ' + (h.score === null || h.score === undefined ? '–' : h.score)),
        el('span', null,
          el('button', { type: 'button', class: 'btn btn-small', text: t('history.load'), onclick: function () { openHistory(h.scan_id); } }))));
    });
    if (historyItems.length > 1) { oldSel.selectedIndex = historyItems.length - 1; newSel.selectedIndex = 0; }
    if (keepOld) { oldSel.value = keepOld; }
    if (keepNew) { newSel.value = keepNew; }
  }
  function openHistory(id) {
    api('GET', '/api/history/' + encodeURIComponent(id)).then(function (scan) {
      state.result = scan; state.scanId = id; state.tab = 'all';
      renderScore(); renderTabs(); renderResults();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }).catch(fail);
  }
  function listBlock(title, items) {
    return el('div', null, el('strong', { text: title }),
      items.length ? el('ul', null, items.map(function (x) { return el('li', { text: typeof x === 'string' ? x : x.check_id + ': ' + x.old_status + ' → ' + x.new_status }); })) : el('p', { class: 'muted', text: t('diff.none') }));
  }
  function runDiff() {
    var o = $('diff-old').value, n = $('diff-new').value, box = $('diff-result');
    if (!o || !n || o === n) { notice(t('history.pickTwo'), 'error'); return; }
    api('GET', '/api/history/diff?old=' + encodeURIComponent(o) + '&new=' + encodeURIComponent(n)).then(function (d) {
      clear(box); box.hidden = false;
      box.appendChild(el('p', null, el('strong', { text: t('diff.delta') + ': ' }), (d.score_delta > 0 ? '+' : '') + d.score_delta));
      box.appendChild(listBlock(t('diff.new'), d.new_findings || []));
      box.appendChild(listBlock(t('diff.resolved'), d.resolved || []));
      box.appendChild(listBlock(t('diff.changed'), d.changed || []));
    }).catch(fail);
  }
  function renderBackups() {
    var list = $('backups-list');
    clear(list);
    $('backups-empty').hidden = backupItems.length > 0;
    var s = state.status || {};
    backupItems.forEach(function (b) {
      var btn = el('button', {
        type: 'button', class: 'btn btn-small', text: t('backups.rollback'), disabled: !!s.readonly,
        onclick: function () {
          if (!window.confirm(t('backups.confirm'))) { return; }
          api('POST', '/api/rollback', { snapshot_id: b.snapshot_id }).then(function (r) { notice(r.message || '', r.ok ? 'ok' : 'error'); }).catch(fail);
        }
      });
      list.appendChild(el('li', null, el('span', null, b.snapshot_id + (b.created ? ' · ' + fmtDate(b.created) : '')), btn));
    });
  }

  // ---- export ---------------------------------------------------------------------------------------------------------
  function download(name, mime, text) {
    var url = URL.createObjectURL(new Blob([text], { type: mime }));
    var a = el('a', { href: url, download: name });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }
  function doExport(fmt) {
    $('export-menu').open = false;
    var url = '/api/export?fmt=' + encodeURIComponent(fmt) + (state.scanId ? '&scan_id=' + encodeURIComponent(state.scanId) : '');
    api('GET', url).then(function (d) {
      var stamp = new Date().toISOString().slice(0, 10);
      if (fmt === 'markdown') { download('securitywizard-' + stamp + '.md', 'text/markdown', d.markdown); }
      else if (fmt === 'html') { download('securitywizard-' + stamp + '.html', 'text/html', d.html); }
      else if (fmt === 'sarif') { download('securitywizard-' + stamp + '.sarif', 'application/json', JSON.stringify(d, null, 2)); }
      else { download('securitywizard-' + stamp + '.json', 'application/json', JSON.stringify(d, null, 2)); }
    }).catch(fail);
  }

  // ---- wiring ---------------------------------------------------------------------------------------------------------------
  function init() {
    var saved = store('sw-lang');
    if (saved === 'ar' || saved === 'en') { state.lang = saved; }
    else if ((navigator.language || '').toLowerCase().indexOf('ar') === 0) { state.lang = 'ar'; }
    initTheme();
    $('lang-toggle').addEventListener('click', function () { setLang(state.lang === 'ar' ? 'en' : 'ar'); });
    $('theme-toggle').addEventListener('click', toggleTheme);
    $('scan-btn').addEventListener('click', startScan);
    $('search').addEventListener('input', function (e) { state.search = e.target.value.trim().toLowerCase(); renderResults(); });
    $('severity-filters').addEventListener('click', function (e) {
      var chip = e.target.closest('[data-severity]');
      if (!chip) { return; }
      var sev = chip.getAttribute('data-severity');
      state.severities[sev] = !state.severities[sev];
      chip.setAttribute('aria-pressed', state.severities[sev] ? 'true' : 'false');
      renderResults();
    });
    document.querySelectorAll('[data-close]').forEach(function (b) {
      b.addEventListener('click', function () { var d = $(b.getAttribute('data-close')); if (d.open) { d.close(); } });
    });
    $('fix-modal').addEventListener('close', stopDeadman);
    $('fix-confirm').addEventListener('change', function (e) { $('fix-apply').disabled = !e.target.checked || !!applyDisabledReason(); });
    $('fix-apply').addEventListener('click', doApply);
    $('deadman-confirm').addEventListener('click', confirmDeadman);
    $('diff-btn').addEventListener('click', runDiff);
    document.querySelectorAll('[data-export]').forEach(function (b) { b.addEventListener('click', function () { doExport(b.getAttribute('data-export')); }); });
    document.addEventListener('sw:authenticated', function () { bootData(); });
    applyI18n();
    loadVersion();
    bootData();
  }
  function bootData() {
    loadStatus().then(function () { renderBackups(); });
    loadHistory();
    loadBackups();
    api('GET', '/api/scan/status').then(function (s) { if (!applyScanState(s)) { poll(); } }).catch(function () { /* login required */ });
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
}());
