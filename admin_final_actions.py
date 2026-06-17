"""Shared CSS/JS for randomized final-action editor in admin templates."""

FINAL_ACTIONS_CSS = """
    .fa-scope { margin-top: 0.5rem; }
    .fa-random-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.85rem; margin: 0.65rem 0 0.85rem; padding: 0.65rem 0.75rem; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; }
    .fa-random-row label { display: inline-flex; align-items: center; gap: 0.45rem; margin: 0; color: var(--text); font-size: 0.875rem; cursor: pointer; }
    .fa-random-row .hint { margin: 0; font-size: 0.78rem; color: var(--muted); line-height: 1.4; flex: 1 1 12rem; }
    .fa-multi-wrap { margin-top: 0.75rem; padding: 0.85rem; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; }
    .fa-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.75rem; margin-bottom: 0.75rem; }
    .fa-count-badge { display: inline-flex; align-items: center; justify-content: center; min-width: 1.5rem; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; background: var(--border); color: var(--text); }
    .fa-btn-add, .fa-btn-clear { padding: 0.4rem 0.75rem; font-size: 0.8125rem; border-radius: 6px; cursor: pointer; border: 1px solid var(--border); background: var(--surface); color: var(--text); }
    .fa-btn-add { background: var(--accent); color: #fff; border-color: var(--accent); }
    .fa-btn-add:hover { background: #2563eb; }
    .fa-btn-clear:hover { border-color: #ef4444; color: #ef4444; }
    .fa-empty { display: none; text-align: center; padding: 1rem; border: 1px dashed var(--border); border-radius: 8px; color: var(--muted); font-size: 0.85rem; margin-bottom: 0.75rem; }
    .fa-empty.visible { display: block; }
    .fa-actions-list { display: flex; flex-direction: column; gap: 0.75rem; }
    .fa-action-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem; }
    .fa-action-top { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 0.5rem; margin-bottom: 0.65rem; padding-bottom: 0.55rem; border-bottom: 1px solid var(--border); }
    .fa-action-title { font-weight: 600; font-size: 0.875rem; }
    .fa-action-summary { font-size: 0.78rem; color: var(--muted); margin-top: 0.15rem; }
    .fa-btn-danger { padding: 0.3rem 0.6rem; font-size: 0.75rem; background: transparent; color: var(--muted); border: 1px solid var(--border); border-radius: 5px; cursor: pointer; }
    .fa-btn-danger:hover { color: #ef4444; border-color: #ef4444; }
    .fa-action-card .mode-toggles { max-width: none; margin: 0.5rem 0; }
    .fa-action-card label { margin-top: 0.55rem; }
    .fa-action-card .panel { margin-top: 0.35rem; }
    .fa-action-label-input { width: 100%; max-width: 22rem; padding: 0.4rem 0.55rem; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; font-size: 0.8125rem; }
    .fa-single-wrap.fa-hidden { display: none !important; }
"""

FINAL_ACTION_ACTION_TEMPLATE = """
<div id="fa-action-template" style="display:none;" class="fa-action-card" data-fa-id="">
  <div class="fa-action-top">
    <div>
      <div class="fa-action-title">Action</div>
      <div class="fa-action-summary"></div>
    </div>
    <button type="button" class="fa-btn-danger fa-remove-action" aria-label="Delete this action">Delete</button>
  </div>
  <label>Label (optional)</label>
  <input type="text" class="fa-action-label-input" placeholder="e.g. Fake 404" maxlength="80">
  <div class="mode-toggles fa-mode-toggles" role="group">
    <button type="button" class="mode-btn fa-mode-btn" data-mode="redirect">Redirect</button>
    <button type="button" class="mode-btn fa-mode-btn" data-mode="media">Media</button>
    <button type="button" class="mode-btn fa-mode-btn active" data-mode="error">Error</button>
  </div>
  <input type="hidden" class="fa-mode-value" value="error">
  <div class="panel fa-panel-redirect">
    <label>Redirect URL</label>
    <input type="text" class="fa-field" data-field="default_redirect_url" placeholder="https://example.com">
  </div>
  <div class="panel fa-panel-media">
    <label>Media URL or /media path</label>
    <input type="text" class="fa-field" data-field="media_url" placeholder="/media/... or https://...">
    <label>From /media folder</label>
    <select class="fa-media-select" aria-label="Select media file">
      <option value="">— Select file (optional) —</option>
    </select>
    <label>Type</label>
    <select class="fa-field fa-select" data-field="media_type">
      <option value="image">Image</option>
      <option value="gif">GIF</option>
      <option value="video" selected>Video</option>
      <option value="youtube">YouTube</option>
    </select>
    <label>Tab title mode</label>
    <select class="fa-field fa-tab-mode" data-field="media_tab_mode">
      <option value="none" selected>None</option>
      <option value="static">Static</option>
      <option value="scrolling">Scrolling</option>
      <option value="rotating">Rotating</option>
    </select>
    <div class="panel fa-tab-panel fa-tab-static">
      <label>Static title</label>
      <input type="text" class="fa-field" data-field="media_tab_static_text" maxlength="500">
    </div>
    <div class="panel fa-tab-panel fa-tab-scrolling">
      <label>Scrolling title</label>
      <input type="text" class="fa-field" data-field="media_tab_scrolling_text" maxlength="500">
    </div>
    <div class="panel fa-tab-panel fa-tab-rotating">
      <label>Rotating titles (one per line)</label>
      <textarea class="fa-field" data-field="media_tab_rotating_messages" rows="2" maxlength="10000"></textarea>
      <label>Rotate interval (seconds)</label>
      <input type="number" class="fa-field" data-field="media_tab_rotate_interval_sec" value="3" min="1" max="60" style="max-width:6rem;">
    </div>
  </div>
  <div class="panel fa-panel-error active">
    <label>HTTP status</label>
    <select class="fa-field fa-select" data-field="status_code"></select>
  </div>
</div>
"""

FINAL_ACTIONS_JS = """
(function() {
  var MAX_ACTIONS = 20;
  var STATUS_CODES = [403, 404, 410, 412, 418, 500, 501, 502, 503, 504, 505, 506, 507, 508];
  var mediaFilesCache = null;

  function faRandomId() {
    if (window.crypto && crypto.getRandomValues) {
      var a = new Uint8Array(8);
      crypto.getRandomValues(a);
      return Array.from(a).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    }
    return 'fa' + Math.random().toString(16).slice(2);
  }

  function faGetMediaFiles() {
    if (mediaFilesCache) return Promise.resolve(mediaFilesCache);
    return fetch('/api/media-files', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(files) { mediaFilesCache = files || []; return mediaFilesCache; })
      .catch(function() { mediaFilesCache = []; return mediaFilesCache; });
  }

  function faPopulateStatusSelect(sel) {
    if (!sel || sel.options.length) return;
    STATUS_CODES.forEach(function(code) {
      var opt = document.createElement('option');
      opt.value = String(code);
      opt.textContent = String(code);
      sel.appendChild(opt);
    });
  }

  function faBindModeToggles(card) {
    var toggles = card.querySelectorAll('.fa-mode-btn');
    var modeInput = card.querySelector('.fa-mode-value');
    var panels = {
      redirect: card.querySelector('.fa-panel-redirect'),
      media: card.querySelector('.fa-panel-media'),
      error: card.querySelector('.fa-panel-error')
    };
    toggles.forEach(function(btn) {
      btn.addEventListener('click', function() {
        var m = btn.getAttribute('data-mode');
        toggles.forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        if (modeInput) modeInput.value = m;
        Object.keys(panels).forEach(function(k) {
          if (panels[k]) panels[k].classList.toggle('active', k === m);
        });
        faSyncActionSummary(card);
      });
    });
    var tabMode = card.querySelector('.fa-tab-mode');
    if (tabMode) {
      tabMode.addEventListener('change', function() {
        var v = tabMode.value;
        card.querySelectorAll('.fa-tab-panel').forEach(function(p) {
          p.classList.remove('active');
          if (p.classList.contains('fa-tab-' + v)) p.classList.add('active');
        });
      });
    }
    card.querySelectorAll('.fa-field, .fa-action-label-input').forEach(function(el) {
      el.addEventListener('input', function() { faSyncActionSummary(card); });
      el.addEventListener('change', function() { faSyncActionSummary(card); });
    });
  }

  function faSyncActionSummary(card) {
    var summary = card.querySelector('.fa-action-summary');
    if (!summary) return;
    var mode = (card.querySelector('.fa-mode-value') || {}).value || 'error';
    var label = (card.querySelector('.fa-action-label-input') || {}).value || '';
    var bits = [mode];
    if (label.trim()) bits.unshift(label.trim());
    if (mode === 'redirect') {
      var u = (card.querySelector('[data-field="default_redirect_url"]') || {}).value || '';
      if (u.trim()) bits.push(u.trim().slice(0, 48));
    } else if (mode === 'media') {
      var mu = (card.querySelector('[data-field="media_url"]') || {}).value || '';
      if (mu.trim()) bits.push(mu.trim().slice(0, 48));
    } else {
      var sc = (card.querySelector('[data-field="status_code"]') || {}).value || '404';
      bits.push('HTTP ' + sc);
    }
    summary.textContent = bits.join(' · ');
  }

  function faSerializeCard(card) {
    function get(field) {
      var el = card.querySelector('[data-field="' + field + '"]');
      return el ? String(el.value || '').trim() : '';
    }
    var tabInterval = parseInt(get('media_tab_rotate_interval_sec') || '3', 10);
    if (isNaN(tabInterval) || tabInterval < 1) tabInterval = 3;
    if (tabInterval > 60) tabInterval = 60;
    var mode = (card.querySelector('.fa-mode-value') || {}).value || 'error';
    return {
      id: (card.getAttribute('data-fa-id') || '').trim() || faRandomId(),
      label: (card.querySelector('.fa-action-label-input') || {}).value || '',
      mode: mode,
      default_redirect_url: get('default_redirect_url'),
      media_url: get('media_url'),
      media_type: get('media_type'),
      media_tab_mode: get('media_tab_mode') || 'none',
      media_tab_static_text: get('media_tab_static_text'),
      media_tab_scrolling_text: get('media_tab_scrolling_text'),
      media_tab_rotating_messages: get('media_tab_rotating_messages'),
      media_tab_rotate_interval_sec: tabInterval,
      status_code: parseInt(get('status_code') || '404', 10) || 404
    };
  }

  function faSerializeSingle(root) {
    if (!root) return { mode: 'error', status_code: 404 };
    function q(sel) { return root.querySelector(sel); }
    function val(name) {
      var el = q('[name="' + name + '"]') || q('#' + name) || q('[data-field="' + name + '"]');
      return el ? String(el.value || '').trim() : '';
    }
    function hostVal(field) {
      var el = root.querySelector('.host-input[data-field="' + field + '"]') || root.querySelector('.host-mode[data-field="' + field + '"]');
      return el ? String(el.value || '').trim() : '';
    }
    var mode = val('mode') || hostVal('mode') || 'error';
    var tabInterval = parseInt(val('media_tab_rotate_interval_sec') || hostVal('media_tab_rotate_interval_sec') || '3', 10);
    if (isNaN(tabInterval) || tabInterval < 1) tabInterval = 3;
    if (tabInterval > 60) tabInterval = 60;
    return {
      mode: mode,
      default_redirect_url: val('default_redirect_url') || hostVal('default_redirect_url'),
      media_url: val('media_url') || hostVal('media_url'),
      media_type: val('media_type') || hostVal('media_type'),
      media_tab_mode: val('media_tab_mode') || hostVal('media_tab_mode') || 'none',
      media_tab_static_text: val('media_tab_static_text') || hostVal('media_tab_static_text'),
      media_tab_scrolling_text: val('media_tab_scrolling_text') || hostVal('media_tab_scrolling_text'),
      media_tab_rotating_messages: val('media_tab_rotating_messages') || hostVal('media_tab_rotating_messages'),
      media_tab_rotate_interval_sec: tabInterval,
      status_code: parseInt(val('status_code') || hostVal('status_code') || '404', 10) || 404
    };
  }

  function faSerializeScope(scopeEl) {
    var randomToggle = scopeEl.querySelector('.fa-random-toggle');
    var randomOn = randomToggle && randomToggle.checked;
    var singleRoot = scopeEl.querySelector('.fa-single-wrap') || scopeEl;
    var base = faSerializeSingle(singleRoot);
    if (!randomOn) {
      return Object.assign({}, base, { random_actions_enabled: false, actions: [] });
    }
    var actions = [];
    scopeEl.querySelectorAll('.fa-actions-list .fa-action-card').forEach(function(card) {
      actions.push(faSerializeCard(card));
    });
    return Object.assign({}, base, { random_actions_enabled: true, actions: actions });
  }

  function faRefreshScopeChrome(scopeEl) {
    var list = scopeEl.querySelector('.fa-actions-list');
    var count = list ? list.querySelectorAll('.fa-action-card').length : 0;
    var badge = scopeEl.querySelector('.fa-count-badge');
    var empty = scopeEl.querySelector('.fa-empty');
    if (badge) badge.textContent = String(count);
    if (empty) empty.classList.toggle('visible', count === 0);
    var addBtn = scopeEl.querySelector('.fa-btn-add');
    if (addBtn) addBtn.disabled = count >= MAX_ACTIONS;
  }

  function faToggleRandom(scopeEl) {
    var randomOn = scopeEl.querySelector('.fa-random-toggle').checked;
    var single = scopeEl.querySelector('.fa-single-wrap');
    var multi = scopeEl.querySelector('.fa-multi-wrap');
    if (single) single.classList.toggle('fa-hidden', randomOn);
    if (multi) multi.hidden = !randomOn;
    if (randomOn) {
      var list = scopeEl.querySelector('.fa-actions-list');
      if (list && !list.querySelector('.fa-action-card')) {
        faAppendAction(scopeEl, faSerializeSingle(single || scopeEl));
      }
    }
    faRefreshScopeChrome(scopeEl);
  }

  function faFillCard(card, action) {
    action = action || {};
    card.setAttribute('data-fa-id', action.id || faRandomId());
    var labelEl = card.querySelector('.fa-action-label-input');
    if (labelEl) labelEl.value = action.label || '';
    var mode = action.mode || 'error';
    var modeInput = card.querySelector('.fa-mode-value');
    if (modeInput) modeInput.value = mode;
    card.querySelectorAll('.fa-mode-btn').forEach(function(btn) {
      btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
    });
    card.querySelector('.fa-panel-redirect').classList.toggle('active', mode === 'redirect');
    card.querySelector('.fa-panel-media').classList.toggle('active', mode === 'media');
    card.querySelector('.fa-panel-error').classList.toggle('active', mode === 'error');
    function set(field, value) {
      var el = card.querySelector('[data-field="' + field + '"]');
      if (el && value != null) el.value = value;
    }
    set('default_redirect_url', action.default_redirect_url || '');
    set('media_url', action.media_url || '');
    set('media_type', action.media_type || 'video');
    set('media_tab_mode', action.media_tab_mode || 'none');
    set('media_tab_static_text', action.media_tab_static_text || '');
    set('media_tab_scrolling_text', action.media_tab_scrolling_text || '');
    set('media_tab_rotating_messages', action.media_tab_rotating_messages || '');
    set('media_tab_rotate_interval_sec', action.media_tab_rotate_interval_sec != null ? action.media_tab_rotate_interval_sec : 3);
    set('status_code', action.status_code != null ? action.status_code : 404);
    var tabMode = action.media_tab_mode || 'none';
    card.querySelectorAll('.fa-tab-panel').forEach(function(p) {
      p.classList.remove('active');
      if (p.classList.contains('fa-tab-' + tabMode)) p.classList.add('active');
    });
    faSyncActionSummary(card);
  }

  function faBindMediaSelect(card) {
    var sel = card.querySelector('.fa-media-select');
    var input = card.querySelector('[data-field="media_url"]');
    if (!sel) return;
    faGetMediaFiles().then(function(files) {
      while (sel.options.length > 1) sel.remove(1);
      (files || []).forEach(function(f) {
        var opt = document.createElement('option');
        opt.value = '/media/' + f;
        opt.textContent = f;
        sel.appendChild(opt);
      });
      if (input && input.value && input.value.indexOf('/media/') === 0) sel.value = input.value;
    });
    if (!sel.dataset.bound) {
      sel.dataset.bound = '1';
      sel.addEventListener('change', function() {
        if (sel.value && input) input.value = sel.value;
        faSyncActionSummary(card);
      });
    }
  }

  function faAppendAction(scopeEl, action) {
    var tpl = document.getElementById('fa-action-template');
    var list = scopeEl.querySelector('.fa-actions-list');
    if (!tpl || !list) return;
    if (list.querySelectorAll('.fa-action-card').length >= MAX_ACTIONS) return;
    var card = tpl.cloneNode(true);
    card.removeAttribute('id');
    card.style.display = '';
    faPopulateStatusSelect(card.querySelector('[data-field="status_code"]'));
    faFillCard(card, action || {});
    faBindModeToggles(card);
    faBindMediaSelect(card);
    card.querySelector('.fa-remove-action').addEventListener('click', function() {
      if (!window.confirm('Delete this action from the list?')) return;
      card.remove();
      faRefreshScopeChrome(scopeEl);
    });
    list.appendChild(card);
    faRefreshScopeChrome(scopeEl);
  }

  window.initFinalActionsScope = function(scopeEl, initial) {
    if (!scopeEl) return;
    initial = initial || {};
    var toggle = scopeEl.querySelector('.fa-random-toggle');
    if (toggle) {
      toggle.checked = !!initial.random_actions_enabled;
      toggle.addEventListener('change', function() { faToggleRandom(scopeEl); });
    }
    var actions = Array.isArray(initial.actions) ? initial.actions : [];
    actions.forEach(function(a) { faAppendAction(scopeEl, a); });
    faToggleRandom(scopeEl);
    var addBtn = scopeEl.querySelector('.fa-btn-add');
    if (addBtn) {
      addBtn.addEventListener('click', function() {
        faAppendAction(scopeEl, { mode: 'error', status_code: 404 });
      });
    }
    var clearBtn = scopeEl.querySelector('.fa-btn-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', function() {
        var list = scopeEl.querySelector('.fa-actions-list');
        if (!list || !list.querySelector('.fa-action-card')) return;
        if (!window.confirm('Remove all actions from this list?')) return;
        list.innerHTML = '';
        faRefreshScopeChrome(scopeEl);
      });
    }
    faRefreshScopeChrome(scopeEl);
  };

  window.serializeFinalActionsScope = faSerializeScope;
})();
"""
