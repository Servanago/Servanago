// Reference page: search, filter, sort and the card/list switch. State lives in the URL query so a reload or a
// shared link restores it. Query values are only ever matched against the controls' own options, never written as HTML.
(function () {
  var root = document.getElementById('ref');
  if (!root) return;
  var list = document.getElementById('ref-list');
  var cards = Array.prototype.slice.call(list.children);
  var $ = function (id) { return document.getElementById(id); };
  var selects = { kind: $('ref-kind'), status: $('ref-status'), user: $('ref-user'), php: $('ref-php'), compose: $('ref-compose'), sort: $('ref-sort') };
  var q = $('ref-q'), issue = $('ref-issue');
  var views = document.getElementsByName('ref-view');

  // A value is accepted only if the select has that option; anything else means the default.
  function pick(sel, v) {
    if (!sel) return '';
    for (var i = 0; i < sel.options.length; i++) if (sel.options[i].value === v || sel.options[i].text === v) return sel.options[i].value || sel.options[i].text;
    return '';
  }

  function read() {
    var p = new URLSearchParams(location.search);
    q.value = p.get('q') || '';
    Object.keys(selects).forEach(function (k) {
      if (selects[k]) selects[k].value = pick(selects[k], p.get(k) || '') || (k === 'sort' ? 'name' : '');
    });
    issue.checked = p.get('issue') === '1';
    var v = p.get('view') === 'list' ? 'list' : 'cards';
    Array.prototype.forEach.call(views, function (r) { r.checked = r.value === v; });
  }

  function view() {
    return Array.prototype.filter.call(views, function (r) { return r.checked; })[0].value;
  }

  function write() {
    var p = new URLSearchParams();
    if (q.value) p.set('q', q.value);
    Object.keys(selects).forEach(function (k) {
      var s = selects[k];
      if (s && s.value && !(k === 'sort' && s.value === 'name')) p.set(k, s.value);
    });
    if (issue.checked) p.set('issue', '1');
    if (view() === 'list') p.set('view', 'list');
    var qs = p.toString();
    history.replaceState(null, '', location.pathname + (qs ? '?' + qs : ''));
  }

  var order = {
    name: function (a, b) { return cmp(a.dataset.name, b.dataset.name); },
    kind: function (a, b) { return cmp(a.dataset.kind, b.dataset.kind) || order.name(a, b); },
    health: function (a, b) { return rank(a) - rank(b) || order.name(a, b); },
    updated: function (a, b) { return cmp(b.dataset.updated, a.dataset.updated) || order.name(a, b); }
  };
  function cmp(a, b) { return a < b ? -1 : a > b ? 1 : 0; }
  function rank(el) { return { issue: 0, ok: 1, disabled: 2 }[el.dataset.health]; }

  function apply() {
    var text = q.value.trim().toLowerCase(), shown = 0;
    cards.sort(order[selects.sort.value] || order.name).forEach(function (el) {
      var d = el.dataset;
      var ok = (!text || d.filter.indexOf(text) >= 0) &&
        (!selects.kind.value || d.kind === selects.kind.value) &&
        (!selects.status.value || d.health === selects.status.value) &&
        (!selects.user || !selects.user.value || d.user === selects.user.value) &&
        (!selects.php || !selects.php.value || d.php === selects.php.value) &&
        (!selects.compose || !selects.compose.value || d.compose === selects.compose.value) &&
        (!issue.checked || d.health === 'issue');
      el.hidden = !ok;
      if (ok) shown++;
      list.appendChild(el);
    });
    root.className = 'view-' + view();
    cards.forEach(function (el) { // rows are keyboard-operable only in list view
      var row = el.firstElementChild;
      if (view() === 'list') { row.tabIndex = 0; row.setAttribute('role', 'button'); row.setAttribute('aria-expanded', el.hasAttribute('data-open')); }
      else { row.removeAttribute('tabindex'); row.removeAttribute('role'); row.removeAttribute('aria-expanded'); }
    });
    $('ref-count').textContent = shown + ' of ' + cards.length + ' sites';
    $('ref-empty').hidden = shown > 0;
    write();
  }

  [q, issue].concat(Object.keys(selects).map(function (k) { return selects[k]; }), Array.prototype.slice.call(views))
    .forEach(function (el) { if (el) el.addEventListener(el === q ? 'input' : 'change', apply); });
  $('ref-clear').addEventListener('click', function () { history.replaceState(null, '', location.pathname); read(); apply(); });
  // List view: a click on a row's summary opens or closes its details; the edit link still navigates.
  function toggle(row) {
    var art = row.parentNode, open = !art.hasAttribute('data-open');
    if (open) art.setAttribute('data-open', ''); else art.removeAttribute('data-open');
    row.setAttribute('aria-expanded', open);
  }
  list.addEventListener('click', function (e) {
    var row = e.target.closest('.ref-row');
    if (row && !e.target.closest('a') && view() === 'list') toggle(row);
  });
  list.addEventListener('keydown', function (e) {
    var row = e.target.closest('.ref-row');
    if ((e.key === 'Enter' || e.key === ' ') && row && e.target === row && view() === 'list') { e.preventDefault(); toggle(row); }
  });
  read();
  apply();
})();
