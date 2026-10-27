/* HomeGuard: backend/app.js
   Data
   - alerts.json   (required)  [{id, status, timestamp, src_ip, dst_ip, protocol, dst_port, length, explanation}]
   - devices.json  (optional)  [{name, type, ip, last_active}]
     If devices.json is missing, devices are derived from the src_ip values in alerts.json.

   Pause / Mark as safe / Add / Remove only live in the page for now (reset on reload).
   Wire them to Flask routes when the backend is ready.
*/
(function () {
  'use strict';

  const ALERTS_URL = '../alerts.json';
  const DEVICES_URL = 'devices.json';
  const POLL_MS = 5000;

  const state = { alerts: [], devices: [], error: false, view: 'dashboard', selected: null, q: '', filter: 'all' };
  const safe = new Set();      // alert ids marked safe
  const paused = new Set();    // device IPs paused
  const removed = new Set();   // device IPs removed
  const added = [];            // devices added by hand
  let fileDevices = null;      // last devices.json contents

  /* ---------- helpers ---------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const cls = s => String(s ?? '').toLowerCase().replace(/[^a-z0-9-]/g, '');
  const when = v => {
    const d = new Date(v);
    return isNaN(d) ? String(v ?? '') : d.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
  };
  const ago = v => {
    const m = Math.max(0, Math.round((Date.now() - new Date(v)) / 60000));
    if (isNaN(m)) return 'n/a';
    if (m < 1) return 'Now';
    if (m < 60) return m + ' min ago';
    const h = Math.round(m / 60);
    return h < 24 ? h + ' hr ago' : Math.round(h / 24) + ' d ago';
  };
  // Drop the model's "Here's an explanation..." lead-in line
  const clean = t => String(t ?? '').replace(/^here's an explanation[^\n]*\n+/i, '').trim();

  const LABEL = { flagged: 'Flagged', review: 'Review', normal: 'Normal', paused: 'Paused' };
  const sev = a => {
    const s = cls(a.status);
    if (['flagged', 'critical', 'high', 'threat', 'malicious'].includes(s)) return 'flagged';
    if (['normal', 'safe', 'low', 'info'].includes(s)) return 'normal';
    return 'review';
  };
  const isOpen = a => !safe.has(a.id) && sev(a) !== 'normal';
  const badge = s => `<span class="alert-status ${s}">${LABEL[s]}</span>`;
  const alertTitle = a => `${LABEL[sev(a)]} connection to ${a.dst_ip}${a.dst_port ? ':' + a.dst_port : ''}`;

  /* ---------- devices ---------- */
  function buildDevices(file) {
    const map = new Map();
    (file || []).forEach(d => map.set(d.ip, { ...d }));
    state.alerts.forEach(a => {
      if (!a.src_ip) return;
      const d = map.get(a.src_ip);
      if (!d) map.set(a.src_ip, { name: 'Device ' + a.src_ip, type: 'Unknown', ip: a.src_ip, last_active: a.timestamp });
      else if (d.derived !== false && new Date(a.timestamp) > new Date(d.last_active)) d.last_active = a.timestamp;
    });
    added.forEach(d => map.set(d.ip, d));
    removed.forEach(ip => map.delete(ip));
    return [...map.values()];
  }
  function deviceStatus(d) {
    if (paused.has(d.ip)) return 'paused';
    const mine = state.alerts.filter(a => a.src_ip === d.ip && isOpen(a));
    if (mine.some(a => sev(a) === 'flagged')) return 'flagged';
    return mine.length ? 'review' : 'normal';
  }

  /* ---------- page scaffolding (nav, tab area, add dialog) ---------- */
  const main = $('main');
  const dashEls = [$('main > h2'), $('#summary'), $('#alerts-container')].filter(Boolean);
  const tabView = document.createElement('section');
  tabView.id = 'tab-view';
  tabView.hidden = true;
  main.appendChild(tabView);

  if (!$('.nav')) {
    const nav = document.createElement('nav');
    nav.className = 'nav';
    nav.setAttribute('aria-label', 'Main');
    nav.innerHTML = ['dashboard', 'devices', 'alerts']
      .map(v => `<button type="button" data-view="${v}">${v[0].toUpperCase() + v.slice(1)}</button>`).join('');
    ($('header') || document.body).appendChild(nav);
  }

  if (!$('#addDialog')) {
    const dlg = document.createElement('dialog');
    dlg.id = 'addDialog';
    dlg.innerHTML = `
      <form method="dialog" id="addForm">
        <h2>Add a device</h2>
        <label>Device name<input name="name" required maxlength="40" placeholder="Kitchen speaker"></label>
        <label>Type
          <select name="type"><option>Camera</option><option>Entertainment</option><option>Mobile</option><option>Computer</option><option>Smart home</option><option>Other</option></select>
        </label>
        <label>IP address<input name="ip" required pattern="^\\d{1,3}(\\.\\d{1,3}){3}$" placeholder="192.168.1.50"></label>
        <div class="row">
          <button type="button" class="btn" data-action="close-add">Cancel</button>
          <button class="btn primary" value="ok">Add device</button>
        </div>
      </form>`;
    document.body.appendChild(dlg);
  }

  /* ---------- Dashboard tab (original index.html behaviour) ---------- */
  function renderDashboard() {
    const summary = $('#summary-text');
    const container = $('#alerts-container');
    container.innerHTML = '';

    if (state.error) {
      summary.textContent = 'Could not load alerts. Make sure alerts.json is in the same folder.';
      return;
    }
    if (state.alerts.length === 0) {
      summary.textContent = 'No alerts detected. Your network looks normal.';
      return;
    }
    summary.textContent = `${state.alerts.length} alert(s) detected on your network.`;

    state.alerts.forEach(alert => {
      const status = cls(alert.status);
      const card = document.createElement('div');
      card.classList.add('alert-card');
      if (status) card.classList.add(status);
      card.innerHTML = `
        <div class="alert-header">
          <span class="alert-status ${status}">${esc(alert.status)}</span>
          <span class="alert-time">${esc(alert.timestamp)}</span>
        </div>
        <p class="alert-explanation">${esc(alert.explanation)}</p>
        <div class="alert-details">
          <span>Device: ${esc(alert.src_ip)}</span>
          <span>Destination: ${esc(alert.dst_ip)}</span>
          <span>Protocol: ${esc(alert.protocol)}</span>
          <span>Port: ${esc(alert.dst_port)}</span>
        </div>`;
      container.appendChild(card);
    });
  }

  /* ---------- Devices tab ---------- */
  function rowsHtml() {
    const list = state.devices.filter(d => {
      const hit = `${d.name} ${d.ip} ${d.type}`.toLowerCase().includes(state.q.toLowerCase());
      return hit && (state.filter === 'all' || deviceStatus(d) === state.filter);
    });
    if (!list.length) return '<tr><td colspan="6" class="empty">No devices match your search.</td></tr>';
    return list.map(d => `<tr>
      <td class="name">${esc(d.name)}</td><td>${esc(d.type)}</td><td>${esc(d.ip)}</td>
      <td>${esc(ago(d.last_active))}</td><td>${badge(deviceStatus(d))}</td>
      <td><button type="button" class="link" data-action="remove" data-id="${esc(d.ip)}">Remove</button></td></tr>`).join('');
  }

  function viewDevices() {
    const opts = ['all', 'flagged', 'review', 'normal', 'paused']
      .map(s => `<option value="${s}" ${state.filter === s ? 'selected' : ''}>${s === 'all' ? 'All statuses' : LABEL[s]}</option>`).join('');
    return `
      <div class="head">
        <div><h2>Devices</h2><p class="muted">${state.devices.length} devices seen on your home network.</p></div>
        <button type="button" class="btn primary" data-action="add">Add device</button>
      </div>
      <div class="panel">
        <div class="toolbar">
          <input id="q" type="search" placeholder="Search devices" aria-label="Search devices" value="${esc(state.q)}">
          <select id="statusFilter" aria-label="Filter by status">${opts}</select>
        </div>
        <div class="table-wrap"><table>
          <thead><tr><th>Device</th><th>Type</th><th>IP address</th><th>Last active</th><th>Status</th><th></th></tr></thead>
          <tbody id="rows">${rowsHtml()}</tbody>
        </table></div>
      </div>`;
  }

  /* ---------- Alerts tab ---------- */
  function viewAlerts() {
    if (!state.alerts.length) return '<h2>Recent alerts</h2><div class="panel empty">No alerts. HomeGuard will show anything suspicious here.</div>';
    const open = state.alerts.filter(isOpen);
    if (!state.alerts.some(a => a.id === state.selected)) state.selected = (open[0] || state.alerts[0]).id;
    const a = state.alerts.find(x => x.id === state.selected);
    const dev = state.devices.find(d => d.ip === a.src_ip);
    const isSafe = safe.has(a.id);
    const level = isSafe ? 'normal' : sev(a);

    const list = state.alerts.map(x => {
      const l = safe.has(x.id) ? 'normal' : sev(x);
      return `<button type="button" class="alert-row ${l}" data-action="select-alert" data-id="${esc(x.id)}" aria-pressed="${x.id === state.selected}">
        <span class="t">${esc(x.src_ip)}</span><span class="s">${esc(when(x.timestamp))}</span>
        <span>${esc(alertTitle(x))}</span></button>`;
    }).join('');

    return `
      <h2>Recent alerts</h2>
      <p class="muted lead">Review activity that may need your attention.</p>
      <div class="split">
        <div>${list}</div>
        <section class="panel">
          ${isSafe ? '<span class="alert-status normal">Marked safe</span>' : badge(level)}
          <h3 class="detail-title">${esc(alertTitle(a))}</h3>
          <p class="alert-explanation detail-summary">${esc(clean(a.explanation))}</p>
          <dl>
            <dt>Device</dt><dd>${esc(a.src_ip)}</dd>
            <dt>Destination</dt><dd>${esc(a.dst_ip)}</dd>
            <dt>Protocol</dt><dd>${esc(a.protocol)}${a.dst_port ? ' (port ' + esc(a.dst_port) + ')' : ''}</dd>
            <dt>Packet size</dt><dd>${esc(a.length ?? 'n/a')}${a.length ? ' bytes' : ''}</dd>
            <dt>First observed</dt><dd>${esc(when(a.timestamp))}</dd>
          </dl>
          ${isSafe ? '' : `
          <div class="review-box"><b>Recommended review</b>If you don't recognize this activity, pause the device and change its password.</div>
          <div class="actions">
            <button type="button" class="btn primary" data-action="pause" data-id="${esc(a.src_ip)}" ${!dev || paused.has(a.src_ip) ? 'disabled' : ''}>${paused.has(a.src_ip) ? 'Device paused' : 'Pause device'}</button>
            <button type="button" class="btn" data-action="safe" data-id="${esc(a.id)}">Mark as safe</button>
          </div>`}
        </section>
      </div>`;
  }

  /* ---------- render + data ---------- */
  function render() {
    document.querySelectorAll('.nav button').forEach(b => {
      if (b.dataset.view === state.view) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    const dash = state.view === 'dashboard';
    dashEls.forEach(el => { el.hidden = !dash; });
    tabView.hidden = dash;
    if (dash) renderDashboard();
    else tabView.innerHTML = state.view === 'devices' ? viewDevices() : viewAlerts();
  }

  async function load() {
    try {
      const res = await fetch(ALERTS_URL, { cache: 'no-store' });
      if (!res.ok) throw new Error('alerts.json: HTTP ' + res.status);
      state.alerts = await res.json();
      state.error = false;
    } catch (err) {
      state.error = true;
      console.error(err);
    }
    let file = null;
    try {
      const res = await fetch(DEVICES_URL, { cache: 'no-store' });
      if (res.ok) file = await res.json();
    } catch (err) { /* devices.json is optional */ }
    fileDevices = file;
    state.devices = buildDevices(file);

    const typing = document.activeElement && document.activeElement.id === 'q';
    if (!typing && !$('#addDialog').open) render();
  }

  /* ---------- events ---------- */
  document.addEventListener('click', e => {
    const nav = e.target.closest('[data-view]');
    if (nav) { state.view = nav.dataset.view; render(); return; }
    const t = e.target.closest('[data-action]');
    if (!t) return;
    const id = t.dataset.id;
    const alertById = () => state.alerts.find(a => String(a.id) === id);

    switch (t.dataset.action) {
      case 'select-alert': state.selected = alertById()?.id; render(); break;
      case 'safe': if (alertById()) { safe.add(alertById().id); render(); } break;
      case 'pause': paused.add(id); render(); break;
      case 'remove':
        if (confirm(`Remove ${id} from monitoring?`)) {
          removed.add(id);
          const i = added.findIndex(d => d.ip === id);
          if (i > -1) added.splice(i, 1);
          state.devices = state.devices.filter(d => d.ip !== id);
          render();
        }
        break;
      case 'add': $('#addDialog').showModal(); break;
      case 'close-add': $('#addDialog').close(); break;
    }
  });

  document.addEventListener('input', e => {
    if (e.target.id === 'q') { state.q = e.target.value; $('#rows').innerHTML = rowsHtml(); }
  });
  document.addEventListener('change', e => {
    if (e.target.id === 'statusFilter') { state.filter = e.target.value; $('#rows').innerHTML = rowsHtml(); }
  });

  $('#addForm').addEventListener('submit', e => {
    if (e.submitter && e.submitter.value !== 'ok') return;
    const f = new FormData(e.target);
    const d = { name: f.get('name').trim(), type: f.get('type'), ip: f.get('ip').trim(), last_active: new Date().toISOString(), derived: false };
    removed.delete(d.ip);
    added.push(d);
    state.devices = buildDevices(fileDevices);
    e.target.reset();
    render();
  });

  load();
  setInterval(load, POLL_MS);
})();