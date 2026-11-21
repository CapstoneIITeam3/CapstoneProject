/* Shared helpers: API wrapper, formatting, alert banner polling, log detail modal. */
const TW = (() => {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  let online = true;
  function setOnline(ok) {
    if (ok === online) return;
    online = ok;
    $('#offlineBar').hidden = ok;
    const live = $('#liveStatus');
    live.classList.toggle('offline', !ok);
    live.querySelector('.txt').textContent = ok ? 'Live' : 'Offline';
  }

  async function api(url, opts = {}) {
    const o = { credentials: 'same-origin', headers: { Accept: 'application/json' }, ...opts };
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers['Content-Type'] = 'application/json';
    }
    if (o.method && o.method !== 'GET') o.headers['X-CSRF-Token'] = csrf;
    let res;
    try {
      res = await fetch(url, o);
    } catch (e) {
      setOnline(false);
      throw new Error('Cannot reach the server.');
    }
    if (res.status === 401) { location.href = '/login?next=' + encodeURIComponent(location.pathname); throw new Error('Session expired'); }
    const data = await res.json().catch(() => ({}));
    if (res.status === 503) { setOnline(false); throw new Error(data.error || 'Service unavailable'); }
    setOnline(true);
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  /* ---------- formatting ---------- */
  const d = (iso) => (iso ? new Date(iso) : null);
  const fmtTime = (iso) => (iso ? d(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '—');
  const fmtDateTime = (iso) => (iso ? d(iso).toLocaleString([], { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '—');
  const fmtNum = (n) => (n == null ? '—' : Number(n).toLocaleString());
  const fmtBytes = (n) => {
    if (n == null) return '—';
    if (n < 1024) return `${n|0} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  };
  function ago(iso) {
    if (!iso) return '';
    const s = Math.max(0, (Date.now() - d(iso)) / 1000);
    if (s < 60) return `${s | 0}s ago`;
    if (s < 3600) return `${(s / 60) | 0}m ago`;
    if (s < 86400) return `${(s / 3600) | 0}h ago`;
    return `${(s / 86400) | 0}d ago`;
  }

  const ICONS = {
    Normal: '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 6.2 5 8.6l4.6-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    Suspicious: '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M6 3.2v3.4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="6" cy="8.6" r=".9" fill="currentColor"/></svg>',
    Malicious: '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M6 .8 11.4 10.6H.6z" fill="currentColor"/><path d="M6 4.3v3" stroke="#3a1514" stroke-width="1.4" stroke-linecap="round"/><circle cx="6" cy="8.8" r=".75" fill="#3a1514"/></svg>',
  };
  const pill = (tier) => (tier ? `<span class="pill pill-${tier}">${ICONS[tier] || ''}${tier}</span>` : '—');
  const statusPill = (s) => `<span class="pill pill-${s}">${s[0].toUpperCase() + s.slice(1)}</span>`;
  const tierColor = (t) => ({ Normal: '#0ca30c', Suspicious: '#fab219', Malicious: '#d03b3b' }[t] || '#8f8e86');
  function scoreBar(score, tier) {
    if (score == null) return '—';
    return `<span class="score"><span class="track"><span style="width:${Math.round(score * 100)}%;background:${tierColor(tier)}"></span></span><span class="mono">${score.toFixed(3)}</span></span>`;
  }

  let toastTimer;
  function toast(msg, isError = false) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.toggle('error', isError);
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), 3500);
  }

  /* ---------- detail modal ---------- */
  const modal = $('#detailModal');
  function closeModal(m) { m.hidden = true; }
  document.addEventListener('click', (e) => {
    if (e.target.matches('[data-close]') || e.target.classList.contains('modal-bg')) closeModal(e.target.closest('.modal-bg'));
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') document.querySelectorAll('.modal-bg:not([hidden])').forEach(closeModal);
  });

  async function openLog(id) {
    modal.hidden = false;
    $('#detailTitle').textContent = `Log record #${id}`;
    $('#detailSub').textContent = '';
    $('#detailBody').innerHTML = '<span class="spinner"></span> Loading…';
    $('#detailFoot').innerHTML = '';
    try {
      const r = await api(`/api/logs/${id}`);
      $('#detailSub').textContent = `${fmtDateTime(r.timestamp)} · source: ${r.source}`;
      const explain = (r.explanation || []).map((x) =>
        `<li><b class="mono">${esc(x.feature)}</b> <span class="mono secondary">= ${esc(x.value)}</span> <span class="muted">— ${esc(x.note)}</span></li>`).join('');
      const feats = Object.entries(r.features).map(([k, v]) => {
        const nz = typeof v === 'string' ? v !== '' : v !== 0;
        return `<div class="${nz ? 'nz' : ''}"><span title="${esc(k)}">${esc(k)}</span><span class="mono">${esc(typeof v === 'number' ? +v.toFixed(4) : v)}</span></div>`;
      }).join('');
      $('#detailBody').innerHTML = `
        <div class="kv">
          <div><span>Classification</span><b>${pill(r.tier)}</b></div>
          <div><span>Threat score</span><b>${scoreBar(r.threat_score, r.tier)}</b></div>
          <div><span>Attack category</span><b>${esc(r.attack_category || '—')}</b></div>
          <div><span>Source → destination</span><b class="mono">${esc(r.src_ip || '—')} → ${esc(r.dst_ip || '—')}</b></div>
          <div><span>Protocol / service / flag</span><b class="mono">${esc(r.protocol)} / ${esc(r.service)} / ${esc(r.flag)}</b></div>
          <div><span>Bytes (src / dst)</span><b class="mono">${fmtBytes(r.src_bytes)} / ${fmtBytes(r.dst_bytes)}</b></div>
          <div><span>Anomaly score (IF)</span><b class="mono">${r.anomaly_score != null ? r.anomaly_score.toFixed(4) : '—'}</b></div>
          <div><span>RF P(attack)</span><b class="mono">${r.rf_probability != null ? r.rf_probability.toFixed(4) : '—'}</b></div>
          <div><span>Thresholds applied</span><b class="mono">S ≥ ${r.suspicious_threshold_applied} · M ≥ ${r.threshold_applied}</b></div>
          <div><span>Model</span><b class="mono">${esc(r.model_version)}</b></div>
          <div><span>Dataset label</span><b class="mono">${esc(r.true_label || '—')}</b></div>
          <div><span>Alert</span><b>${r.alert_id ? `#${r.alert_id} ${statusPill(r.alert_status)}` : '<span class="muted">none</span>'}</b></div>
        </div>
        <p class="section-label">Why it was flagged</p>
        <ul class="explain">${explain || '<li class="muted">No explanation available for this model.</li>'}</ul>
        <p class="section-label">All feature values <span class="muted" style="text-transform:none;letter-spacing:0;font-weight:400">(non-zero in bold)</span></p>
        <div class="feature-grid">${feats}</div>`;
      if (r.alert_id && r.alert_status === 'open') {
        $('#detailFoot').innerHTML = `<button class="btn" data-dismiss-alert="${r.alert_id}">Dismiss (false positive)</button>
          <button class="btn primary" data-ack-alert="${r.alert_id}">Acknowledge alert</button>`;
      } else {
        $('#detailFoot').innerHTML = '<button class="btn" data-close>Close</button>';
      }
    } catch (e) {
      $('#detailBody').innerHTML = `<div class="flash error">${esc(e.message)}</div>`;
    }
  }

  async function alertAction(id, action, note) {
    const r = await api(`/api/alerts/${id}/${action}`, { method: 'POST', body: note ? { note } : {} });
    document.dispatchEvent(new CustomEvent('tw:alert-changed', { detail: r }));
    pollBanner();
    return r;
  }

  document.addEventListener('click', async (e) => {
    const ack = e.target.closest('[data-ack-alert]');
    const dis = e.target.closest('[data-dismiss-alert]');
    if (!ack && !dis) return;
    e.stopPropagation();
    const id = (ack || dis).dataset[ack ? 'ackAlert' : 'dismissAlert'];
    try {
      await alertAction(id, ack ? 'acknowledge' : 'dismiss');
      toast(`Alert #${id} ${ack ? 'acknowledged' : 'dismissed'}.`);
      if (!modal.hidden) closeModal(modal);
    } catch (err) { toast(err.message, true); }
  });

  /* ---------- alert banner (polls for open Malicious alerts) ---------- */
  const banner = $('#alertBanner');
  let bannerAlert = null;
  let collapsedAt = 0;
  try { collapsedAt = +sessionStorage.getItem('tw-banner-collapsed-at') || 0; } catch (_) {}

  async function pollBanner() {
    try {
      const r = await api('/api/alerts?status=open&severity=Malicious&per_page=1');
      const badge = $('#navAlertCount');
      badge.textContent = r.counts.open > 999 ? '999+' : r.counts.open;
      badge.hidden = r.counts.open === 0;
      const a = r.items[0];
      if (!a) { banner.hidden = true; bannerAlert = null; return; }
      const isNew = !bannerAlert || a.id !== bannerAlert.id;
      bannerAlert = a;
      $('#bannerCount').textContent = r.total > 1 ? `${r.total} open` : '';
      $('#bannerDetail').innerHTML =
        `${esc(a.attack_category || 'Threat')} from <span class="mono">${esc(a.src_ip)}</span> → <span class="mono">${esc(a.dst_ip || '—')}</span> ` +
        `(${esc(a.protocol)}/${esc(a.service)}) · score <span class="mono">${a.threat_score.toFixed(3)}</span> · ${ago(a.created_at)}`;
      // a newer alert than the one the user collapsed re-expands the banner
      if (isNew && a.id > collapsedAt) setCollapsed(false);
      banner.hidden = false;
    } catch (_) { /* offline bar handles it */ }
  }
  function setCollapsed(c) {
    banner.classList.toggle('collapsed', c);
    const t = $('#bannerToggle');
    t.textContent = c ? '▼' : '▲';
    t.setAttribute('aria-expanded', String(!c));
    t.title = c ? 'Expand banner' : 'Collapse banner';
  }
  $('#bannerToggle').addEventListener('click', () => {
    const c = !banner.classList.contains('collapsed');
    setCollapsed(c);
    if (c && bannerAlert) {
      collapsedAt = bannerAlert.id;
      try { sessionStorage.setItem('tw-banner-collapsed-at', collapsedAt); } catch (_) {}
    }
  });
  $('#bannerView').addEventListener('click', () => bannerAlert && openLog(bannerAlert.log_id));
  $('#bannerAck').addEventListener('click', async () => {
    if (!bannerAlert) return;
    try { await alertAction(bannerAlert.id, 'acknowledge'); toast(`Alert #${bannerAlert.id} acknowledged.`); }
    catch (e) { toast(e.message, true); }
  });
  pollBanner();
  setInterval(pollBanner, 3000);

  /* Chart.js defaults for the dark theme */
  if (window.Chart) {
    Chart.defaults.color = '#b9b7c0';
    Chart.defaults.borderColor = '#1c1b1f';
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.font.size = 12;
    Chart.defaults.animation.duration = 300;
    Object.assign(Chart.defaults.plugins.tooltip, {
      backgroundColor: '#0b0b0d', borderColor: '#2c2a31', borderWidth: 1, padding: 10,
      titleColor: '#f0efec', bodyColor: '#c3c2b7', cornerRadius: 6, boxPadding: 4,
    });
  }

  return { api, $, esc, fmtTime, fmtDateTime, fmtNum, fmtBytes, ago, pill, statusPill, scoreBar, tierColor, toast, openLog, alertAction, setOnline };
})();
