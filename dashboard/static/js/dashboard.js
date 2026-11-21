(() => {
  const { api, $, esc, fmtTime, fmtNum, pill, scoreBar, toast, openLog } = TW;
  const C = { mal: '#d03b3b', sus: '#fab219', good: '#0ca30c', blue: '#9b7bff', grid: '#1c1b1f', muted: '#7c7a84' };
  let minutes = 30;
  let paused = false;
  let lastMaxId = 0;
  let thresholds = { suspicious: 0.4, malicious: 0.7 };

  /* ---------------- charts ---------------- */
  const baseScales = (yTitle) => ({
    x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 14 } },
    y: { beginAtZero: true, grid: { color: C.grid }, border: { display: false }, ticks: { precision: 0 },
         title: yTitle ? { display: true, text: yTitle, color: C.muted } : undefined },
  });

  const activity = new Chart($('#activityChart'), {
    type: 'bar',
    data: { labels: [], datasets: [
      { label: 'Malicious', data: [], backgroundColor: C.mal, stack: 's', borderRadius: 2, borderSkipped: 'bottom', categoryPercentage: .82, barPercentage: .9 },
      { label: 'Suspicious', data: [], backgroundColor: C.sus, stack: 's', borderRadius: 2, borderSkipped: 'bottom', categoryPercentage: .82, barPercentage: .9 },
    ] },
    options: {
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      scales: { ...baseScales('records'), x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 18 } }, y: { ...baseScales('records').y, stacked: true } },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: {
          footer: (items) => {
            const i = items[0].dataIndex;
            const s = activity.$series[i];
            return s ? `Total analysed: ${s.Normal + s.Suspicious + s.Malicious}` : '';
          },
        } },
      },
    },
  });

  const thresholdLines = {
    id: 'thresholdLines',
    afterDatasetsDraw(chart) {
      const { ctx, chartArea: a, scales: { x } } = chart;
      [[thresholds.suspicious, C.sus, 'S'], [thresholds.malicious, C.mal, 'M']].forEach(([t, color, tag]) => {
        const px = x.getPixelForValue(t * 20 - 0.5);
        ctx.save();
        ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.setLineDash([5, 4]);
        ctx.beginPath(); ctx.moveTo(px, a.top); ctx.lineTo(px, a.bottom); ctx.stroke();
        ctx.setLineDash([]); ctx.fillStyle = '#f0efec'; ctx.font = '600 11px system-ui, sans-serif';
        ctx.fillText(`${tag} ${t.toFixed(2)}`, px + 4, a.top + 11);
        ctx.restore();
      });
    },
  };
  const binTier = (i) => { const mid = (i + 0.5) / 20; return mid >= thresholds.malicious ? 'Malicious' : mid >= thresholds.suspicious ? 'Suspicious' : 'Normal'; };
  const hist = new Chart($('#histChart'), {
    type: 'bar',
    data: { labels: Array.from({ length: 20 }, (_, i) => (i / 20).toFixed(2)), datasets: [{ data: [], backgroundColor: [], borderRadius: 2, categoryPercentage: 1, barPercentage: .9 }] },
    options: {
      maintainAspectRatio: false,
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 0, callback: (v, i) => (i % 5 === 0 ? (i / 20).toFixed(2) : '') }, title: { display: true, text: 'threat score', color: C.muted } },
        y: { type: 'logarithmic', grid: { color: C.grid }, border: { display: false }, title: { display: true, text: 'records (log scale)', color: C.muted },
             ticks: { callback: (v) => ([1, 10, 100, 1000, 10000].includes(v) ? fmtNum(v) : '') } },
      },
      plugins: { legend: { display: false }, tooltip: { callbacks: {
        title: (it) => `Score ${(it[0].dataIndex / 20).toFixed(2)}–${((it[0].dataIndex + 1) / 20).toFixed(2)}`,
        label: (it) => ` ${fmtNum(it.raw)} records · ${binTier(it.dataIndex)}`,
      } } },
    },
    plugins: [thresholdLines],
  });

  const hbar = (el, colors) => new Chart(el, {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: colors, borderRadius: 4, borderSkipped: 'start', barPercentage: .7, categoryPercentage: .9 }] },
    options: {
      indexAxis: 'y', maintainAspectRatio: false,
      scales: { x: { beginAtZero: true, grid: { color: C.grid }, border: { display: false }, ticks: { precision: 0 } }, y: { grid: { display: false }, ticks: { color: '#f0efec' } } },
      plugins: { legend: { display: false } },
    },
  });
  const catChart = hbar($('#catChart'), C.blue);
  catChart.options.plugins.tooltip.callbacks = { label: (it) => ` ${fmtNum(it.raw)} flagged records` };
  const tierChart = hbar($('#tierChart'), [C.good, C.sus, C.mal]);
  tierChart.options.plugins.tooltip.callbacks = {
    label: (it) => { const tot = it.dataset.data.reduce((a, b) => a + b, 0) || 1; return ` ${fmtNum(it.raw)} records (${((it.raw / tot) * 100).toFixed(1)}%)`; },
  };

  /* ---------------- stats ---------------- */
  const RISK_LEVELS = ['Low', 'Elevated', 'High', 'Critical'];
  async function loadStats() {
    try {
      const s = await api(`/api/stats?minutes=${minutes}`);
      thresholds = s.thresholds;
      $('#sTotal').textContent = fmtNum(s.total);
      $('#sNormal').textContent = fmtNum(s.normal);
      $('#sThreats').textContent = fmtNum(s.threats);
      $('#sMal').textContent = fmtNum(s.malicious);
      $('#sSus').textContent = fmtNum(s.suspicious);
      $('#sOpen').textContent = fmtNum(s.open_alerts);
      const lastMin = s.series.slice(-6, -1);
      const perMin = lastMin.length ? lastMin.reduce((a, b) => a + b.Normal + b.Suspicious + b.Malicious, 0) / lastMin.length / s.bucket_minutes : 0;
      $('#sRate').innerHTML = `<b>${perMin.toFixed(1)}</b>/min recently`;

      const lvl = s.risk.level;
      $('#sRisk').textContent = lvl;
      $('#riskCard').className = `card stat risk-${lvl}`;
      const n = RISK_LEVELS.indexOf(lvl);
      document.querySelectorAll('.risk-meter span').forEach((el, i) => el.classList.toggle('on', i <= n));
      $('#sRiskWhy').textContent = `${(s.risk.ratio * 100).toFixed(1)}% weighted threat rate (last ${s.risk.window}) · ${s.risk.open_malicious_10m} open malicious in 10 min`;

      $('#detChip').textContent = `detector: ${s.detector.mode}`;
      $('#detChip').classList.toggle('warn', !s.detector.real);
      $('#detChip').title = s.detector.real ? '' : 'No ML module or model files found, so the demo heuristic is scoring records. See README.';
      $('#thrChip').textContent = `thresholds: S ≥ ${s.thresholds.suspicious.toFixed(2)} · M ≥ ${s.thresholds.malicious.toFixed(2)}${s.thresholds.anomaly_flag ? ' · IF flag on' : ''}`;
      const ev = s.evaluation;
      $('#evalChip').hidden = !ev;
      if (ev) {
        const pct = (v) => (v == null ? '—' : `${(v * 100).toFixed(1)}%`);
        $('#evalChip').textContent = `accuracy ${pct(ev.accuracy)} · recall ${pct(ev.recall)} (${fmtNum(ev.n)} labelled)`;
        $('#evalChip').title = `Dashboard verdicts vs dataset labels, all ${ev.n} replayed dataset records\nPrecision ${pct(ev.precision)} · TP ${ev.tp} · FP ${ev.fp} · TN ${ev.tn} · FN ${ev.fn}`;
      }
      const team = s.detector.mode.startsWith('team');
      $('#catTitle').textContent = team ? 'What triggered each flag' : 'Detected attack categories';
      $('#catSub').textContent = team ? 'RF confidence vs Isolation Forest outliers, all-time' : 'All-time, predicted by the model';
      $('#updatedAt').textContent = `Updated ${new Date().toLocaleTimeString([], { hour12: false })}` +
        (s.replay ? ' · replay running' : ' · replay paused') + (s.last_record_at ? ` · last record ${TW.ago(s.last_record_at)}` : '');

      // activity
      activity.$series = s.series;
      const showDate = minutes > 60;
      activity.data.labels = s.series.map((b) => new Date(b.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }));
      activity.data.datasets[0].data = s.series.map((b) => b.Malicious);
      activity.data.datasets[1].data = s.series.map((b) => b.Suspicious);
      activity.update('none');
      $('#activitySub').textContent = `Flagged records per ${s.bucket_minutes === 1 ? 'minute' : s.bucket_minutes + ' minutes'}, last ${minutes >= 60 ? minutes / 60 + 'h' : minutes + ' min'}`;

      hist.data.datasets[0].data = s.score_hist.map((v) => v || null);
      hist.data.datasets[0].backgroundColor = s.score_hist.map((_, i) => ({ Normal: C.good, Suspicious: C.sus, Malicious: C.mal }[binTier(i)]));
      hist.update('none');
      $('#histSub').textContent = s.detector.mode.startsWith('team')
        ? `Last ${fmtNum(s.score_sample)} records, by RF attack probability (IF outliers can be Suspicious below S)`
        : `Last ${fmtNum(s.score_sample)} records, by combined model score`;

      catChart.data.labels = Object.keys(s.categories);
      catChart.data.datasets[0].data = Object.values(s.categories);
      catChart.update('none');
      tierChart.data.labels = ['Normal', 'Suspicious', 'Malicious'];
      tierChart.data.datasets[0].data = [s.normal, s.suspicious, s.malicious];
      tierChart.update('none');

      const max = Math.max(1, ...s.top_sources.map((x) => x.count));
      $('#topSources').innerHTML = s.top_sources.length
        ? s.top_sources.map((x) => `<li><span class="mono">${esc(x.ip)}</span><span class="mono secondary">${fmtNum(x.count)}</span><span class="bar"><span style="width:${(x.count / max) * 100}%"></span></span></li>`).join('')
        : '<li class="muted">No flagged sources yet.</li>';
    } catch (e) { /* offline bar shows */ }
  }

  /* ---------------- live feed ---------------- */
  async function loadFeed() {
    if (paused) return;
    try {
      const tier = $('#onlyThreats').checked ? '&tier=Suspicious,Malicious' : '';
      const r = await api(`/api/logs?per_page=15${tier}`);
      const prev = lastMaxId;
      $('#feed').innerHTML = r.items.length ? r.items.map((x) => `
        <tr data-id="${x.id}" class="row-${x.tier} ${prev && x.id > prev ? 'fresh' : ''}">
          <td class="mono">${fmtTime(x.timestamp)}</td>
          <td class="mono">${esc(x.src_ip || '—')}</td>
          <td class="mono">${esc(x.dst_ip || '—')}</td>
          <td class="mono">${esc(x.protocol)}</td>
          <td class="mono">${esc(x.service)}</td>
          <td>${scoreBar(x.threat_score, x.tier)}</td>
          <td>${pill(x.tier)}</td>
          <td class="cat">${esc(x.attack_category || '—')}</td>
        </tr>`).join('')
        : '<tr><td colspan="8" class="empty"><strong>No log entries yet</strong>Records will appear here as they are ingested.</td></tr>';
      lastMaxId = Math.max(prev, ...r.items.map((x) => x.id), 0);
    } catch (e) { /* offline */ }
  }
  $('#feed').addEventListener('click', (e) => { const tr = e.target.closest('tr[data-id]'); if (tr) openLog(tr.dataset.id); });
  $('#onlyThreats').addEventListener('change', () => { lastMaxId = 0; loadFeed(); });
  $('#pauseBtn').addEventListener('click', (e) => {
    paused = !paused;
    e.target.textContent = paused ? 'Resume' : 'Pause';
    e.target.setAttribute('aria-pressed', String(paused));
    const live = $('#liveStatus');
    live.classList.toggle('paused', paused);
    live.querySelector('.txt').textContent = paused ? 'Paused' : 'Live';
    if (!paused) loadFeed();
  });
  $('#rangeToggle').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    document.querySelectorAll('#rangeToggle button').forEach((x) => x.classList.toggle('on', x === b));
    minutes = +b.dataset.min; loadStats();
  });
  document.addEventListener('tw:alert-changed', loadStats);

  /* ---------------- analyze-a-record form ---------------- */
  const FIELDS = [
    { k: 'protocol_type', label: 'Protocol', type: 'select', opts: ['tcp', 'udp', 'icmp'] },
    { k: 'service', label: 'Service', type: 'text', def: 'http' },
    { k: 'flag', label: 'Flag', type: 'select', opts: ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'S1', 'S2', 'S3', 'OTH'] },
    { k: 'duration', label: 'Duration (s)', min: 0, max: 60000, def: 0 },
    { k: 'src_bytes', label: 'Source bytes', min: 0, max: 1e9, def: 230 },
    { k: 'dst_bytes', label: 'Destination bytes', min: 0, max: 1e9, def: 2100 },
    { k: 'count', label: 'Count (same host, 2s)', min: 0, max: 511, int: true, def: 5 },
    { k: 'serror_rate', label: 'SYN error rate', min: 0, max: 1, def: 0 },
    { k: 'rerror_rate', label: 'REJ error rate', min: 0, max: 1, def: 0 },
    { k: 'diff_srv_rate', label: 'Different-service rate', min: 0, max: 1, def: 0 },
    { k: 'num_failed_logins', label: 'Failed logins', min: 0, max: 5, int: true, def: 0 },
    { k: 'root_shell', label: 'Root shell (0/1)', min: 0, max: 1, int: true, def: 0 },
    { k: 'hot', label: 'Hot indicators', min: 0, max: 100, int: true, def: 0 },
    { k: 'same_srv_rate', label: 'Same-service rate', min: 0, max: 1, def: 1 },
    { k: 'src_ip', label: 'Source IP (optional)', type: 'text', def: '', optional: true },
  ];
  const PRESETS = {
    normal: {},
    synflood: { protocol_type: 'tcp', service: 'private', flag: 'S0', src_bytes: 0, dst_bytes: 0, count: 280, serror_rate: 1, same_srv_rate: 0.05, src_ip: '185.220.101.4' },
    scan: { protocol_type: 'tcp', service: 'other', flag: 'REJ', src_bytes: 0, dst_bytes: 0, count: 90, rerror_rate: 0.9, diff_srv_rate: 0.85, same_srv_rate: 0.1, src_ip: '45.33.12.9' },
    brute: { protocol_type: 'tcp', service: 'telnet', flag: 'SF', src_bytes: 125, dst_bytes: 179, num_failed_logins: 3, src_ip: '103.21.244.7' },
    root: { protocol_type: 'tcp', service: 'telnet', flag: 'SF', duration: 120, src_bytes: 2400, dst_bytes: 6800, root_shell: 1, hot: 4, src_ip: '91.240.118.22' },
  };
  $('#anFields').innerHTML = FIELDS.map((f) => `
    <label class="field">${f.label}
      ${f.type === 'select'
        ? `<select name="${f.k}">${f.opts.map((o) => `<option>${o}</option>`).join('')}</select>`
        : `<input name="${f.k}" ${f.type === 'text' ? 'type="text"' : `type="number" step="${f.int ? 1 : 'any'}" min="${f.min}" max="${f.max}"`} value="${f.def ?? ''}" ${f.optional ? '' : 'required'}>`}
      <span class="field-err" data-err="${f.k}"></span>
    </label>`).join('');
  function applyPreset(name) {
    const p = PRESETS[name];
    FIELDS.forEach((f) => { const el = $(`[name="${f.k}"]`, $('#anFields')); el.value = p[f.k] ?? f.def ?? (f.opts ? f.opts[0] : ''); el.classList.remove('invalid'); });
    document.querySelectorAll('[data-err]').forEach((e) => (e.textContent = ''));
    $('#anResult').hidden = true;
  }
  document.querySelectorAll('[data-preset]').forEach((b) => b.addEventListener('click', () => applyPreset(b.dataset.preset)));
  $('#analyzeBtn').addEventListener('click', () => { $('#analyzeModal').hidden = false; $('#anResult').hidden = true; });

  function validateForm() {
    let ok = true;
    const body = {};
    FIELDS.forEach((f) => {
      const el = $(`[name="${f.k}"]`, $('#anFields'));
      const errEl = $(`[data-err="${f.k}"]`);
      let err = '';
      const raw = el.value.trim();
      if (f.type === 'select' || f.type === 'text') {
        if (!raw && !f.optional) err = 'Required';
        else if (f.k === 'src_ip' && raw && !/^(\d{1,3}\.){3}\d{1,3}$/.test(raw)) err = 'Enter an IPv4 address';
        else if (raw) body[f.k] = raw;
      } else {
        const v = Number(raw);
        if (raw === '' || Number.isNaN(v)) err = 'Enter a number';
        else if (v < f.min || v > f.max) err = `Must be ${f.min}–${f.max}`;
        else if (f.int && !Number.isInteger(v)) err = 'Whole number only';
        else body[f.k] = v;
      }
      errEl.textContent = err;
      el.classList.toggle('invalid', !!err);
      if (err) ok = false;
    });
    return ok ? body : null;
  }
  $('#analyzeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = validateForm();
    if (!body) return;
    const btn = $('#anSubmit');
    btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Classifying…';
    try {
      const r = await api('/api/classify', { method: 'POST', body });
      $('#anResult').hidden = false;
      $('#anResult').innerHTML = `
        <div>${pill(r.classification)}</div>
        <div>Threat score ${scoreBar(r.threat_score, r.classification)}</div>
        <div class="secondary">Category: <b>${esc(r.attack_category || '—')}</b></div>
        <div class="secondary">${r.is_alert ? 'Alert raised' : 'No alert'}</div>
        <button type="button" class="btn sm" id="anOpen">Open record #${r.log_id}</button>`;
      $('#anOpen').onclick = () => { $('#analyzeModal').hidden = true; openLog(r.log_id); };
      loadFeed(); loadStats();
    } catch (err) {
      $('#anResult').hidden = false;
      $('#anResult').innerHTML = `<span style="color:#ff8a8a">${esc(err.message)}</span>`;
    } finally {
      btn.disabled = false; btn.textContent = 'Classify';
    }
  });

  loadStats(); loadFeed();
  setInterval(loadFeed, 3000);
  setInterval(loadStats, 5000);
})();
