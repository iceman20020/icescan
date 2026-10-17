// sorting
document.querySelectorAll('#findings-table thead th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    const tbody = document.querySelector('#findings-table tbody');
    const rows = Array.from(tbody.querySelectorAll('tr.row'));
    const order = th.dataset.order === 'asc' ? 'desc' : 'asc';
    document.querySelectorAll('#findings-table thead th').forEach(t => delete t.dataset.order);
    th.dataset.order = order;

    const sevRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    rows.sort((a, b) => {
      let av, bv;
      if (key === 'severity') { av = sevRank[a.dataset.sev]; bv = sevRank[b.dataset.sev]; }
      else { av = a.dataset[key] || a.cells[1].innerText; bv = b.dataset[key] || b.cells[1].innerText; }
      if (av < bv) return order === 'asc' ? -1 : 1;
      if (av > bv) return order === 'asc' ? 1 : -1;
      return 0;
    });
    rows.forEach(r => {
      tbody.appendChild(r);
      const next = r.nextElementSibling;
      if (next && next.classList.contains('evidence-row')) tbody.appendChild(next);
    });
  });
});

// expand evidence
document.querySelectorAll('button.expand').forEach(btn => {
  btn.addEventListener('click', () => {
    const row = document.getElementById(btn.dataset.target);
    if (!row) return;
    row.hidden = !row.hidden;
    btn.textContent = row.hidden ? '+' : '−';
  });
});

// filter
const filter = document.getElementById('filter');
if (filter) {
  filter.addEventListener('input', () => {
    const q = filter.value.toLowerCase();
    document.querySelectorAll('#findings-table tbody tr.row').forEach(row => {
      const hay = row.innerText.toLowerCase();
      const show = !q || hay.includes(q);
      row.style.display = show ? '' : 'none';
      const ev = row.nextElementSibling;
      if (ev && ev.classList.contains('evidence-row') && !show) ev.hidden = true;
    });
  });
}

// donut chart
const sevCanvas = document.getElementById('sevChart');
if (sevCanvas && sevCanvas.getContext) {
  const ctx = sevCanvas.getContext('2d');
  const data = [
    { label: 'critical', value: +sevCanvas.dataset.critical, color: '#ff3b5c' },
    { label: 'high', value: +sevCanvas.dataset.high, color: '#ff6b3b' },
    { label: 'medium', value: +sevCanvas.dataset.medium, color: '#ffb020' },
    { label: 'low', value: +sevCanvas.dataset.low, color: '#3b9eff' },
    { label: 'info', value: +sevCanvas.dataset.info, color: '#6b7280' },
  ].filter(d => d.value > 0);
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const cx = sevCanvas.width / 2, cy = sevCanvas.height / 2;
  const rOuter = 100, rInner = 62;
  let a0 = -Math.PI / 2;
  data.forEach(d => {
    const a1 = a0 + (d.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, rOuter, a0, a1);
    ctx.arc(cx, cy, rInner, a1, a0, true);
    ctx.closePath();
    ctx.fillStyle = d.color;
    ctx.fill();
    a0 = a1;
  });
  ctx.fillStyle = '#e6e8ee';
  ctx.font = '600 26px ui-monospace, monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy - 6);
  ctx.fillStyle = '#8b90a0';
  ctx.font = '11px ui-sans-serif, sans-serif';
  ctx.fillText('findings', cx, cy + 16);
}

// category bar chart
const catCanvas = document.getElementById('catChart');
if (catCanvas && catCanvas.getContext && catCanvas.dataset.cats) {
  const ctx = catCanvas.getContext('2d');
  let cats;
  try { cats = JSON.parse(catCanvas.dataset.cats); } catch { cats = {}; }
  const entries = Object.entries(cats).sort((a, b) => b[1] - a[1]);
  const maxV = Math.max(1, ...entries.map(e => e[1]));
  const pad = 20;
  const barH = 22, gap = 8;
  const labelW = 120;
  catCanvas.height = Math.max(240, entries.length * (barH + gap) + pad * 2);
  entries.forEach(([name, val], i) => {
    const y = pad + i * (barH + gap);
    const w = ((catCanvas.width - labelW - 60) * val / maxV);
    ctx.fillStyle = '#8b90a0';
    ctx.font = '12px ui-monospace, monospace';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText(name, 0, y + barH / 2);
    ctx.fillStyle = '#3b9eff';
    ctx.fillRect(labelW, y, w, barH);
    ctx.fillStyle = '#e6e8ee';
    ctx.fillText(String(val), labelW + w + 8, y + barH / 2);
  });
}
