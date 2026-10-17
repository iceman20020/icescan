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
      tbody.appendChild(r
