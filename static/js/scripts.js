// static/js/scripts.js

window.addEventListener('DOMContentLoaded', () => {
  // SBOM Upload
  const uploadBtn = document.getElementById('uploadBtn');
  if (uploadBtn) {
    uploadBtn.addEventListener('click', async () => {
      const fileInput = document.getElementById('sbomFile');
      if (!fileInput.files.length) return alert('Lütfen bir dosya seçin.');
      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      try {
        const res = await fetch('/upload', { method: 'POST', body: formData });
        const list = await res.json();
        const tbody = document.querySelector('#previewTable tbody');
        tbody.innerHTML = '';
        list.forEach(item => {
          const row = document.createElement('tr');
          row.innerHTML = `<td>${item.component}</td><td>${item.version}</td>`;
          tbody.appendChild(row);
        });
      } catch (err) {
        console.error(err);
        alert('Yükleme hatası');
      }
    });
  }

  // CVE Tarama
  const scanBtn = document.getElementById('scanBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      const progressBar = document.getElementById('scanProgress');
      const scanLog = document.getElementById('scanLog');
      const scanTableBody = document.querySelector('#scanTable tbody');
      progressBar.style.width = '0%';
      scanLog.innerHTML = '';
      scanTableBody.innerHTML = '';
      try {
        const res = await fetch('/scan', { method: 'POST' });
        let progress = 0;
        const timer = setInterval(() => {
          progress = Math.min(progress + 20, 100);
          progressBar.style.width = `${progress}%`;
          scanLog.innerHTML += `↻ ${new Date().toLocaleTimeString()} - %${progress}<br>`;
          if (progress >= 100) clearInterval(timer);
        }, 400);
        const results = await res.json();
        clearInterval(timer);
        progressBar.style.width = '100%';
        scanLog.innerHTML += `✔ Tarama tamamlandı<br>`;
        results.forEach(item => {
          const row = document.createElement('tr');
          row.innerHTML = `<td>${item.component}</td><td>${item.cve}</td><td>${item.cvss}</td><td>${item.desc}</td>`;
          scanTableBody.appendChild(row);
        });
      } catch (e) {
        console.error(e);
        scanLog.innerHTML += '✖ Tarama hatası';
      }
    });
  }

  // Versiyon & Güncellik Kontrolü
  const versionBtn = document.getElementById('versionBtn');
  if (versionBtn) {
    versionBtn.addEventListener('click', async () => {
      versionBtn.disabled = true;
      versionBtn.textContent = 'Kontrol ediliyor...';
      try {
        const res = await fetch('/version-check');
        const data = await res.json();
        const tbody = document.querySelector('#versionTable tbody');
        tbody.innerHTML = '';
        data.forEach(item => {
          const isCurrent = item.current_version === item.latest_version;
          const row = document.createElement('tr');
          row.innerHTML = `
            <td>${item.component}</td>
            <td>${item.current_version}</td>
            <td>${item.latest_version}</td>
            <td>${isCurrent ? '✔️' : '❌'}</td>
          `;
          tbody.appendChild(row);
        });
      } catch (e) {
        console.error(e);
        alert('Versiyon kontrolü sırasında hata oluştu.');
      } finally {
        versionBtn.disabled = false;
        versionBtn.textContent = 'Versiyon Kontrol Et';
      }
    });
  }

  // CRA Uyum Skoru
  const scoreBtn = document.getElementById('scoreBtn');
  if (scoreBtn) {
    scoreBtn.addEventListener('click', async () => {
      scoreBtn.disabled = true;
      scoreBtn.textContent = 'Hesaplanıyor...';
      try {
        const res = await fetch('/score');
        const json = await res.json();
        document.getElementById('gauge').textContent = `${json.score}%`;
        const list = document.getElementById('criteriaList');
        list.innerHTML = '';
        json.criteria.forEach(c => {
          const li = document.createElement('li');
          li.className = 'list-group-item d-flex justify-content-between align-items-center';
          li.innerHTML = `${c.name} <span class="badge ${c.status ? 'bg-success' : 'bg-danger'}">${c.status ? '✔️' : '❌'}</span>`;
          list.appendChild(li);
        });
      } catch (e) {
        console.error(e);
        alert('Skor hesaplanırken hata oluştu.');
      } finally {
        scoreBtn.disabled = false;
        scoreBtn.textContent = 'Skoru Hesapla';
      }
    });
  }

  // Güncelleme & Yama Planları
  const planForm = document.getElementById('planForm');
  if (planForm) {
    planForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const component = document.getElementById('planComponent').value;
      const date = document.getElementById('planDate').value;
      const note = document.getElementById('planNote').value;
      try {
        const res = await fetch('/plans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ component, date, note })
        });
        if (!res.ok) throw new Error();
        planForm.reset();
        loadPlans();
      } catch {
        alert('Plan eklenirken hata oluştu.');
      }
    });
    async function loadPlans() {
      try {
        const res = await fetch('/plans');
        const plans = await res.json();
        const tbody = document.querySelector('#planTable tbody');
        tbody.innerHTML = '';
        plans.forEach(p => {
          const row = document.createElement('tr');
          row.innerHTML = `
            <td>${p.component}</td>
            <td>${p.date}</td>
            <td>${p.note}</td>
            <td>${p.status}</td>
          `;
          tbody.appendChild(row);
        });
      } catch (e) {
        console.error('Plans load error', e);
      }
    }
    loadPlans();
  }

  // Seyir Defteri
  async function loadLogs() {
    try {
      const res = await fetch('/logs');
      if (!res.ok) return;
      const logs = await res.json();
      const container = document.getElementById('logEntries');
      container.innerHTML = '';
      logs.forEach(l => {
        const div = document.createElement('div');
        div.textContent = `${l.timestamp} - ${l.action}`;
        container.appendChild(div);
      });
    } catch (e) {
      console.error('Log yüklenemedi:', e);
    }
  }
  const logTab = document.querySelector('button[data-bs-target="#tab-log"]');
  if (logTab) {
    logTab.addEventListener('shown.bs.tab', loadLogs);
  }

  // Raporlar listesi
  async function loadReports() {
    const res = await fetch('/reports');
    if (!res.ok) return;
    let data = await res.json();
  
    // Tarihe göre büyükten küçüğe sırala:
    data.sort((a, b) => new Date(b.date) - new Date(a.date));
  
    const tbody = document.querySelector('#reportsTable tbody');
    tbody.innerHTML = '';
    data.forEach(r => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${r.date}</td>
        <td>${r.sbom}</td>
        <td>${r.score}%</td>
        <td><a href="/reports/files/${r.file}" class="btn btn-sm btn-primary">İndir</a></td>
      `;
      tbody.appendChild(row);
    });
  }

    // Rapor Oluşturma (PDF oluştur ve tabloya ekle)
  const reportBtn = document.getElementById('generateReportBtn');
  if (reportBtn) {
    reportBtn.addEventListener('click', async () => {
      reportBtn.disabled = true;
      reportBtn.textContent = 'Oluşturuluyor...';
      try {
        // PDF indirme yerine JSON entry al
        const res = await fetch('/reports', { method: 'POST' });
        if (!res.ok) throw new Error();
        // Tabloyu güncelle
        await loadReports();
      } catch {
        alert('Rapor oluşturulurken hata oluştu.');
      } finally {
        reportBtn.disabled = false;
        reportBtn.textContent = 'Rapor Oluştur';
      }
    });
    loadReports();
  }
});