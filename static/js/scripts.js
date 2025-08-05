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

        //Updating the comboboxes
        await loadSbomList();
      } catch (err) {
        console.error(err);
        alert('Yükleme hatası');
      }
    });
  }

  // CVE Tarama

  const scanBtnOnline = document.getElementById('scanBtnOnline');
  const scanBtnOffline = document.getElementById("scanBtnOffline");
  const scanUpdateBtn = document.getElementById('cveUpdateBtn');


  //Load the SBOM options
  async function loadSbomList() {
  try {
    const res = await fetch("/list-sboms");
    const files = await res.json();

   // Select all <select> elements with class "sbomSelector"
    const sbomSelectors = document.querySelectorAll(".sbomSelector");

    sbomSelectors.forEach(sbomSelector => {
      sbomSelector.innerHTML = ""; // Clear existing options

      files.forEach(file => {
        const option = document.createElement("option");
        option.value = file;
        option.textContent = file;
        sbomSelector.appendChild(option);
      });
    });
  } catch (err) {
    console.error("SBOM listesi alınamadı:", err);
  }
}

loadSbomList();



//ONLINE CVE Scan
if (scanBtnOnline) {
  scanBtnOnline.addEventListener('click', async () => {
        const selectedFile = document.getElementById("sbomSelector-cve").value;
        scanBtnOnline.disabled = true;
        scanBtnOnline.textContent = 'Taraniyor...';

        //Turn off the other buttons
        scanBtnOffline.disabled = true;
        scanUpdateBtn.disabled = true;

      const progressBar = document.getElementById('scanProgress');
      const scanLog = document.getElementById('scanLog');
      const scanTableBody = document.querySelector('#scanTable tbody');
      progressBar.style.width = '0%';
      scanLog.innerHTML = '';
      scanTableBody.innerHTML = '';
      try {
        //const res = await fetch('/scan-online', { method: 'POST' });
        const res = await fetch('/scan-online', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ filename: selectedFile })
        });

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
      } finally {
          //Return to default after successful attempt
          scanBtnOnline.disabled = false;
          scanBtnOnline.textContent = 'Taramayı Başlat';
          scanBtnOffline.disabled = false;
          scanUpdateBtn.disabled = false;          
        };

    });
  }

  function sanitize(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

  //OFFLINE CVE Scan
  if (scanBtnOffline) {
    scanBtnOffline.addEventListener('click', async () => {
      const selectedFile = document.getElementById("sbomSelector-cve").value;
      scanBtnOffline.disabled = true;
      scanBtnOffline.textContent = 'Taraniyor...';

      //Turn off the other buttons
      scanBtnOnline.disabled = true;
      scanUpdateBtn.disabled = true;

      const progressBar = document.getElementById('scanProgress');
      const scanLog = document.getElementById('scanLog');
      const scanTableBody = document.querySelector('#scanTable tbody');
      progressBar.style.width = '0%';
      scanLog.innerHTML = '';
      scanTableBody.innerHTML = '';
      try {
        //const res = await fetch('/scan-offline', { method: 'POST' });
        const res = await fetch('/scan-offline', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ filename: selectedFile })
        });
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
        //DISPLAYS only 50 of them -> If they're too many - Google crashes
        (results.slice(0, 50)).forEach(item => {
          const row = document.createElement('tr');
          //row.innerHTML = `<td>${item.component}</td><td>${item.cve}</td><td>${item.cvss}</td><td>${item.desc}</td>`;
          row.innerHTML = `
            <td>${sanitize(item.component)}</td>
            <td>${sanitize(item.cve)}</td>
            <td>${sanitize(item.cvss)}</td>
            <td>${sanitize(item.desc)}</td>
          `;

          scanTableBody.appendChild(row);
        });
      } catch (e) {
        console.error(e);
        scanLog.innerHTML += '✖ Tarama hatası';
      } finally {
          //Return to default after successful attempt
          scanBtnOffline.disabled = false;
          scanBtnOffline.textContent = 'Çevrimdışı Tarama';
          scanBtnOnline.disabled = false;
          scanUpdateBtn.disabled = false;          
        };
    }) 
  }; //End of if for Offline Scan Btn


  //CVE Güncellemenk

  // Update timestamp in the UI
  async function updateLastUpdatedDisplay() {
    try {
        const res = await fetch("/last-updated");
        const data = await res.json();
        document.getElementById("last-updated").textContent = data.timestamp;
    } catch (e) {
        console.warn("Could not fetch last update time", e);
    }
}

// On page load
updateLastUpdatedDisplay();


  if (scanUpdateBtn) {
    scanUpdateBtn.addEventListener('click', async () => {
      scanUpdateBtn.disabled = true;
      scanUpdateBtn.textContent = 'Güncelleniyor...';

      //Turn off the other buttons
      scanBtnOnline.disabled = true;
      scanBtnOffline.disabled = true;

      try {
          const res = await fetch("/update-cve", { method: "POST" });
          const data = await res.json(); // Await the parsed JSON
          alert(data.message);

          // Update timestamp in the UI after successful update
          if (data.timestamp) {
              document.getElementById("last-updated").textContent = data.timestamp;
          } else {
              await updateLastUpdatedDisplay();  // fallback
          }
      } catch (e) {
          alert("Update failed: " + e);
      } finally {
          //Return to default after successful attempt
          scanUpdateBtn.disabled = false; 
          scanUpdateBtn.textContent = 'CVE Veritabanını Güncelle';
          scanBtnOffline.disabled = false;
          scanBtnOnline.disabled = false;
      }
    })
  }; //End of if for Update CVE data


  // Versiyon & Güncellik Kontrolü
  const versionBtn = document.getElementById('versionBtn');
  if (versionBtn) {
    versionBtn.addEventListener('click', async () => {
      const selectedFile = document.getElementById("sbomSelector-version").value;
      versionBtn.disabled = true;
      versionBtn.textContent = 'Kontrol ediliyor...';

      try {
        //const res = await fetch('/version-check');
        const res = await fetch('/version-check', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ filename: selectedFile })
        });
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
      const selectedFile = document.getElementById("sbomSelector-cra").value;
      scoreBtn.disabled = true;
      scoreBtn.textContent = 'Hesaplanıyor...';

      try {
        //const res = await fetch('/score');
        const res = await fetch('/score', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ filename: selectedFile })
        });
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
      const selectedFile = document.getElementById("sbomSelector-report").value;

      reportBtn.disabled = true;
      reportBtn.textContent = 'Oluşturuluyor...';
      try {
        // PDF indirme yerine JSON entry al
        //const res = await fetch('/reports', { method: 'POST' });
        const res = await fetch('/reports', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ filename: selectedFile })
        });
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

  async function loadProducts() {
    const res = await fetch('/products');
    if (!res.ok) return;
    const products = await res.json();
    const tbody = document.querySelector('#productsTable tbody');
    tbody.innerHTML = '';
  
    products.forEach(p => {
      // Dosya adından timestamp’i çıkar, yoksa tamamını göster
      const displayName = p.sbom_path.includes('_')
        ? p.sbom_path.substring(p.sbom_path.indexOf('_') + 1)
        : p.sbom_path;
  
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${p.id}</td>
        <td>${p.brand}</td>
        <td>${p.model}</td>
        <td>${p.version}</td>
        <td>
          <a href="/products/sbom/${p.sbom_path}" target="_blank">
            ${displayName}
          </a>
        </td>
        <td>${new Date(p.created).toLocaleString()}</td>
        <td>
          <button
            class="btn btn-sm btn-danger btn-delete"
            data-id="${p.id}"
            >
            Sil
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }
  // Tab gösterildiğinde de yükle
  document
    .querySelector('[data-bs-target="#tab-products"]')
    .addEventListener('shown.bs.tab', loadProducts);

  // Silme butonu dinleyicisi
  document
    .querySelector('#productsTable tbody')
    .addEventListener('click', async e => {
      if (!e.target.matches('.btn-delete')) return;
      const id = e.target.dataset.id;
      if (!confirm('Bu ürünü silmek istediğinize emin misiniz?')) return;

      const res = await fetch(`/products/delete/${id}`, { method: 'POST' });
      if (!res.ok) {
        alert('Silme işlemi başarısız oldu.');
      } else {
        // Başarılı silme → listeyi yenile
        await loadProducts();
      }
    });
  
  // Ürün ekleme formu submit
  document.getElementById('productForm').addEventListener('submit', async e => {
    e.preventDefault();
    const form = e.target;
    const fd = new FormData(form);
  
    const res = await fetch('/products/new', {
      method: 'POST',
      body: fd
    });
    if (!res.ok) {
      return alert('Ürün eklenirken bir hata oluştu.');
    }
  
    // 1) Formu temizle
    form.reset();
  
    // 2) “Ürünler” sekmesini aktif et
    const productsTabBtn = document.querySelector('[data-bs-target="#tab-products"]');
    const tabInstance = bootstrap.Tab.getOrCreateInstance(productsTabBtn);
    tabInstance.show();
  
    // 3) Sekme geçişini bekle ve listeyi yükle
    productsTabBtn.addEventListener('shown.bs.tab', loadProducts, { once: true });

    // 4) Update comboboxes
    //Updating the comboboxes
    await loadSbomList();
  });
  
  // “Ürünler” sekmesi aktif olduğunda da listeyi yüklesin
  document.querySelector('[data-bs-target="#tab-products"]')
    .addEventListener('shown.bs.tab', loadProducts);

    const compareTabBtn = document.querySelector('[data-bs-target="#tab-compare"]');
  compareTabBtn.addEventListener('shown.bs.tab', async () => {
    const res = await fetch('/products');
    if (!res.ok) return;
    const prods = await res.json();

    const left = document.getElementById('leftProduct');
    const right = document.getElementById('rightProduct');
    left.innerHTML  = '<option value="">Seçiniz</option>';
    right.innerHTML = '<option value="">Seçiniz</option>';

    prods.forEach(p => {
      const txt = `${p.brand} ${p.model} (${p.version})`;
      const o1 = document.createElement('option');
      o1.value = p.id; o1.textContent = txt;
      const o2 = o1.cloneNode(true);
      right.appendChild(o2);
      left.appendChild(o1);
    });
  });

  // Form submit → karşılaştırma isteği
  document.getElementById('compareForm')
    .addEventListener('submit', async e => {
      e.preventDefault();
      const leftId  = document.getElementById('leftProduct').value;
      const rightId = document.getElementById('rightProduct').value;
      if (!leftId || !rightId) {
        return alert('İki farklı ürün seçmelisiniz.');
      }
      if (leftId === rightId) {
        return alert('Aynı ürünü seçemezsiniz.');
      }

      const res = await fetch(`/compare?left=${leftId}&right=${rightId}`);
      if (!res.ok) {
        const err = await res.json();
        return alert(err.error || 'Karşılaştırma hatası');
      }
      const data = await res.json();

      // Tablo oluştur
      const div = document.getElementById('compareResult');
      let html = `
        <table class="table table-striped table-bordered">
          <thead class="table-light">
            <tr>
              <th>Bileşen</th>
              <th>Ürün 1</th>
              <th>Ürün 2</th>
            </tr>
          </thead>
          <tbody>
      `;
      data.forEach(r => {
        html += `
          <tr>
            <td>${r.component}</td>
            <td>${r.left_version}</td>
            <td>${r.right_version}</td>
          </tr>
        `;
      });
      html += `</tbody></table>`;
      div.innerHTML = html;
    });
});