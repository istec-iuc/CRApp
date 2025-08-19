// static/js/scripts.js

window.addEventListener('DOMContentLoaded', () => {

// Step 1: Reset all tabs and panes
document.querySelectorAll('.tab-pane').forEach(pane => {
  pane.classList.remove('active', 'show');
});
document.querySelectorAll('.nav-link').forEach(link => {
  link.classList.remove('active');
});

// Step 2: Choose your "homepage" tab
const defaultTabId = "tab-product-add"; // change this to your default tab's ID
const defaultTabPane = document.getElementById(defaultTabId);
const defaultTabNav = document.querySelector(`button[data-bs-target="#${defaultTabId}"]`);

if (defaultTabPane && defaultTabNav) {
  defaultTabPane.classList.add('active', 'show');
  defaultTabNav.classList.add('active');
}


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


  //Load the SBOM files onto the comboboxes
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
      option.value = file.sbom_path; // use path for value
      option.textContent = file.label; // but show product name
      sbomSelector.appendChild(option);
    });
  });
} catch (err) {
  console.error("SBOM listesi alınamadı:", err);
}
}

//Execute on first load of the page
loadSbomList();


//Helper function
function sanitize(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

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
          row.innerHTML = `
          <td>${sanitize(item.component)}</td>
            <td>${sanitize(item.cve)}</td>
            <td>${sanitize(item.cvss)}</td>
            <td>${sanitize(item.desc)}</td>`;
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


// Version Editor of the JSON File
const form = document.getElementById("versionForm");
const tableBody = document.querySelector("#versionEditorTable tbody");

function loadVersionData() {
  fetch("/version-editor/data")
    .then(res => res.json())
    .then(data => {
      tableBody.innerHTML = "";
      for (const [name, info] of Object.entries(data)) {
        //For debugging
        //console.log(info)
        //console.log(info.latest_display)
        
        const row = document.createElement("tr");
        //FILTER THROUGH VS V for version !
        row.innerHTML = `
          <td>${name}</td>
          <td>${Array.isArray(info.latest) ? info.latest.join(", ") : info.latest}</td>
          <td>${info.latest_display || "-"}</td>
          <td><a href="${info.homepage}" target="_blank">${info.homepage}</a></td>
        `;
        tableBody.appendChild(row);
      }
    });
}

//HELPER FUNCTION
/*
function isValidVersion(v) {
  // Very basic validation: must match a version pattern like 1.2, 2.3.4, etc.
  return /^\d+(\.\d+)+$/.test(v.trim());
}
*/

form.addEventListener("submit", function (e) {
  e.preventDefault();
  const component = document.getElementById("componentName").value.trim();
  const latest = document.getElementById("latestVersions").value.trim();
  const homepage = document.getElementById("homepage").value.trim();

  /*
  //Confirm if the version/s given from the user are valid
  const versionList = latest.split(",").map(v => v.trim()).filter(Boolean);
  const invalidVersions = versionList.filter(v => !isValidVersion(v));
  
  if (invalidVersions.length > 0) {
    alert("Geçersiz sürüm formatı: " + invalidVersions.join(", "));
    return;
  }
  */
  
  // Check if the component already exists
  fetch("/version-editor/data")
    .then(res => res.json())
    .then(existingData => {
      if (component in existingData) {
        if (!confirm(`${component} zaten var. Güncellemek istiyor musunuz?`)) {
          form.reset();
          return;
        }
      }

  fetch("/version-editor/update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ component, latest, homepage })
    }).then(res => res.json())
    .then(result => {
    if (result.error) {
      alert(result.error);
    } else {
      alert("Başarıyla güncellendi.");
      loadVersionData();
      form.reset();
    }

    });
  });
});


//Deleting components from version_mapping.json
const versionDeleteBtn = document.getElementById("deleteButton")
if (versionDeleteBtn) {
    versionDeleteBtn.addEventListener("click", function () {
    const component = document.getElementById("componentName").value.trim();

    if (!component) {
      alert("Lütfen silmek istediğiniz bileşen adını girin.");
      return;
    }

    if (!confirm(`${component} bileşenini silmek istediğinize emin misiniz?`)) {
      return;
    }

    fetch("/version-editor/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ component })
    })
      .then(res => res.json())
      .then(result => {
        if (result.error) {
          alert("Hata: " + result.error);
        } else {
          alert(result.message);
          form.reset();
          loadVersionData();
        }
      });
  });

}



// Load data initially
loadVersionData();

// Versiyon & Güncellik Kontrolü
const versionBtn = document.getElementById('versionBtn');
if (versionBtn) {
  versionBtn.addEventListener('click', async () => {
    const selectedFile = document.getElementById("sbomSelector-version").value;
    console.log("Selected SBOM file:", selectedFile);

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
      console.log("RECEIVED DATA:");
      console.log(data);
      
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


//PRODUCTS PAGES LOGIC
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
document.querySelector('[data-bs-target="#tab-products"]').addEventListener('shown.bs.tab', loadProducts);

// Silme butonu dinleyicisi
document.querySelector('#productsTable tbody').addEventListener('click', async e => {
    if (!e.target.matches('.btn-delete')) return;
    const id = e.target.dataset.id;
    if (!confirm('Bu ürünü silmek istediğinize emin misiniz?')) return;

    const res = await fetch(`/products/delete/${id}`, { method: 'POST' });
    if (!res.ok) {
      alert('Silme işlemi başarısız oldu.');
    } else {
      // Başarılı silme → listeyi & comboboxları yenile
      await loadProducts();
      await loadSbomList();
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

// SBOM preview logic for Product Upload
const productSbomInput = document.getElementById('sbom');
if (productSbomInput) {
  productSbomInput.addEventListener('change', async () => {
    const file = productSbomInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('sbom', file);

    try {
      const res = await fetch('/upload', {
        method: 'POST',
        body: formData
      });

      if (!res.ok) throw new Error('Upload failed');

      const list = await res.json();

      const tbody = document.querySelector('#productPreviewTable tbody');
      tbody.innerHTML = '';
      list.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${item.component}</td><td>${item.version}</td>`;
        tbody.appendChild(row);
      });

    } catch (err) {
      console.error(err);
      alert('SBOM önizleme yüklenemedi/ Products page /');
    }
  });
}

// Clear the sbom components display after upload
const productUploadBtn = document.getElementById("productUploadBtn")
if(productUploadBtn) {
  productUploadBtn.addEventListener("click", async () => {
    const tbody = document.querySelector('#productPreviewTable tbody');
    tbody.innerHTML = '';
  })
}

  

  // “Ürünler” sekmesi aktif olduğunda da listeyi yüklesin
document.querySelector('[data-bs-target="#tab-products"]').addEventListener('shown.bs.tab', loadProducts);

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



//SUMMARY LOGIC
const summaryBtn = document.getElementById("summaryBtn");
if(summaryBtn) {
  summaryBtn.addEventListener("click", async () => {
    const file = document.getElementById("sbomSelector-summary").value;

    if (!file) {
      alert("Lütfen bir SBOM dosyası seçin.");
      return;
    }

    try {
          const res = await fetch('/summary', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename: file })
        });

        const data = await res.json();
        const summaryBody = document.querySelector("#summaryTable tbody");
        summaryBody.innerHTML = '';

        // Optional: show a warning if something is missing
        //if (data.missing.version_check) {
        //  alert("Bu dosya için versiyon kontrolü yapılmamış.");
       // }
        //if (data.missing.cve_scan) {
        //  alert("Bu dosya için CVE taraması yapılmamış.");
        //}

        if (data.message) {
          alert(data.message);
          return;
        } else {
          if (data.missing?.version_check) {
            alert("Bu dosya için versiyon kontrolü yapılmamış.");
          }

          if (data.missing?.cve_scan) {
            alert("Bu dosya için CVE taraması yapılmamış.");
          }
        }




        // Handle case where no version data exists at all
      if (data.version_results?.length === 0) {
        const row = document.createElement("tr");
        row.innerHTML = `<td colspan="5" class="text-center text-muted">Veri bulunamadı</td>`;
        summaryBody.appendChild(row);
        return;
      }

        let cveMap = {};
       // Combine version + CVE results by component
      if (Array.isArray(data.cve_results)) {
        data.cve_results.forEach(cve => {
          cveMap[cve.component.toLowerCase()] = cve;
        });
      }

      // Build the table
      data.version_results.forEach(item => {
        const component = item.component.toLowerCase();
        const cve = cveMap[component];
        const homepage = item.homepage ? `<a href="${item.homepage}" target="_blank">${new URL(item.homepage).hostname}</a>` : '—';
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${item.component}</td>
          <td>${item.current_version}</td>
          <td>${item.latest_version}</td>
          <td>${cve ? `CVE: ${cve.cve_count}` : 'Yok'}</td>
          <td>${homepage}</td> 
        `;
        summaryBody.appendChild(row);
      });

    } catch (e){
      console.error("Summary fetch error:", e);
      alert("Özet verisi alınırken bir hata oluştu.");
    }

  });
}




});

