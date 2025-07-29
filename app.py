from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.utils import secure_filename
import requests
import os, time
from sbom_parser import parse_sbom
from vulnerability_scanner import scan_vulnerabilities
from flask import send_file, send_from_directory
from werkzeug.utils import secure_filename
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__, template_folder='templates')
app.secret_key = 'replace_with_secure_key'
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Demo in-memory stores
USERS = {}
PLANS = []        # {'user','component','date','note','status'}
LOGS = []         # {'user','timestamp','action'}

def record_log(user, action):
    
    LOGS.append({
        'user': user,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'action': action
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        pwd = request.form['password']
        if email in USERS:
            return render_template('register.html', error='Bu e-posta zaten kayıtlı.')
        USERS[email] = pwd
        session['user'] = email
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pwd = request.form['password']
        if USERS.get(email) == pwd:
            session['user'] = email
            return redirect(url_for('index'))
        return render_template('login.html', error='Geçersiz e-posta veya şifre.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', user=session['user'])

@app.route('/upload', methods=['POST'])
def upload_sbom():
    if 'user' not in session:
        return jsonify({'error': 'Yetkisiz'}), 401
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'Dosya bulunamadı'}), 400
    filename = secure_filename(f.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(path)
    # Gerçek SBOM parse işlemi
    components = parse_sbom(path)
    return jsonify(components[:50])

@app.route('/scan', methods=['POST'])
def scan_cve():
    if 'user' not in session:
        return jsonify({'error': 'Yetkisiz'}), 401
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    if not files:
        return jsonify({'error': 'Önce SBOM yükleyin'}), 400
    latest = sorted(files, key=lambda f: os.path.getctime(os.path.join(app.config['UPLOAD_FOLDER'], f)))[-1]
    path = os.path.join(app.config['UPLOAD_FOLDER'], latest)
    components = parse_sbom(path)
    # Gerçek CVE taraması
    api_key = request.args.get('api_key')
    results = scan_vulnerabilities(components, api_key=api_key)
    return jsonify(results)

@app.route('/version-check', methods=['GET'])
def version_check():
    if 'user' not in session:
        return jsonify({'error': 'Yetkisiz'}), 401

    # Son yüklenen SBOM dosyasını bul
    uploads = app.config['UPLOAD_FOLDER']
    files = os.listdir(uploads)
    if not files:
        return jsonify({'error': 'Önce SBOM yükleyin'}), 400
    latest_sbom = sorted(
        files,
        key=lambda f: os.path.getctime(os.path.join(uploads, f))
    )[-1]
    path = os.path.join(uploads, latest_sbom)

    # SBOM’u parse et
    components = parse_sbom(path)

    results = []
    for comp in components:
        name = comp.get('component')
        current = comp.get('version') or 'unknown'
        latest_ver = None

        # 1) PyPI'de ara
        try:
            r = requests.get(f'https://pypi.org/pypi/{name}/json', timeout=5)
            if r.status_code == 200:
                latest_ver = r.json().get('info', {}).get('version')
        except Exception:
            pass

        # 2) npm registry'de ara (fallback)
        if not latest_ver:
            try:
                r2 = requests.get(f'https://registry.npmjs.org/{name}', timeout=5)
                if r2.status_code == 200:
                    latest_ver = r2.json().get('dist-tags', {}).get('latest')
            except Exception:
                pass

        results.append({
            'component':       name,
            'current_version': current,
            'latest_version':  latest_ver or 'unknown'
        })

    return jsonify(results)

@app.route('/score', methods=['GET'])
def cra_score():
    if 'user' not in session:
        return jsonify({'error': 'Yetkisiz'}), 401
    # TODO: Compute CRA compliance score and criteria matching
    return jsonify({'score': 81, 'criteria': [
        {'name': 'Default Şifre', 'status': False},
        {'name': 'Known Vulnerabilities', 'status': True},
        {'name': 'Update Policy', 'status': False}
    ]})

@app.route('/plans', methods=['GET', 'POST'])
def plans():
    if 'user' not in session:
        return jsonify({'error':'Yetkisiz'}), 401
    user = session['user']
    if request.method == 'POST':
        data = request.get_json()
        plan = {
            'user': user,
            'component': data.get('component'),
            'date': data.get('date'),
            'note': data.get('note'),
            'status': 'Beklemede'
        }
        PLANS.append(plan)
        return jsonify(plan), 201
    # GET: sadece o kullanıcıya ait planları döndür
    user_plans = [p for p in PLANS if p['user'] == user]
    return jsonify(user_plans)

@app.route('/logs', methods=['GET'])
def logs():
    user=session.get('user')
    if not user: return jsonify({'error':'Yetkisiz'}),401
    user_logs=[l for l in LOGS if l['user']==user]
    return jsonify(user_logs)


# En başta:
REPORTS = []     # {user,date,sbom,component_count,vuln_count,score,file}

app.config['REPORT_FOLDER'] = 'reports'
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)

# PDF indirme route
@app.route('/reports/files/<path:filename>')
def report_file(filename):
    return send_from_directory(app.config['REPORT_FOLDER'], filename, as_attachment=True)

# Rapor oluşturma ve listeleme
@app.route('/reports', methods=['GET', 'POST'])
def reports():
    user = session.get('user')
    if not user:
        return jsonify({'error': 'Yetkisiz'}), 401

    # SBOM klasöründen en son yüklenen dosyayı bul
    sbom_files = os.listdir(app.config['UPLOAD_FOLDER'])
    if not sbom_files:
        return jsonify({'error': 'Önce SBOM yükleyin'}), 400
    latest_sbom = sorted(
        sbom_files,
        key=lambda f: os.path.getctime(os.path.join(app.config['UPLOAD_FOLDER'], f))
    )[-1]
    sbom_path = os.path.join(app.config['UPLOAD_FOLDER'], latest_sbom)

    if request.method == 'POST':
        # 1) Parse SBOM & CVE tarama
        comps = parse_sbom(sbom_path)
        vulns = scan_vulnerabilities(comps)
        score = int((1 - len({v['component'] for v in vulns}) / len(comps)) * 100) if comps else 0

        # 2) ReportLab ile PDF oluştur ve kaydet
        pdf_filename = f'report_{user}_{int(time.time())}.pdf'
        pdf_path = os.path.join(app.config['REPORT_FOLDER'], pdf_filename)

        c = canvas.Canvas(pdf_path, pagesize=A4)
        width, height = A4

        # Başlık ve meta
        c.setFont("Helvetica-Bold", 16)
        c.drawCentredString(width/2, height - 50, "CRA SBOM Analiz Raporu")
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 80, f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height - 95, f"SBOM: {latest_sbom}")
        c.drawString(50, height - 110, f"Toplam Bilesen: {len(comps)}, Zafiyet: {len(vulns)}, Skor: {score}%")

        # Zafiyet detayları tablosu
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 140, "Zafiyet Detaylari:")
        y = height - 160
        c.setFont("Helvetica", 9)
        c.drawString(50, y, "Bilesen")
        c.drawString(200, y, "CVE ID")
        c.drawString(300, y, "Açiklama")
        y -= 15
        for v in vulns:
            if y < 50:
                c.showPage()
                y = height - 50
            c.drawString(50, y, v['component'][:20])
            c.drawString(200, y, v['cve'])
            c.drawString(300, y, v['desc'][:60])
            y -= 12

        c.save()

        # Log kaydı ve geri dönüş JSON
        record_log(user, f'report_generated {pdf_filename}')
        entry = {
            'user': user,
            'date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'sbom': latest_sbom,
            'score': score,
            'file': pdf_filename
        }
        REPORTS.append(entry)
        return jsonify(entry), 201

    # GET: sadece o kullanıcıya ait raporları döndür
    user_reports = [r for r in REPORTS if r['user'] == user]
    return jsonify(user_reports)

if __name__ == '__main__':
    app.run(debug=True)