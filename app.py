# app.py
import os
import time
from io import BytesIO
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_from_directory
)
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import pymysql
from sbom_parser import parse_sbom
from vulnerability_scanner import scan_vulnerabilities
from version_checker import check_version
from cra_rule_checker import run_cra_checks
from offline_vulnerability_scanner import scan_vulnerabilities_offline, load_cve_database
from update_vulnerability_scanner import download_and_extract_latest_cve_files
from datetime import datetime, timezone, timedelta

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import socket

# ─── App & Config ──────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates")
app.secret_key = "replace_with_secure_key"

# Upload & Report klasörleri
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["REPORT_FOLDER"] = "reports"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)

# ─── MySQL Bağlantı Ayarları ─────────────────────────────────────────────────────
DB_USER     = "cra_user"
DB_PASSWORD = "StrongPassw0rd!"
DB_HOST     = "localhost"
DB_NAME     = "cra_analyzer"

app.config["SQLALCHEMY_DATABASE_URI"] = (f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# SQLAlchemy ORM nesnesi
db = SQLAlchemy(app)

# ─── Models ───────────────────────────────────────────────────────────────────

class Product(db.Model):
    __tablename__ = "products"
    id        = db.Column(db.Integer,  primary_key=True)
    user      = db.Column(db.String(128), nullable=False)
    brand     = db.Column(db.String(128), nullable=False)
    model     = db.Column(db.String(128), nullable=False)
    version   = db.Column(db.String(64),  nullable=False)
    sbom_path = db.Column(db.String(256), nullable=False)
    created   = db.Column(db.DateTime,    server_default=db.func.now())

#Store CVEs
class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    
    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    component   = db.Column(db.String(255), nullable=False)
    cve_id      = db.Column(db.String(64), nullable=False)
    cvss        = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=False)
    scanned_at  = db.Column(db.DateTime, server_default=db.func.now())


# ─── In‐Memory Stores & Utils ─────────────────────────────────────────────────

USERS   = {}   # demo kullanıcı store
PLANS   = []   # güncelleme planları
LOGS    = []   # seyir defteri
REPORTS = []   # oluşturulan raporlar

def record_log(user, action):
    LOGS.append({
        "user":      user,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action":    action
    })

# ---Helper Function -------------
# Check if we can do online or offline cve scan (Depending on the result we'll use either for pdf generation)
def is_online(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error as ex:
        print(f"[WARN] No internet connection: {ex}")
        return False


# ─── Auth Routes ───────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        pwd   = request.form["password"]
        if email in USERS:
            return render_template("register.html", error="Bu e-posta zaten kayıtlı.")
        USERS[email] = pwd
        session["user"] = email
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        pwd   = request.form["password"]
        if USERS.get(email) == pwd:
            session["user"] = email
            return redirect(url_for("index"))
        return render_template("login.html", error="Geçersiz e-posta veya şifre.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─── Main Dashboard ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", user=session["user"])


# ─── SBOM & Analysis ──────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload_sbom():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401
    f = request.files.get("file")
    if not f:
        return jsonify({"error":"Dosya bulunamadı"}), 400
    fn   = secure_filename(f.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], fn)
    f.save(path)
    comps = parse_sbom(path)
    return jsonify(comps[:50])

#Returns the list of all uploaded files
@app.route("/list-sboms", methods=["GET"])
def list_sboms():
    if "user" not in session:
        return jsonify({"error": "Yetkisiz"}), 401
    
    allowed_exts = {'.json', '.xml'}
    files = [
        f for f in os.listdir(app.config["UPLOAD_FOLDER"])
        if not f.startswith('.') and os.path.splitext(f)[1].lower() in allowed_exts
    ]

    #HOW DO I MAKE IT TAKE THEM FROM THE DATABASE?
    #files = os.listdir(app.config["UPLOAD_FOLDER"])
    files = sorted(files, key=lambda f: os.path.getctime(os.path.join(app.config["UPLOAD_FOLDER"], f)), reverse=True)

    return jsonify(files)


@app.route('/scan-online', methods=['POST'])
def scan_cve():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401
    
    data = request.get_json()
    selected_file = data.get("filename") if data else None

    files = os.listdir(app.config["UPLOAD_FOLDER"])
    if not files:
        return jsonify({"error":"Önce SBOM yükleyin"}), 400
    
    if selected_file and selected_file in files:
        path = os.path.join(app.config["UPLOAD_FOLDER"], selected_file)
    else:
        # Fallback: use latest file
        latest = sorted(files, key=lambda f: os.path.getctime(os.path.join(app.config["UPLOAD_FOLDER"], f)))[-1]
        path = os.path.join(app.config["UPLOAD_FOLDER"], latest)

    print("USED FILE:")
    print(selected_file)

    comps = parse_sbom(path)
    results = scan_vulnerabilities(comps)
    return jsonify(results)


@app.route('/scan-offline', methods=['POST'])
def scan_cve_offline():
    if 'user' not in session:
        return jsonify({'error': 'Yetkisiz'}), 401
    
    data = request.get_json()
    selected_file = data.get("filename") if data else None

    files = os.listdir(app.config["UPLOAD_FOLDER"])
    if not files:
        return jsonify({"error":"Önce SBOM yükleyin"}), 400
    
    if selected_file and selected_file in files:
        path = os.path.join(app.config["UPLOAD_FOLDER"], selected_file)
    else:
        # Fallback: use latest file
        latest = sorted(files, key=lambda f: os.path.getctime(os.path.join(app.config["UPLOAD_FOLDER"], f)))[-1]
        path = os.path.join(app.config["UPLOAD_FOLDER"], latest)

    print("USED FILE:")
    print(selected_file)

    comps = parse_sbom(path)
    results = scan_vulnerabilities_offline(comps)
    return jsonify(results)

#Display the last updated timestamp of CVEs on open
@app.route("/last-updated", methods=["GET"])
def get_last_updated():
    if 'user' not in session:
        return jsonify({'error': 'Yetkisiz'}), 401
    
    try:
        with open("last_updated.txt", "r") as f:
            timestamp = f.read().strip()
    except FileNotFoundError:
        # File not found — assume never updated
        timestamp = "Hiç güncellenmedi"
    return jsonify({"timestamp": timestamp})

#Updating the CVE database
@app.route("/update-cve", methods=["POST"])
def update_cve():
    if 'user' not in session:
            return jsonify({'error': 'Yetkisiz'}), 401

    try:
        # Check if file exists
        last_updated_path = "last_updated.txt"
        if os.path.exists(last_updated_path):
            with open(last_updated_path, "r") as f:
                last_updated_str = f.read().strip()
                last_updated = datetime.strptime(last_updated_str, "%Y-%m-%d %H:%M:%S UTC")
                last_updated = last_updated.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)
                delta = now - last_updated

                #CHANGE TO hours=2
                if delta < timedelta(seconds=10):
                    return jsonify({
                        "status": "skipped",
                        "message": f"Already updated less than 2 hours ago ({last_updated_str})."
                    })
                
        # Proceed with update
        download_and_extract_latest_cve_files()

        # Save the timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with open("last_updated.txt", "w") as f:
            f.write(timestamp)

        return jsonify({
            "status": "success",
            "message": "CVE data updated successfully.",
            "timestamp": timestamp  # Return timestamp to JS too
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route('/version-check', methods=['GET', "POST"])
def version_check():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401

    data = request.get_json()
    selected_file = data.get("filename") if data else None

    files = os.listdir(app.config["UPLOAD_FOLDER"])
    if not files:
        return jsonify({"error":"Önce SBOM yükleyin"}), 400
    
    if selected_file and selected_file in files:
        path = os.path.join(app.config["UPLOAD_FOLDER"], selected_file)
    else:
        # Fallback: use latest file
        latest = sorted(files, key=lambda f: os.path.getctime(os.path.join(app.config["UPLOAD_FOLDER"], f)))[-1]
        path = os.path.join(app.config["UPLOAD_FOLDER"], latest)

    #Debugging
    print("USED FILE:")
    print(selected_file)

    comps = parse_sbom(path)
    results = check_version(comps)
    record_log(session["user"], "Versiyon kontrolü yapıldı")
    return jsonify(results)


@app.route("/score", methods=["POST"])
def cra_score():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401
    
    data = request.get_json()
    filename = data.get("filename")

    if not filename:
        return jsonify({"error":"Dosya adı gerekli"}), 400

    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if not os.path.exists(path):
        return jsonify({"error": "Dosya bulunamadı"}), 404

    res = run_cra_checks(path)
    record_log(session["user"], "CRA skoru hesaplandı")
    return jsonify(res)

    files = os.listdir(app.config["UPLOAD_FOLDER"])
    if not files:
        return jsonify({"error":"Önce SBOM yükleyin"}), 400
    latest_path = os.path.join(app.config["UPLOAD_FOLDER"],
                    sorted(files, key=lambda f: os.path.getctime(os.path.join(app.config["UPLOAD_FOLDER"], f)))[-1])
    res    = run_cra_checks(latest_path)
    return jsonify(res)


# ─── Plans & Logs ─────────────────────────────────────────────────────────────

@app.route("/plans", methods=["GET","POST"])
def plans():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401
    user = session["user"]
    if request.method == "POST":
        data = request.get_json()
        plan = {
            "user":      user,
            "component": data["component"],
            "date":      data["date"],
            "note":      data.get("note",""),
            "status":    "Beklemede"
        }
        PLANS.append(plan)
        return jsonify(plan), 201
    return jsonify([p for p in PLANS if p["user"]==user])

@app.route("/logs")
def logs():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401
    return jsonify([l for l in LOGS if l["user"]==session["user"]])


# ─── Reports ──────────────────────────────────────────────────────────────────

@app.route("/reports/files/<path:filename>")
def report_file(filename):
    return send_from_directory(app.config["REPORT_FOLDER"], filename, as_attachment=True)

@app.route("/reports", methods=["GET","POST"])
def reports():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401
    

    if request.method == "POST":
        data = request.get_json()
        filename = data.get("filename")

        if not filename:
            return jsonify({"error":"Dosya adı gerekli"}), 400

        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        if not os.path.exists(path):
            return jsonify({"error": "Dosya bulunamadı"}), 404
        
        print("USED FILE:")
        print(filename)
        comps = parse_sbom(path)
        #THAT'S ONLY ONLINE - NEEDS TO CHANGE
        #vulns = scan_vulnerabilities(comps)

        if is_online():
            print("Online detected: using live CVE scanner")
            vulns = scan_vulnerabilities(comps)  # Online scanner
        else:
            print("Offline detected: falling back to offline scan")
            vulns = scan_vulnerabilities_offline(comps) # Offline scanner

        score = int((1 - len({v["component"] for v in vulns})/len(comps)) * 100) if comps else 0

        pdf_fn = f"report_{session['user']}_{int(time.time())}.pdf"
        pdf_p  = os.path.join(app.config["REPORT_FOLDER"], pdf_fn)
        c = canvas.Canvas(pdf_p, pagesize=A4)
        w,h = A4
        c.setFont("Helvetica-Bold",16)
        c.drawCentredString(w/2, h-50, "CRA SBOM Analiz Raporu")
        c.setFont("Helvetica",10)
        c.drawString(50, h-80, f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, h-95, f"SBOM: {os.path.basename(path)}")
        c.drawString(50, h-110, f"Bileşen: {len(comps)}, Zafiyet: {len(vulns)}, Skor: {score}%")
        y = h-140
        c.setFont("Helvetica", 9)
        for v in vulns:
            if y < 50:
                c.showPage(); y = h-50
            c.drawString(50, y, v["component"][:20])
            c.drawString(200, y, v["cve"])
            c.drawString(300, y, v["desc"][:60])
            y -= 12
        c.save()

        record_log(session["user"], f"report_generated {pdf_fn}")
        entry = {
            "user": session["user"],
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sbom": os.path.basename(path),
            "score": score,
            "file": pdf_fn
        }
        REPORTS.append(entry)
        return jsonify(entry), 201

    return jsonify([r for r in REPORTS if r["user"]==session["user"]])


# ─── Products ─────────────────────────────────────────────────────────────────

@app.route("/products", methods=["GET"])
def products():
    if "user" not in session:
        return jsonify([]), 401
    prods = Product.query.filter_by(user=session["user"]).all()
    return jsonify([
        {
            "id":         p.id,
            "brand":      p.brand,
            "model":      p.model,
            "version":    p.version,
            "sbom_path":  p.sbom_path,
            "created":    p.created.isoformat()
        } for p in prods
    ])

@app.route("/products/new", methods=["POST"])
def products_new():
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401
    f = request.files.get("sbom")
    fn = secure_filename(f"{int(time.time())}_{f.filename}")
    f.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
    p = Product(
        user      = session["user"],
        brand     = request.form["brand"],
        model     = request.form["model"],
        version   = request.form["version"],
        sbom_path = fn
    )
    db.session.add(p)
    db.session.commit()
    return ("", 204)

@app.route("/products/delete/<int:product_id>", methods=["POST"])
def delete_product(product_id):
    if "user" not in session:
        return jsonify({"error":"Yetkisiz"}), 401

    prod = Product.query.filter_by(id=product_id, user=session["user"]).first()
    if prod:
        # 1) Fiziksel dosyayı sil
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], prod.sbom_path))
        except OSError:
            pass

        # 2) Veritabanından sil ve commit
        db.session.delete(prod)
        db.session.commit()

        # 3) Kalan kayıtları yeniden numaralandır
        #    - Önce sayaç değişkenini başlat
        db.session.execute(text("SET @i := 0"))
        #    - Ardından created zamanına göre sıralı şekilde id'leri yeniden ata
        db.session.execute(text("""
            UPDATE products
            SET id = (@i := @i + 1)
            ORDER BY created
        """))
        # 4) AUTO_INCREMENT'ı son numaradan bir fazlası olarak ayarla
        db.session.execute(text("ALTER TABLE products AUTO_INCREMENT = 1"))
        db.session.commit()

    # 5) AJAX için boş 204 dön
    return ("", 204)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Uygulama bağlamında tabloları oluştur
    with app.app_context():
        db.create_all()
    app.run(debug=True)