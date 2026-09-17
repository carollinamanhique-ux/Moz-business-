import os
import sqlite3
import uuid
import hmac
import hashlib
import json
import requests
import re

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_PATH = BASE_DIR / "moz_business.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Official Moz Business payment contacts
PAYMENT_CONTACTS = {
    "MPESA": "858804425",
    "EMOLA": "865742391",
}

app = Flask(__name__)
app.secret_key = os.environ.get("MOZ_BUSINESS_SECRET", "CHANGE_THIS_SECRET_IN_PRODUCTION")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

ALLOWED_VIDEO = {"mp4", "webm", "mov"}
CATEGORIES = ["Restaurantes", "Moda", "Beleza", "Automóveis", "Casa",
              "Tecnologia", "Educação", "Serviços", "Esportes", "Outras"]

# Preços provisórios: altere estes valores antes de colocar o Moz Business em LIVE.
PLANS = {
    "basico": {"name": "Básico", "amount": 500, "description": "A empresa aparece nas pesquisas do Moz Business."},
    "premium": {"name": "Premium", "amount": 700, "description": "Pesquisa + perfil completo com fotos, serviços, contactos e redes sociais."},
    "anuncio": {"name": "Anúncio", "amount": 1500, "description": "Publicidade para TikTok e Facebook. Vídeo até 30 segundos e sujeito a aprovação."},
}

PAGAR_BASE_URL = os.environ.get("PAGAR_API_BASE_URL", "https://api.pagar.co.mz/api/v1")
PAGAR_API_KEY = os.environ.get("PAGAR_API_KEY", "")
PAGAR_SIGNING_SECRET = os.environ.get("PAGAR_SIGNING_SECRET", "")
PAGAR_WEBHOOK_SECRET = os.environ.get("PAGAR_WEBHOOK_SECRET", "")

class DatabaseConnection:
    """Small compatibility wrapper so the same Flask code works with SQLite and Supabase Postgres."""
    def __init__(self, conn, postgres=False):
        self.conn = conn
        self.postgres = postgres

    def execute(self, query, params=()):
        if self.postgres:
            query = query.replace("?", "%s")
        return self.conn.execute(query, params)

    def executescript(self, script):
        if self.postgres:
            raise RuntimeError("Schema creation for Supabase is done by the SQL script supplied with this project.")
        return self.conn.executescript(script)

    def commit(self):
        return self.conn.commit()

    def close(self):
        return self.conn.close()


def db():
    if "db" not in g:
        if DATABASE_URL:
            if psycopg is None:
                raise RuntimeError("psycopg não está instalado. Faça deploy com o requirements.txt deste projeto.")
            conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
            g.db = DatabaseConnection(conn, postgres=True)
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g.db = DatabaseConnection(conn, postgres=False)
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()

def init_db():
    # In production, Supabase already contains the schema created by the SQL migration.
    if DATABASE_URL:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'business',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        city TEXT NOT NULL,
        description TEXT NOT NULL,
        phone TEXT,
        whatsapp TEXT,
        instagram TEXT,
        facebook TEXT,
        tiktok TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS ads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        video_filename TEXT,
        duration_seconds INTEGER,
        destination_url TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        company_id INTEGER NOT NULL,
        plan_code TEXT NOT NULL,
        amount_mzn INTEGER NOT NULL,
        method TEXT NOT NULL CHECK(method IN ('MPESA','EMOLA')),
        payer_phone TEXT NOT NULL,
        reference TEXT NOT NULL UNIQUE,
        provider_payment_id TEXT,
        status TEXT NOT NULL DEFAULT 'PENDING',
        failure_reason TEXT,
        paid_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS webhook_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_event_id TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # Create a local admin account only if none exists.
    admin = conn.execute("SELECT id FROM users WHERE email = ?", ("admin@mozbusiness.local",)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
            ("Administrador", "admin@mozbusiness.local",
             generate_password_hash("ChangeMe-2026!"), "admin")
        )
    conn.commit()
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Faça login para continuar.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Acesso reservado ao administrador.")
            return redirect(url_for("home"))
        return fn(*args, **kwargs)
    return wrapped

def allowed_video(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_VIDEO


def pagar_post(path, body, idempotency_key):
    """Chama a Pagar apenas no backend; nunca expõe a API key ao navegador."""
    if not PAGAR_API_KEY or not PAGAR_SIGNING_SECRET:
        raise RuntimeError("Pagamentos ainda não configurados. Defina as credenciais Pagar no servidor.")
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    timestamp = str(int(__import__("time").time() * 1000))
    nonce = uuid.uuid4().hex
    body_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    from urllib.parse import urlparse
    canonical_path = urlparse(PAGAR_BASE_URL + path).path
    canonical = "\n".join([timestamp, nonce, "POST", canonical_path, body_hash])
    signature = hmac.new(PAGAR_SIGNING_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    r = requests.post(
        PAGAR_BASE_URL + path,
        headers={
            "Authorization": f"Bearer {PAGAR_API_KEY}",
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
            "X-Pagar-Timestamp": timestamp,
            "X-Pagar-Nonce": nonce,
            "X-Pagar-Signature": "v1=" + signature,
        },
        data=raw,
        timeout=25,
    )
    try:
        data = r.json()
    except ValueError:
        data = {"message": r.text}
    if not r.ok:
        raise RuntimeError(data.get("message", "Pagamento recusado pelo provedor."))
    return data

def payment_methods():
    return [("MPESA", "M-Pesa"), ("EMOLA", "e-Mola")]


def ensure_company_entitlement_columns():
    # The Supabase schema already contains these columns.
    if DATABASE_URL:
        return
    conn = db()
    cols = {row[1] for row in conn.execute("PRAGMA table_info(companies)").fetchall()}
    if "active_plan" not in cols:
        conn.execute("ALTER TABLE companies ADD COLUMN active_plan TEXT DEFAULT NULL")
    if "plan_status" not in cols:
        conn.execute("ALTER TABLE companies ADD COLUMN plan_status TEXT DEFAULT 'inactive'")
    if "plan_expires_at" not in cols:
        conn.execute("ALTER TABLE companies ADD COLUMN plan_expires_at TEXT DEFAULT NULL")
    conn.commit()

def activate_paid_plan(payment_id):
    conn = db()
    payment = conn.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    if not payment:
        return False
    company_id = payment["company_id"]
    plan_code = payment["plan_code"]
    if not company_id or plan_code not in PLANS:
        return False
    # A PAID payment activates exactly the plan that was purchased.
    conn.execute("""UPDATE companies
       SET active_plan = ?, plan_status = 'active'
       WHERE id = ?""", (plan_code, company_id))
    conn.commit()
    return True

@app.route("/")
def home():
    conn = db()
    companies = conn.execute(
        "SELECT * FROM companies WHERE status='approved' ORDER BY id DESC LIMIT 12"
    ).fetchall()
    ads = conn.execute("""
        SELECT ads.*, companies.name AS company_name, companies.city
        FROM ads JOIN companies ON companies.id=ads.company_id
        WHERE ads.status='approved' AND companies.status='approved'
        ORDER BY ads.id DESC LIMIT 8
    """).fetchall()
    return render_template("home.html", companies=companies, ads=ads, categories=CATEGORIES)

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    city = request.args.get("city", "").strip()
    sql = "SELECT * FROM companies WHERE status='approved'"
    params = []
    if q:
        sql += " AND (name LIKE ? OR category LIKE ? OR description LIKE ?)"
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if city:
        sql += " AND city LIKE ?"
        params.append(f"%{city}%")
    sql += " ORDER BY name"
    companies = db().execute(sql, params).fetchall()
    return render_template("search.html", companies=companies, q=q, city=city)

@app.route("/company/<int:company_id>")
def company(company_id):
    conn = db()
    c = conn.execute("SELECT * FROM companies WHERE id=?", (company_id,)).fetchone()
    if not c or (c["status"] != "approved" and session.get("user_id") != c["owner_id"] and session.get("role") != "admin"):
        return "Empresa não encontrada", 404
    ads = conn.execute("SELECT * FROM ads WHERE company_id=? AND status='approved' ORDER BY id DESC", (company_id,)).fetchall()
    return render_template("company.html", company=c, ads=ads)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if not name or not email or len(password) < 8:
            flash("Preencha os campos e use uma senha com pelo menos 8 caracteres.")
            return render_template("register.html")
        try:
            db().execute(
                "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                (name, email, generate_password_hash(password), "business")
            )
            db().commit()
            flash("Conta criada. Agora faça login.")
            return redirect(url_for("login"))
        except Exception:
            flash("Este email já está cadastrado ou não foi possível criar a conta.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form["password"]):
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["name"] = user["name"]
            return redirect(url_for("admin" if user["role"] == "admin" else "dashboard"))
        flash("Email ou senha incorretos.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    companies = db().execute("SELECT * FROM companies WHERE owner_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    ads = db().execute("""
        SELECT ads.*, companies.name AS company_name
        FROM ads JOIN companies ON companies.id=ads.company_id
        WHERE companies.owner_id=? ORDER BY ads.id DESC
    """, (session["user_id"],)).fetchall()
    return render_template("dashboard.html", companies=companies, ads=ads)

@app.route("/company/new", methods=["GET", "POST"])
@login_required
def new_company():
    if request.method == "POST":
        f = request.form
        db().execute("""
            INSERT INTO companies(owner_id,name,category,city,description,phone,whatsapp,instagram,facebook,tiktok)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (session["user_id"], f["name"].strip(), f["category"], f["city"].strip(),
              f["description"].strip(), f.get("phone","").strip(), f.get("whatsapp","").strip(),
              f.get("instagram","").strip(), f.get("facebook","").strip(), f.get("tiktok","").strip()))
        db().commit()
        flash("Empresa criada e enviada para aprovação.")
        return redirect(url_for("dashboard"))
    return render_template("company_form.html", categories=CATEGORIES)

@app.route("/company/<int:company_id>/ad/new", methods=["GET", "POST"])
@login_required
def new_ad(company_id):
    c = db().execute("SELECT * FROM companies WHERE id=? AND owner_id=?", (company_id, session["user_id"])).fetchone()
    if not c:
        return "Empresa não encontrada", 404
    if request.method == "POST":
        f = request.form
        duration = int(f["duration"])
        if duration < 1 or duration > 30:
            flash("O vídeo deve ter no máximo 30 segundos.")
            return render_template("ad_form.html", company=c)
        file = request.files.get("video")
        filename = None
        if file and file.filename:
            if not allowed_video(file.filename):
                flash("Formato de vídeo não permitido. Use MP4, WebM ou MOV.")
                return render_template("ad_form.html", company=c)
            filename = secure_filename(file.filename)
            filename = f"{session['user_id']}_{company_id}_{filename}"
            file.save(UPLOAD_DIR / filename)
        db().execute("""
            INSERT INTO ads(company_id,title,description,video_filename,duration_seconds,destination_url)
            VALUES(?,?,?,?,?,?)
        """, (company_id, f["title"].strip(), f["description"].strip(), filename, duration, f.get("destination_url","").strip()))
        db().commit()
        flash("Anúncio enviado para aprovação.")
        return redirect(url_for("dashboard"))
    return render_template("ad_form.html", company=c)


@app.route("/payments", methods=["GET", "POST"])
@login_required
def payments():
    conn = db()
    companies = conn.execute(
        "SELECT * FROM companies WHERE owner_id=? AND status='approved' ORDER BY id",
        (session["user_id"],)
    ).fetchall()
    history = conn.execute(
        "SELECT payments.*, companies.name AS company_name FROM payments "
        "JOIN companies ON companies.id=payments.company_id WHERE payments.user_id=? "
        "ORDER BY payments.id DESC LIMIT 20", (session["user_id"],)
    ).fetchall()
    if request.method == "POST":
        company_id = int(request.form["company_id"])
        plan_code = request.form["plan_code"]
        method = request.form["method"]
        phone = request.form["payer_phone"].strip()
        if company_id not in [c["id"] for c in companies]:
            flash("Empresa inválida.")
            return redirect(url_for("payments"))
        if plan_code not in PLANS or method not in {"MPESA", "EMOLA"}:
            flash("Plano ou método de pagamento inválido.")
            return redirect(url_for("payments"))
        if not re.fullmatch(r"\+?258\s?\d{9}", phone.replace("-", "")):
            flash("Informe um número moçambicano válido.")
            return redirect(url_for("payments"))
        plan=PLANS[plan_code]
        reference=f"MB-{uuid.uuid4().hex[:12].upper()}"
        conn.execute("""INSERT INTO payments
            (user_id,company_id,plan_code,amount_mzn,method,payer_phone,reference)
            VALUES(?,?,?,?,?,?,?)""",
            (session["user_id"],company_id,plan_code,plan["amount"],method,phone,reference))
        payment_db_id=conn.execute("SELECT id FROM payments WHERE reference=?", (reference,)).fetchone()["id"]
        conn.commit()
        try:
            result=pagar_post("/payments", {
                "reference": reference,
                "title": f"Moz Business - {plan['name']}",
                "description": plan["description"],
                "amountMzn": plan["amount"],
                "method": method,
                "payerPhone": phone,
            }, f"payment:{payment_db_id}")
            payment=result.get("payment", result)
            conn.execute(
                "UPDATE payments SET provider_payment_id=?,status=?,failure_reason=? WHERE id=?",
                (payment.get("id"), payment.get("status","PENDING"), payment.get("failureReason"), payment_db_id)
            )
            conn.commit()
            flash("Pagamento iniciado. Confirme no seu telemóvel e aguarde a confirmação.")
        except Exception as e:
            conn.execute("UPDATE payments SET status='FAILED',failure_reason=? WHERE id=?", (str(e)[:500], payment_db_id))
            conn.commit()
            flash("Não foi possível iniciar o pagamento: " + str(e))
        return redirect(url_for("payments"))
    return render_template("payments.html", companies=companies, history=history, plans=PLANS, methods=payment_methods())

@app.post("/payments/webhook")
def pagar_webhook():
    raw=request.get_data()
    event_id=request.headers.get("Pagar-Event-Id")
    sig=request.headers.get("Pagar-Signature","")
    if not PAGAR_WEBHOOK_SECRET or not event_id:
        return "", 401
    parts={}
    for item in sig.split(","):
        if "=" in item:
            k,v=item.split("=",1)
            parts[k]=v
    timestamp=parts.get("t")
    received=parts.get("v1","")
    if not timestamp or not re.fullmatch(r"\d+",timestamp) or not re.fullmatch(r"[a-f0-9]{64}",received):
        return "",401
    if abs(__import__("time").time()-int(timestamp))>300:
        return "",401
    expected=hmac.new(PAGAR_WEBHOOK_SECRET.encode(), (timestamp+"."+raw.decode("utf-8")).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(received,expected):
        return "",401
    conn=db()
    try:
        conn.execute("INSERT INTO webhook_events(provider_event_id,payload) VALUES(?,?)",(event_id,raw.decode("utf-8")))
    except Exception:
        # Duplicate webhook events are intentionally idempotent.
        return "",200
    event=json.loads(raw.decode("utf-8"))
    payment=event.get("payment",{})
    reference=payment.get("reference")
    status=payment.get("status")
    if reference and status:
        row=conn.execute("SELECT id FROM payments WHERE reference=?",(reference,)).fetchone()
        if row:
            if status=="PAID":
                conn.execute("UPDATE payments SET status='PAID',paid_at=CURRENT_TIMESTAMP,failure_reason=NULL WHERE id=?",(row["id"],))
                activate_paid_plan(row["id"])
            elif status in {"FAILED","CANCELLED","RECONCILIATION_REQUIRED"}:
                final_status = "FAILED" if status == "RECONCILIATION_REQUIRED" else status
                conn.execute("UPDATE payments SET status=?,failure_reason=? WHERE id=?",(final_status,payment.get("failureReason") or status,row["id"]))
    conn.commit()
    return "",200

@app.route("/admin")
@admin_required
def admin():
    conn = db()
    companies = conn.execute("SELECT companies.*, users.email AS owner_email FROM companies JOIN users ON users.id=companies.owner_id ORDER BY companies.id DESC").fetchall()
    ads = conn.execute("SELECT ads.*, companies.name AS company_name FROM ads JOIN companies ON companies.id=ads.company_id ORDER BY ads.id DESC").fetchall()
    return render_template("admin.html", companies=companies, ads=ads)

@app.post("/admin/company/<int:company_id>/<action>")
@admin_required
def moderate_company(company_id, action):
    status = "approved" if action == "approve" else "rejected"
    db().execute("UPDATE companies SET status=? WHERE id=?", (status, company_id))
    db().commit()
    return redirect(url_for("admin"))

@app.post("/admin/ad/<int:ad_id>/<action>")
@admin_required
def moderate_ad(ad_id, action):
    status = "approved" if action == "approve" else "rejected"
    db().execute("UPDATE ads SET status=? WHERE id=?", (status, ad_id))
    db().commit()
    return redirect(url_for("admin"))

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), debug=False)


@app.context_processor
def inject_payment_contacts():
    return {"payment_contacts": PAYMENT_CONTACTS}
