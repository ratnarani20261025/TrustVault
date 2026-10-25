import os, sqlite3, uuid, secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("TRUSTVAULT_DB", os.path.join(BASE, "trustvault.db"))
STORAGE = os.environ.get("TRUSTVAULT_STORAGE", os.path.join(BASE, "private_uploads"))
os.makedirs(STORAGE, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-ME-before-deployment-" + secrets.token_hex(16))
MAX_UPLOAD = 5 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".docx", ".csv"}

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def now():
    return datetime.now(timezone.utc).isoformat()

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer'))
        );
        CREATE TABLE IF NOT EXISTS documents(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
          category TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL, size INTEGER NOT NULL, content_type TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grants(
          document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          can_read INTEGER NOT NULL DEFAULT 0, can_edit INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(document_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor_id INTEGER,
          action TEXT NOT NULL, document_id TEXT, detail TEXT NOT NULL, outcome TEXT NOT NULL,
          FOREIGN KEY(actor_id) REFERENCES users(id)
        );
        """)
        seeds = [
          ("admin", "AdminDemo!2026", "admin"),
          ("owner", "OwnerDemo!2026", "owner"),
          ("viewer", "ViewerDemo!2026", "viewer"),
          ("other", "OtherDemo!2026", "viewer"),
        ]
        for username, password, role in seeds:
            con.execute("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES(?,?,?)",
                        (username, generate_password_hash(password), role))

def audit(actor_id, action, document_id=None, detail="", outcome="success"):
    with db() as con:
        con.execute("INSERT INTO audit(at,actor_id,action,document_id,detail,outcome) VALUES(?,?,?,?,?,?)",
                    (now(), actor_id, action, document_id, detail[:500], outcome))

def current_user():
    if "uid" not in session:
        return None
    with db() as con:
        return con.execute("SELECT id,username,role FROM users WHERE id=?", (session["uid"],)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user()["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

def can_read(user, doc_id):
    with db() as con:
        doc = con.execute("SELECT owner_id FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not doc: return False
        if user["role"] == "admin" or doc["owner_id"] == user["id"]: return True
        row = con.execute("SELECT can_read FROM grants WHERE document_id=? AND user_id=?",
                          (doc_id, user["id"])).fetchone()
        return bool(row and row["can_read"])

def can_edit(user, doc_id):
    with db() as con:
        doc = con.execute("SELECT owner_id FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not doc: return False
        if user["role"] == "admin" or doc["owner_id"] == user["id"]: return True
        row = con.execute("SELECT can_edit FROM grants WHERE document_id=? AND user_id=?",
                          (doc_id, user["id"])).fetchone()
        return bool(row and row["can_edit"])

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("_csrf", "")
        if not token or not secrets.compare_digest(token, session.get("_csrf", "")):
            abort(400, "Invalid CSRF token")

@app.route("/")
def home():
    return redirect(url_for("documents") if current_user() else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["uid"] = user["id"]
            session["_csrf"] = secrets.token_urlsafe(24)
            audit(user["id"], "login", detail="Successful login")
            return redirect(url_for("documents"))
        audit(user["id"] if user else None, "login_failed", detail="Invalid credentials", outcome="denied")
        flash("Login details were not accepted.")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user()
    audit(user["id"], "logout", detail="User logged out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/documents")
@login_required
def documents():
    user = current_user()
    q = request.args.get("q","").strip()
    category = request.args.get("category","").strip()
    owner = request.args.get("owner","").strip()
    date = request.args.get("date","").strip()
    sql = """SELECT DISTINCT d.*, u.username owner_name FROM documents d
             JOIN users u ON u.id=d.owner_id
             LEFT JOIN grants g ON g.document_id=d.id AND g.user_id=?
             WHERE (?='admin' OR d.owner_id=? OR g.can_read=1 OR g.can_edit=1)
             AND (d.name LIKE ? OR d.category LIKE ?)
             AND (?='' OR d.category=?)
             AND (?='' OR u.username=?)
             AND (?='' OR substr(d.created_at,1,10)=?)
             ORDER BY d.created_at DESC"""
    like = "%" + q + "%"
    with db() as con:
        rows = con.execute(sql, (user["id"], user["role"], user["id"], like, like,
                                 category, category, owner, owner, date, date)).fetchall()
        users = con.execute("SELECT id,username,role FROM users ORDER BY username").fetchall()
    return render_template("documents.html", docs=rows, users=users, user=user,
                           q=q, category=category, owner=owner, date=date)

@app.route("/upload", methods=["GET","POST"])
@role_required("admin","owner")
def upload():
    user = current_user()
    if request.method == "POST":
        f = request.files.get("file")
        name = request.form.get("name","").strip() or (secure_filename(f.filename) if f else "")
        category = request.form.get("category","General").strip()[:80]
        if not f or not f.filename:
            flash("Choose a file first.")
            return redirect(url_for("upload"))
        safe_name = secure_filename(f.filename)
        ext = os.path.splitext(safe_name)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            flash("File type is not allowed.")
            return redirect(url_for("upload"))
        data = f.read(MAX_UPLOAD + 1)
        if not data or len(data) > MAX_UPLOAD:
            flash("File is empty or exceeds 5 MB.")
            return redirect(url_for("upload"))
        doc_id = str(uuid.uuid4())
        stored = doc_id + ext
        with open(os.path.join(STORAGE, stored), "wb") as out:
            out.write(data)
        with db() as con:
            con.execute("""INSERT INTO documents(id,name,stored_name,category,owner_id,created_at,size,content_type)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (doc_id, name[:180], stored, category, user["id"], now(), len(data),
                         f.mimetype or "application/octet-stream"))
        audit(user["id"], "upload", doc_id, f"Uploaded {name[:180]}")
        flash("Document uploaded.")
        return redirect(url_for("documents"))
    return render_template("upload.html")

@app.route("/document/<doc_id>")
@login_required
def detail(doc_id):
    user = current_user()
    with db() as con:
        doc = con.execute("""SELECT d.*,u.username owner_name FROM documents d JOIN users u ON u.id=d.owner_id
                             WHERE d.id=?""", (doc_id,)).fetchone()
    if not doc:
        audit(user["id"], "read_denied", doc_id, "Document not found", "denied")
        abort(404)
    if not can_read(user, doc_id):
        audit(user["id"], "read_denied", doc_id, "Unauthorized document view", "denied")
        abort(403)
    audit(user["id"], "view", doc_id, "Document metadata viewed")
    with db() as con:
        grants = con.execute("""SELECT g.*,u.username FROM grants g JOIN users u ON u.id=g.user_id
                                WHERE g.document_id=? ORDER BY u.username""", (doc_id,)).fetchall()
        users = con.execute("SELECT id,username,role FROM users WHERE id<>? ORDER BY username", (doc["owner_id"],)).fetchall()
    return render_template("detail.html", doc=doc, grants=grants, users=users, user=user,
                           can_manage=(user["role"]=="admin" or doc["owner_id"]==user["id"]))

@app.route("/document/<doc_id>/download")
@login_required
def download(doc_id):
    user = current_user()
    with db() as con:
        doc = con.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc or not can_read(user, doc_id):
        audit(user["id"], "download_denied", doc_id, "Unauthorized or missing document", "denied")
        abort(404 if not doc else 403)
    path = os.path.join(STORAGE, doc["stored_name"])
    if not os.path.isfile(path):
        audit(user["id"], "download_missing", doc_id, "Stored file missing", "error")
        abort(404)
    audit(user["id"], "download", doc_id, "Document downloaded")
    return send_file(path, as_attachment=True, download_name=secure_filename(doc["name"]) or "document")

@app.route("/document/<doc_id>/grant", methods=["POST"])
@role_required("admin","owner")
def grant(doc_id):
    user = current_user()
    if not can_edit(user, doc_id):
        audit(user["id"], "grant_denied", doc_id, "Unauthorized permission change", "denied")
        abort(403)
    target = request.form.get("user_id", type=int)
    read = 1 if request.form.get("can_read") == "on" else 0
    edit = 1 if request.form.get("can_edit") == "on" else 0
    if edit: read = 1
    with db() as con:
        doc = con.execute("SELECT owner_id FROM documents WHERE id=?", (doc_id,)).fetchone()
        target_user = con.execute("SELECT id FROM users WHERE id=?", (target,)).fetchone()
        if not doc or not target_user or target == doc["owner_id"]:
            abort(400)
        if not read and not edit:
            con.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (doc_id,target))
            detail = f"Revoked access from user_id={target}"
        else:
            con.execute("""INSERT INTO grants(document_id,user_id,can_read,can_edit) VALUES(?,?,?,?)
                           ON CONFLICT(document_id,user_id) DO UPDATE SET can_read=excluded.can_read,can_edit=excluded.can_edit""",
                        (doc_id,target,read,edit))
            detail = f"Set permissions for user_id={target}: read={read}, edit={edit}"
    audit(user["id"], "permission_change", doc_id, detail)
    flash("Permissions updated. Revocation applies to future requests.")
    return redirect(url_for("detail", doc_id=doc_id))

@app.route("/document/<doc_id>/rename", methods=["POST"])
@login_required
def rename(doc_id):
    user = current_user()
    if not can_edit(user, doc_id):
        audit(user["id"], "edit_denied", doc_id, "Unauthorized rename", "denied")
        abort(403)
    name = request.form.get("name","").strip()
    if not name or len(name)>180:
        abort(400)
    with db() as con:
        con.execute("UPDATE documents SET name=? WHERE id=?", (name,doc_id))
    audit(user["id"], "rename", doc_id, f"Renamed document to {name}")
    flash("Document name updated.")
    return redirect(url_for("detail", doc_id=doc_id))

@app.route("/document/<doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    user = current_user()
    if not can_edit(user, doc_id):
        audit(user["id"], "delete_denied", doc_id, "Unauthorized delete", "denied")
        abort(403)
    with db() as con:
        doc = con.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        con.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    if doc:
        try: os.remove(os.path.join(STORAGE, doc["stored_name"]))
        except FileNotFoundError: pass
        audit(user["id"], "delete", doc_id, f"Deleted {doc['name']}")
    flash("Document deleted.")
    return redirect(url_for("documents"))

@app.route("/admin/audit")
@role_required("admin")
def audit_view():
    with db() as con:
        rows = con.execute("""SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.actor_id
                              ORDER BY a.id DESC LIMIT 500""").fetchall()
    return render_template("audit.html", rows=rows)

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You are not allowed to access this resource."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested resource was not found."), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=getattr(e, "description", "Invalid request.")), 400

init_db()
if __name__ == "__main__":
    app.run(debug=False)
