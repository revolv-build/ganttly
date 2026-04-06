"""
Baseline
────────
A production-ready Flask starter kit with authentication, admin dashboard,
account management, and GDPR compliance. Fork this repo and build your
app-specific features on top.

Architecture:
  - Auth: login, register, password reset, email verification
  - Account: profile, password, avatar, GDPR export/delete
  - Admin: user management, impersonation, platform stats
  - Example CRUD: notes (delete when you build your own features)
"""

import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, g, abort, send_from_directory, jsonify
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape, Markup
import markdown as md_lib
import bleach
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import urllib.request
import urllib.error

# ── Config ────────────────────────────────────────────────────────

load_dotenv()

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "data" / "app.db"

UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "txt", "csv", "zip",
                      "png", "jpg", "jpeg", "gif", "svg", "mp4", "mov", "webm"}
MAX_UPLOAD_MB = 50

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 7  # 7 days
app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # 1 hour CSRF token validity
DEFAULT_PORT = int(os.environ.get("PORT", 5000))

# App metadata — update these for your project
APP_NAME = os.environ.get("APP_NAME", "Baseline")
APP_SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "support@example.com")

# Refuse to boot with default secret key in production
if os.environ.get("FLASK_ENV") == "production" and app.secret_key == "change-me-in-production":
    raise RuntimeError("SECRET_KEY must be set in production. Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\"")

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"],
                  storage_uri="memory://")

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

(APP_DIR / "data").mkdir(exist_ok=True)

# ── Markdown Rendering ────────────────────────────────────────────

ALLOWED_TAGS = [
    "p", "br", "strong", "em", "a", "ul", "ol", "li", "code", "pre",
    "blockquote", "h1", "h2", "h3", "h4", "img", "hr", "del", "table",
    "thead", "tbody", "tr", "th", "td",
]
ALLOWED_ATTRS = {
    "a": ["href", "title", "rel"],
    "img": ["src", "alt", "title"],
}

def render_markdown(text):
    """Convert Markdown to sanitised HTML."""
    if not text:
        return ""
    raw_html = md_lib.markdown(text, extensions=["fenced_code", "tables", "nl2br"])
    clean = bleach.clean(raw_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
    clean = clean.replace("<a ", '<a target="_blank" rel="noopener" ')
    return Markup(clean)

@app.template_filter("markdown")
def markdown_filter(text):
    return render_markdown(text)

def strip_markdown(text):
    """Remove markdown syntax for plain text previews."""
    if not text:
        return ""
    t = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    t = re.sub(r'\*(.+?)\*', r'\1', t)
    t = re.sub(r'__(.+?)__', r'\1', t)
    t = re.sub(r'_(.+?)_', r'\1', t)
    t = re.sub(r'#{1,6}\s*', '', t)
    t = re.sub(r'^\s*[-*+]\s+', '', t, flags=re.MULTILINE)
    t = re.sub(r'^\s*\d+\.\s+', '', t, flags=re.MULTILINE)
    t = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', t)
    t = re.sub(r'`{1,3}[^`]*`{1,3}', '', t)
    t = re.sub(r'^>\s*', '', t, flags=re.MULTILINE)
    t = re.sub(r'---+', '', t)
    t = re.sub(r'\n{2,}', ' ', t)
    return t.strip()

@app.template_filter("timeago")
def timeago_filter(dt_str):
    """Convert ISO datetime string to relative time like '3h ago'."""
    if not dt_str:
        return ""
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return dt_str[:10] if dt_str else ""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        m = seconds // 60
        return f"{m}m ago"
    elif seconds < 86400:
        h = seconds // 3600
        return f"{h}h ago"
    elif seconds < 604800:
        d = seconds // 86400
        return f"{d}d ago"
    elif seconds < 2592000:
        w = seconds // 604800
        return f"{w}w ago"
    else:
        return dt_str[:10]

@app.template_filter("strip_markdown")
def strip_markdown_filter(text):
    return strip_markdown(text)

# ── Email (Resend) ────────────────────────────────────────────────

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", f"{APP_NAME} <noreply@example.com>")

def send_email(to, subject, html_body):
    """Send email via Resend API. Returns True on success."""
    if not RESEND_API_KEY:
        print(f"[EMAIL SKIPPED — no API key] To: {to}, Subject: {subject}")
        return False
    payload = json.dumps({
        "from": EMAIL_FROM,
        "to": [to],
        "subject": subject,
        "html": html_body
    }).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.URLError as e:
        print(f"[EMAIL ERROR] {e}")
        return False

# ── Token Generation ──────────────────────────────────────────────

from itsdangerous import URLSafeTimedSerializer
_serializer = URLSafeTimedSerializer(app.secret_key)

def generate_token(data, salt="default"):
    return _serializer.dumps(data, salt=salt)

def verify_token(token, salt="default", max_age=3600):
    try:
        return _serializer.loads(token, salt=salt, max_age=max_age)
    except Exception:
        return None

# ── Database ──────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            email_verified INTEGER NOT NULL DEFAULT 0,
            bio           TEXT DEFAULT '',
            location      TEXT DEFAULT '',
            website       TEXT DEFAULT '',
            avatar_path   TEXT DEFAULT '',
            created       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notes (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            title         TEXT NOT NULL,
            body          TEXT DEFAULT '',
            created       TEXT NOT NULL,
            updated       TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    # Run migrations
    run_migrations(db)

    # Create default platform admin if no users exist
    row = db.execute("SELECT COUNT(*) FROM users").fetchone()
    if row[0] == 0:
        db.execute(
            "INSERT INTO users (name, email, password_hash, is_admin, email_verified, created) VALUES (?, ?, ?, ?, ?, ?)",
            ("Admin", "admin@example.com", generate_password_hash("changeme"), 1, 1, datetime.now(timezone.utc).isoformat())
        )
        print(f"Default admin created — email: admin@example.com  password: changeme")

    db.commit()
    db.close()

def run_migrations(db):
    """Run numbered SQL migration files from migrations/ directory."""
    migrations_dir = APP_DIR / "migrations"
    if not migrations_dir.exists():
        return
    db.execute("""
        CREATE TABLE IF NOT EXISTS _migrations (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            applied TEXT NOT NULL
        )
    """)
    applied = {row[0] for row in db.execute("SELECT name FROM _migrations").fetchall()}
    migration_files = sorted(migrations_dir.glob("*.sql"))
    for f in migration_files:
        if f.name not in applied:
            print(f"[MIGRATE] Applying {f.name}")
            db.executescript(f.read_text())
            db.execute("INSERT INTO _migrations (name, applied) VALUES (?, ?)",
                       (f.name, datetime.now(timezone.utc).isoformat()))
    db.commit()

# ── Helpers ───────────────────────────────────────────────────────

def get_user_by_id(uid):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def get_user_by_email(email):
    return get_db().execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone()

def current_user():
    uid = session.get("user_id")
    if uid:
        return get_user_by_id(uid)
    return None

def login_user(user):
    """Set session for user with session regeneration to prevent fixation."""
    session.clear()
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session.permanent = True

def slugify(text):
    slug = re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
    return slug[:60]

def avatar_html(user, size=22):
    """Generate avatar HTML — photo if available, initial letter if not."""
    if user and user["avatar_path"]:
        return Markup(f'<img src="/uploads/{user["avatar_path"]}" class="avatar-img" style="width:{size}px;height:{size}px;" />')
    name = user["name"] if user else "?"
    return Markup(f'<span class="avatar" style="width:{size}px;height:{size}px;font-size:{max(10, size//2)}px;">{name[0].upper()}</span>')

def paginate(query, params, page, per_page=20):
    """Add LIMIT/OFFSET to a query and return (items, total, pages)."""
    db = get_db()
    count_q = f"SELECT COUNT(*) FROM ({query})"
    total = db.execute(count_q, params).fetchone()[0]
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    offset = (page - 1) * per_page
    items = db.execute(f"{query} LIMIT ? OFFSET ?", (*params, per_page, offset)).fetchall()
    return items, total, pages, page

def search_like(term):
    """Escape a search term for safe LIKE queries. Returns (pattern, param)."""
    escaped = term.replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"

@app.context_processor
def inject_globals():
    return dict(
        current_user=current_user(),
        avatar_html=avatar_html,
        app_name=APP_NAME,
        support_email=APP_SUPPORT_EMAIL,
    )

# ── Auth Decorators ───────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def platform_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or not user["is_admin"]:
            flash("Admin access required.", "error")
            return redirect("/dashboard")
        return f(*args, **kwargs)
    return decorated

# ── Auth Routes ───────────────────────────────────────────────────

@app.route("/")
def landing():
    if session.get("user_id"):
        return redirect("/dashboard")
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login_page():
    if session.get("user_id"):
        return redirect("/dashboard")
    err = None
    form_ts = str(int(time.time()))
    if request.method == "POST":
        # Honeypot — bots fill hidden field
        if request.form.get("website_url", ""):
            err = "Invalid email or password."
            return render_template("login.html", err=err, form_ts=form_ts)
        # Time trap — reject instant submissions
        ts = request.form.get("_ts", "0")
        try:
            if time.time() - int(ts) < 1.5:
                err = "Invalid email or password."
                return render_template("login.html", err=err, form_ts=form_ts)
        except (ValueError, TypeError):
            pass
        user = get_user_by_email(request.form.get("email", ""))
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            login_user(user)
            return redirect("/dashboard")
        err = "Invalid email or password."
    return render_template("login.html", err=err, form_ts=form_ts)

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register_page():
    if session.get("user_id"):
        return redirect("/dashboard")
    err = None
    name = ""
    email = ""
    form_ts = str(int(time.time()))
    if request.method == "POST":
        if request.form.get("website_url", ""):
            err = "Registration failed."
            return render_template("register.html", err=err, name="", email="", form_ts=form_ts)
        ts = request.form.get("_ts", "0")
        try:
            if time.time() - int(ts) < 2:
                err = "Please slow down and try again."
                return render_template("register.html", err=err, name="", email="", form_ts=form_ts)
        except (ValueError, TypeError):
            pass
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        if not name or not email or not password:
            err = "All fields are required."
        elif len(password) < 8:
            err = "Password must be at least 8 characters."
        elif password != password_confirm:
            err = "Passwords do not match."
        elif get_user_by_email(email):
            err = "An account with that email already exists."
        else:
            db = get_db()
            db.execute(
                "INSERT INTO users (name, email, password_hash, created) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), datetime.now(timezone.utc).isoformat())
            )
            db.commit()
            user = get_user_by_email(email)
            login_user(user)
            token = generate_token(user["id"], salt="email-verify")
            verify_url = request.host_url.rstrip("/") + f"/verify-email/{token}"
            send_email(
                to=email,
                subject=f"Verify your email - {APP_NAME}",
                html_body=f"""
                <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
                    <h2 style="color:#333;">Welcome to {APP_NAME}!</h2>
                    <p style="color:#666;">Hi {name},</p>
                    <p style="color:#666;">Please verify your email address to get full access.</p>
                    <p style="margin:24px 0;">
                        <a href="{verify_url}" style="background:#000;color:#fff;padding:12px 24px;border-radius:4px;text-decoration:none;font-weight:500;">Verify Email</a>
                    </p>
                </div>
                """
            )
            flash("Welcome! Check your email to verify your account.", "success")
            return redirect("/dashboard")
    return render_template("register.html", err=err, name=name, email=email, form_ts=form_ts)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ── Password Reset ────────────────────────────────────────────────

@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def forgot_password():
    sent = False
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = get_user_by_email(email)
        if user:
            token = generate_token(user["id"], salt="password-reset")
            reset_url = request.host_url.rstrip("/") + f"/reset-password/{token}"
            send_email(
                to=user["email"],
                subject="Reset your password",
                html_body=f"""
                <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
                    <h2 style="color:#333;">Reset your password</h2>
                    <p style="color:#666;">Hi {user['name']},</p>
                    <p style="color:#666;">Click the button below to reset your password. This link expires in 1 hour.</p>
                    <p style="margin:24px 0;">
                        <a href="{reset_url}" style="background:#000;color:#fff;padding:12px 24px;border-radius:4px;text-decoration:none;font-weight:500;">Reset Password</a>
                    </p>
                    <p style="color:#999;font-size:13px;">If you didn't request this, you can safely ignore this email.</p>
                </div>
                """
            )
        sent = True
    return render_template("forgot_password.html", sent=sent)

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user_id = verify_token(token, salt="password-reset", max_age=3600)
    if not user_id:
        flash("This reset link has expired or is invalid.", "error")
        return redirect("/forgot-password")
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect("/forgot-password")
    err = None
    if request.method == "POST":
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        if len(password) < 8:
            err = "Password must be at least 8 characters."
        elif password != password_confirm:
            err = "Passwords do not match."
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(password), user_id))
            db.commit()
            flash("Password updated! You can now log in.", "success")
            return redirect("/login")
    return render_template("reset_password.html", err=err, token=token)

# ── Email Verification ────────────────────────────────────────────

@app.route("/verify-email/<token>")
def verify_email(token):
    user_id = verify_token(token, salt="email-verify", max_age=86400)
    if not user_id:
        flash("This verification link has expired or is invalid.", "error")
        return redirect("/login")
    db = get_db()
    db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash("Email verified!", "success")
    if session.get("user_id"):
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/resend-verification", methods=["POST"])
@login_required
@limiter.limit("2 per minute")
def resend_verification():
    user = get_user_by_id(session["user_id"])
    if user and not user["email_verified"]:
        token = generate_token(user["id"], salt="email-verify")
        verify_url = request.host_url.rstrip("/") + f"/verify-email/{token}"
        send_email(
            to=user["email"],
            subject="Verify your email",
            html_body=f"""
            <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
                <h2 style="color:#333;">Verify your email</h2>
                <p style="color:#666;">Hi {user['name']},</p>
                <p style="color:#666;">Click the button below to verify your email address.</p>
                <p style="margin:24px 0;">
                    <a href="{verify_url}" style="background:#000;color:#fff;padding:12px 24px;border-radius:4px;text-decoration:none;font-weight:500;">Verify Email</a>
                </p>
            </div>
            """
        )
        flash("Verification email sent! Check your inbox.", "success")
    return redirect("/dashboard")

# ── Dashboard ─────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    notes = db.execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY updated DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("dashboard.html", notes=notes)

# ── Account ───────────────────────────────────────────────────────

@app.route("/account")
@login_required
def account_page():
    user = get_user_by_id(session["user_id"])
    return render_template("account.html", user=user)

@app.route("/account/profile", methods=["POST"])
@login_required
def account_profile():
    db = get_db()
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    bio = request.form.get("bio", "").strip()
    location = request.form.get("location", "").strip()
    website = request.form.get("website", "").strip()
    existing = get_user_by_email(email)
    if existing and existing["id"] != session["user_id"]:
        flash("Email already in use.", "error")
        return redirect("/account")
    db.execute(
        "UPDATE users SET name=?, email=?, bio=?, location=?, website=? WHERE id=?",
        (name, email, bio, location, website, session["user_id"])
    )
    db.commit()
    session["user_name"] = name
    flash("Profile updated.", "success")
    return redirect("/account")

@app.route("/account/password", methods=["POST"])
@login_required
def account_password():
    db = get_db()
    user = get_user_by_id(session["user_id"])
    if not check_password_hash(user["password_hash"], request.form.get("current", "")):
        flash("Current password incorrect.", "error")
        return redirect("/account")
    new_pw = request.form.get("new", "")
    if len(new_pw) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect("/account")
    db.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (generate_password_hash(new_pw), session["user_id"])
    )
    db.commit()
    flash("Password updated.", "success")
    return redirect("/account")

@app.route("/account/avatar", methods=["POST"])
@login_required
def account_avatar():
    file = request.files.get("avatar")
    if not file or not file.filename:
        flash("No file selected.", "error")
        return redirect("/account")
    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("jpg", "jpeg", "png", "webp", "gif"):
        flash("Please upload a JPG, PNG, or WebP image.", "error")
        return redirect("/account")
    avatar_dir = UPLOAD_DIR / "avatars"
    avatar_dir.mkdir(exist_ok=True)
    avatar_name = f"avatar_{session['user_id']}.{ext}"
    file.save(str(avatar_dir / avatar_name))
    db = get_db()
    db.execute("UPDATE users SET avatar_path = ? WHERE id = ?",
               (f"avatars/{avatar_name}", session["user_id"]))
    db.commit()
    flash("Profile photo updated!", "success")
    return redirect("/account")

@app.route("/account/export")
@login_required
def account_export():
    """GDPR data export — download all your data as JSON."""
    db = get_db()
    uid = session["user_id"]
    user = get_user_by_id(uid)
    data = {
        "account": {
            "id": user["id"], "name": user["name"], "email": user["email"],
            "bio": user["bio"], "location": user["location"], "website": user["website"],
            "created": user["created"]
        },
        "notes": [dict(r) for r in db.execute(
            "SELECT id, title, body, created, updated FROM notes WHERE user_id = ?", (uid,)).fetchall()],
        "exported_at": datetime.now(timezone.utc).isoformat()
    }
    return json.dumps(data, indent=2), 200, {
        "Content-Type": "application/json",
        "Content-Disposition": f"attachment; filename=my-data-{uid}.json"
    }

@app.route("/account/delete", methods=["POST"])
@login_required
def account_delete():
    """GDPR right to deletion — delete account and all associated data."""
    uid = session["user_id"]
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    session.clear()
    flash("Your account and all data have been permanently deleted.", "success")
    return redirect("/")

# ── File Uploads ──────────────────────────────────────────────────

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(str(UPLOAD_DIR), filename)

# ══════════════════════════════════════════════════════════════════
#  EXAMPLE CRUD — Notes (delete this section when building your app)
# ══════════════════════════════════════════════════════════════════

@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title:
            flash("Title is required.", "error")
            return redirect("/notes/new")
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO notes (user_id, title, body, created, updated) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], title, body, now, now)
        )
        db.commit()
        flash("Note created.", "success")
        return redirect("/dashboard")
    return render_template("notes/new.html")

@app.route("/notes/<int:nid>")
@login_required
def view_note(nid):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                      (nid, session["user_id"])).fetchone()
    if not note:
        abort(404)
    return render_template("notes/view.html", note=note)

@app.route("/notes/<int:nid>/edit", methods=["GET", "POST"])
@login_required
def edit_note(nid):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                      (nid, session["user_id"])).fetchone()
    if not note:
        abort(404)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title:
            flash("Title is required.", "error")
            return redirect(f"/notes/{nid}/edit")
        db.execute(
            "UPDATE notes SET title=?, body=?, updated=? WHERE id=?",
            (title, body, datetime.now(timezone.utc).isoformat(), nid)
        )
        db.commit()
        flash("Note updated.", "success")
        return redirect(f"/notes/{nid}")
    return render_template("notes/edit.html", note=note)

@app.route("/notes/<int:nid>/delete", methods=["POST"])
@login_required
def delete_note(nid):
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ? AND user_id = ?",
               (nid, session["user_id"]))
    db.commit()
    flash("Note deleted.", "success")
    return redirect("/dashboard")

# ══════════════════════════════════════════════════════════════════
#  PLATFORM ADMIN — /admin/
# ══════════════════════════════════════════════════════════════════

@app.route("/admin")
@platform_admin_required
def admin_dashboard():
    db = get_db()
    tab = request.args.get("tab", "users")
    stats = {
        "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "new_users_7d": db.execute(
            "SELECT COUNT(*) FROM users WHERE created >= datetime('now', '-7 days')"
        ).fetchone()[0],
    }
    users = db.execute("""
        SELECT u.*
        FROM users u ORDER BY u.created DESC
    """).fetchall()

    activity = []
    for u in db.execute("SELECT id AS user_id, name AS user_name, created FROM users ORDER BY created DESC LIMIT 30").fetchall():
        activity.append({"type": "signup", "user_name": u["user_name"], "user_id": u["user_id"],
                         "detail": None, "created": u["created"]})
    activity.sort(key=lambda x: x["created"], reverse=True)
    activity = activity[:50]

    return render_template("admin.html", stats=stats, users=users, activity=activity, tab=tab)

@app.route("/admin/users/<int:uid>/toggle-admin", methods=["POST"])
@platform_admin_required
def admin_toggle_platform_admin(uid):
    if uid == session["user_id"]:
        flash("Cannot change your own admin status.", "error")
        return redirect("/admin?tab=users")
    db = get_db()
    user = get_user_by_id(uid)
    if not user:
        flash("User not found.", "error")
        return redirect("/admin?tab=users")
    db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (0 if user["is_admin"] else 1, uid))
    db.commit()
    flash(f"{'Removed' if user['is_admin'] else 'Granted'} admin for {user['name']}.", "success")
    return redirect("/admin?tab=users")

@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@platform_admin_required
def admin_delete_user(uid):
    if uid == session["user_id"]:
        flash("Cannot delete yourself.", "error")
        return redirect("/admin?tab=users")
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    flash("User deleted.", "success")
    return redirect("/admin?tab=users")

@app.route("/admin/users/<int:uid>/impersonate", methods=["POST"])
@platform_admin_required
def admin_impersonate(uid):
    user = get_user_by_id(uid)
    if not user:
        flash("User not found.", "error")
        return redirect("/admin?tab=users")
    session["impersonator_id"] = session["user_id"]
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    flash(f"Now viewing as {user['name']}. Use the banner to switch back.", "success")
    return redirect("/dashboard")

@app.route("/admin/stop-impersonating", methods=["POST"])
@login_required
def admin_stop_impersonating():
    real_id = session.pop("impersonator_id", None)
    if real_id:
        user = get_user_by_id(real_id)
        if user:
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            flash("Switched back to your admin account.", "success")
            return redirect("/admin")
    return redirect("/dashboard")

# ── Legal Pages ───────────────────────────────────────────────────

@app.route("/terms")
def terms_page():
    return render_template("legal.html", title="Terms of Service",
                           content="These terms of service govern your use of this platform. By using this platform, you agree to these terms. This is a placeholder — update with your actual terms before launch.")

@app.route("/privacy")
def privacy_page():
    return render_template("legal.html", title="Privacy Policy",
                           content="We collect your name, email, and content you create. We do not sell your data to third parties. Cookies are used for session management only. This is a placeholder — update with your actual privacy policy before launch.")

# ── Error Handlers ────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("errors/500.html"), 500

@app.errorhandler(429)
def rate_limited(e):
    return render_template("errors/429.html"), 429

# ── Boot ──────────────────────────────────────────────────────────

init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=DEFAULT_PORT)
