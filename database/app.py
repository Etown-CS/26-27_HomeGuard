"""
HomeGuard web app (Flask).

Serves the site and the login / sign-up API, backed by the Oracle database.

    pip install -r backend/requirements.txt
    python3 backend/test_connection.py     # check the database connection first
    python3 backend/app.py                 # then open http://localhost:5000

Routes
    GET  /                    dashboard (login required)
    GET  /login.html, /signup.html
    GET  /alerts.json         alert data (login required)
    GET  /backend/app.js, login.js, signup.js   the page scripts (nothing else in backend/ is served)
    POST /api/signup          {fname, lname, email, password}
    POST /api/login           {email, password}
    POST /api/logout
    GET  /api/me              current user, or 401
"""

import logging
import os
import re
import time
from datetime import timedelta
from pathlib import Path

import oracledb
from flask import Flask, abort, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

import db  # loads backend/.env

ROOT = Path(__file__).resolve().parent.parent      # the project folder (index.html lives here)

app = Flask(__name__, static_folder=None)           # static files are served only by the routes below
app.secret_key = os.getenv("SECRET_KEY", "").strip()
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing. Add it to backend/.env (see .env.example).")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=16 * 1024,                    # signup/login bodies are tiny
)
log = logging.getLogger("homeguard")

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MIN_PASSWORD, MAX_PASSWORD = 8, 128
# Compared against when the email is unknown, so response time doesn't reveal which emails exist
DUMMY_HASH = generate_password_hash("not-a-real-password")

# ---------------------------------------------------------------
# login throttle: 5 failed attempts per (ip, email) -> 15 minute lock
# (in memory, so it resets when the server restarts)
# ---------------------------------------------------------------
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60
_fails: dict = {}


def _key(email):
    return (request.remote_addr, email)


def _locked(email) -> bool:
    now = time.time()
    recent = [t for t in _fails.get(_key(email), []) if now - t < LOCK_SECONDS]
    _fails[_key(email)] = recent
    return len(recent) >= MAX_FAILS


# ---------------------------------------------------------------
# helpers
# ---------------------------------------------------------------
def error(message: str, status: int):
    return jsonify({"error": message}), status


def login_required_page(fn):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login.html")
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def login_required_api(fn):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return error("Log in to continue.", 401)
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@app.errorhandler(oracledb.Error)
def database_down(err):
    log.exception("Database error: %s", err)
    return error("The database is unavailable. Try again in a moment.", 503)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    if request.path.startswith("/api/") or request.path == "/alerts.json":
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------
# pages and static files (only these are served; backend/ and .env are never exposed)
# ---------------------------------------------------------------
@app.get("/")
@app.get("/index.html")
@login_required_page
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/login.html")
def login_page():
    return send_from_directory(ROOT, "login.html")


@app.get("/signup.html")
def signup_page():
    return send_from_directory(ROOT, "signup.html")


@app.get("/alerts.json")
@login_required_api
def alerts_json():
    return send_from_directory(ROOT, "alerts.json")

@app.get("/style/<path:name>")
def style_files(name):
    return send_from_directory(ROOT / "style", name)


# The two page scripts live in backend/ next to the server code. Only these exact files are
# served from that folder; everything else there (.env, wallet/, db.py, ...) stays private.
BACKEND_PUBLIC_FILES = {"app.js", "login.js", "signup.js"}


@app.get("/backend/<name>")
def backend_public_files(name):
    if name not in BACKEND_PUBLIC_FILES:
        abort(404)
    return send_from_directory(ROOT / "backend", name)


# ---------------------------------------------------------------
# API
# ---------------------------------------------------------------
@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("Send the sign-up form as JSON.", 400)

    fname = str(data.get("fname", "")).strip()
    lname = str(data.get("lname", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not fname or not lname or len(fname) > 50 or len(lname) > 50:
        return error("Enter your first and last name (50 characters or fewer each).", 400)
    if not EMAIL_RE.match(email) or len(email) > 255:
        return error("Enter a valid email address.", 400)
    if not (MIN_PASSWORD <= len(password) <= MAX_PASSWORD):
        return error(f"Use a password between {MIN_PASSWORD} and {MAX_PASSWORD} characters.", 400)

    try:
        db.create_user(fname, lname, email, generate_password_hash(password))
    except db.EmailTaken:
        return error("An account with that email already exists.", 409)
    return jsonify({"ok": True}), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("Send the login form as JSON.", 400)

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if _locked(email):
        return error("Too many failed attempts. Try again in 15 minutes.", 429)

    user = db.get_user_by_email(email)
    ok = check_password_hash(user["pwd_hash"] if user else DUMMY_HASH, password)
    if not (user and ok):
        _fails.setdefault(_key(email), []).append(time.time())
        return error("Incorrect email or password.", 401)

    _fails.pop(_key(email), None)
    session.clear()
    session["user_id"] = user["user_id"]
    session.permanent = True
    return jsonify({"ok": True, "fname": user["fname"]})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
@login_required_api
def me():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return error("Log in to continue.", 401)
    return jsonify({k: user[k] for k in ("user_id", "fname", "lname", "email")})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)