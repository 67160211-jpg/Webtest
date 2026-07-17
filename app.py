"""
Simple Flask website with:
  - User registration & login (hashed passwords, server-side sessions)
  - A protected home page
  - A public landing page
  - SQLite storage (auto-created on first run)

Only dependency is Flask itself — sessions and hashing use Flask's and
Werkzeug's built-ins, and storage uses Python's standard-library sqlite3,
so there's nothing extra to install.

Run it with:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000
"""

import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, redirect, url_for, flash, request, session, g
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-to-something-secret"  # use env var in production

DB_PATH = Path(__file__).parent / "site.db"


def get_db():
    """One SQLite connection per request, stashed on flask.g."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in to view that page.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    # Makes `user` available in every template automatically.
    return {"user": current_user()}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Public landing page."""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        db = get_db()

        if not username or not password:
            flash("Username and password are required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            flash("That username is already taken.", "error")
        else:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
            flash("Account created. You can log in now.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            next_page = request.args.get("next")
            return redirect(next_page or url_for("home"))

        flash("Incorrect username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You've been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/home")
@login_required
def home():
    """Protected page, only visible when logged in."""
    return render_template("home.html")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
else:
    # Also make sure the DB exists when imported (e.g. by a test client / WSGI server).
    init_db()
