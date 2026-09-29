import os
import sqlite3
import subprocess
from flask import Flask, request, render_template, redirect, make_response, g
from markupsafe import Markup

app = Flask(__name__)
DB_PATH = "/data/app.db"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    os.makedirs("/data", exist_ok=True)
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = db.cursor()

    cur.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT, body TEXT)")

    cur.execute("INSERT OR IGNORE INTO users(username,password) VALUES('alice','alice123')")
    cur.execute("INSERT OR IGNORE INTO users(username,password) VALUES('bob','bob123')")
    cur.execute("INSERT OR IGNORE INTO users(username,password) VALUES('admin','admin')")

    db.commit()
    db.close()

init_db()

def current_user():
    return request.cookies.get("user")

@app.route("/")
def home():
    return render_template("home.html", viewer=current_user())

# Reflected XSS
@app.route("/search")
def search():
    q = request.args.get("q", "")
    q_html = Markup(q)  # intentionally unsafe
    return render_template("search.html", viewer=current_user(), q=q_html)

# Stored XSS
@app.route("/notes", methods=["GET", "POST"])
def notes():
    viewer = current_user() or "anonymous"
    db = get_db()
    if request.method == "POST":
        body = request.form.get("body", "")
        db.execute("INSERT INTO notes(author, body) VALUES(?, ?)", (viewer, body))
        db.commit()
        return redirect("/notes")

    rows = db.execute("SELECT author, body FROM notes ORDER BY id DESC").fetchall()
    return render_template("notes.html", viewer=viewer, notes=rows)

# SQL Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", viewer=current_user(), error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    try:
        row = db.execute(sql).fetchone()
    except sqlite3.OperationalError as e:
        return render_template("login.html", viewer=current_user(), error=f"SQL error: {e}")

    if not row:
        return render_template("login.html", viewer=current_user(), error="Login failed")

    resp = make_response(redirect("/profile"))
    resp.set_cookie("user", row["username"])  # intentionally insecure
    return resp

@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie("user", "", expires=0)
    return resp

@app.route("/profile")
def profile():
    viewer = current_user()
    if not viewer:
        return redirect("/login")
    return render_template("profile.html", viewer=viewer)

# Command Injection
@app.route("/tools/ping")
def ping():
    viewer = current_user()
    if not viewer:
        return redirect("/login")

    host = request.args.get("host", "127.0.0.1")
    cmd = f"ping -c 1 {host}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=3)
        output = out.decode("utf-8", errors="replace")
    except Exception as e:
        output = f"Error running command: {e}"

    return render_template("ping.html", viewer=viewer, host=host, output=output)

@app.route("/health")
def health():
    return {"ok": True}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
