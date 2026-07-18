from __future__ import annotations

import csv
import io
import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "delspark.db"
ROLES = ("super_admin", "parking_admin", "security_officer", "vehicle_owner")

app = Flask(__name__, static_folder=None)
app.config.update(SECRET_KEY=os.environ.get("DELSPARK_SECRET_KEY", "change-this-secret-before-production"), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def audit(action: str, detail: str, user_id: int | None = None):
    with db() as connection:
        connection.execute("INSERT INTO activity_logs (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)", (user_id or session.get("user_id"), action, detail, now()))


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def current_user():
    if not session.get("user_id"):
        return None
    with db() as connection:
        return connection.execute("SELECT id, name, email, role, faculty_scope, active FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def require_roles(*roles):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify(error="Authentication required"), 401
            if roles and user["role"] not in roles:
                return jsonify(error="You do not have permission for this action"), 403
            return fn(*args, **kwargs)
        return wrapped
    return decorate


def row_dict(row):
    return dict(row) if row else None


def initialise_database():
    with db() as connection:
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('super_admin','parking_admin','security_officer','vehicle_owner')),
          faculty_scope TEXT NOT NULL DEFAULT 'All faculties',
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vehicles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          plate TEXT NOT NULL UNIQUE,
          model TEXT NOT NULL,
          owner_name TEXT NOT NULL,
          faculty TEXT NOT NULL,
          category TEXT NOT NULL DEFAULT 'Staff',
          colour TEXT,
          owner_user_id INTEGER REFERENCES users(id),
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS parking_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          vehicle_id INTEGER NOT NULL REFERENCES vehicles(id),
          zone TEXT,
          space_code TEXT,
          check_in_at TEXT NOT NULL,
          check_out_at TEXT,
          recorded_by INTEGER REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER REFERENCES users(id),
          action TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        if not connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            seed_users = [
                ("Admin Officer", "admin@delsu.edu.ng", "Admin@123", "super_admin", "All faculties"),
                ("Mrs. E. Ukpabi", "ukpabi@delsu.edu.ng", "Parking@123", "parking_admin", "Faculty of Science"),
                ("Mr. O. Eze", "eze@delsu.edu.ng", "Security@123", "security_officer", "Management Science"),
                ("Chisom Nwosu", "chisom@delsu.edu.ng", "Owner@123", "vehicle_owner", "Management Science"),
            ]
            for name, email, password, role, scope in seed_users:
                connection.execute("INSERT INTO users (name,email,password_hash,role,faculty_scope,created_at) VALUES (?,?,?,?,?,?)", (name, email, generate_password_hash(password), role, scope, now()))
            connection.executemany("INSERT INTO vehicles (plate,model,owner_name,faculty,category,colour,created_at) VALUES (?,?,?,?,?,?,?)", [
                ("DEL 427 AA", "Toyota Camry", "Dr. E. Okafor", "Faculty of Science", "Staff", "Black", now()),
                ("ABK 981 KD", "Honda Accord", "Chisom Nwosu", "Management Science", "Staff", "Silver", now()),
                ("DEL 112 BR", "Lexus RX 350", "Prof. T. Igho", "Faculty of Science", "Staff", "White", now()),
            ])
        owner = connection.execute("SELECT id FROM users WHERE email = 'chisom@delsu.edu.ng'").fetchone()
        if owner:
            connection.execute("UPDATE vehicles SET owner_user_id = ? WHERE plate = 'ABK 981 KD' AND owner_user_id IS NULL", (owner["id"],))


initialise_database()


@app.get("/")
def home():
    return send_from_directory(ROOT, "index.html") if current_user() else redirect(url_for("login_page"))


@app.get("/login")
def login_page():
    return redirect(url_for("home")) if current_user() else send_from_directory(ROOT, "login.html")


@app.get("/signup")
def signup_page():
    return redirect(url_for("home")) if current_user() else send_from_directory(ROOT, "signup.html")


@app.get("/<path:filename>")
def static_files(filename):
    if filename in {"app.py", "delspark.db"}:
        return "Not found", 404
    return send_from_directory(ROOT, filename)


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    with db() as connection:
        user = connection.execute("SELECT * FROM users WHERE email = ? AND active = 1", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Invalid email or password"), 401
    session.clear()
    session["user_id"] = user["id"]
    audit("User login", f"{user['name']} signed in", user["id"])
    return jsonify(user=row_dict(user))


@app.post("/api/auth/signup")
def signup():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    if not name or "@" not in email or len(password) < 8:
        return jsonify(error="Enter your name, a valid email, and a password with at least 8 characters"), 422
    try:
        with db() as connection:
            cursor = connection.execute("INSERT INTO users (name,email,password_hash,role,faculty_scope,created_at) VALUES (?,?,?,?,?,?)", (name, email, generate_password_hash(password), "vehicle_owner", "Vehicle Owner", now()))
            user_id = cursor.lastrowid
        audit("Vehicle Owner account created", email, user_id)
        session.clear()
        session["user_id"] = user_id
        return jsonify(ok=True), 201
    except sqlite3.IntegrityError:
        return jsonify(error="An account with that email already exists"), 409


@app.post("/api/auth/logout")
@require_roles()
def logout():
    audit("User logout", "User signed out")
    session.clear()
    return jsonify(ok=True)


@app.get("/api/session")
@require_roles()
def session_info():
    return jsonify(user=row_dict(current_user()), roles=ROLES)


@app.get("/api/vehicles")
@require_roles()
def list_vehicles():
    user = current_user()
    with db() as connection:
        query = "SELECT * FROM vehicles WHERE active = 1"
        values = []
        if user["role"] == "vehicle_owner":
            query += " AND owner_user_id = ?"
            values.append(user["id"])
        query += " ORDER BY id DESC"
        return jsonify(vehicles=[row_dict(row) for row in connection.execute(query, values)])


@app.post("/api/vehicles")
@require_roles("super_admin", "parking_admin")
def create_vehicle():
    data = request.get_json(silent=True) or {}
    required = ("plate", "model", "owner_name", "faculty")
    if any(not str(data.get(field, "")).strip() for field in required):
        return jsonify(error="Plate, model, owner name and faculty are required"), 422
    try:
        with db() as connection:
            connection.execute("INSERT INTO vehicles (plate,model,owner_name,faculty,category,colour,created_at) VALUES (?,?,?,?,?,?,?)", (data["plate"].upper().strip(), data["model"].strip(), data["owner_name"].strip(), data["faculty"], data.get("category", "Staff"), data.get("colour", "").strip(), now()))
        audit("Vehicle registered", data["plate"].upper().strip())
        return jsonify(ok=True), 201
    except sqlite3.IntegrityError:
        return jsonify(error="A vehicle with that plate number already exists"), 409


@app.post("/api/gate/<operation>")
@require_roles("super_admin", "parking_admin", "security_officer")
def gate_operation(operation):
    if operation not in {"checkin", "checkout"}:
        return jsonify(error="Unknown operation"), 404
    data = request.get_json(silent=True) or {}
    plate = str(data.get("plate", "")).upper().strip()
    with db() as connection:
        vehicle = connection.execute("SELECT id FROM vehicles WHERE plate = ? AND active = 1", (plate,)).fetchone()
        if not vehicle:
            return jsonify(error="Registered vehicle not found"), 404
        if operation == "checkin":
            connection.execute("INSERT INTO parking_logs (vehicle_id,zone,space_code,check_in_at,recorded_by) VALUES (?,?,?,?,?)", (vehicle["id"], data.get("zone", "Campus"), data.get("space_code", "Unassigned"), now(), session["user_id"]))
        else:
            log = connection.execute("SELECT id FROM parking_logs WHERE vehicle_id = ? AND check_out_at IS NULL ORDER BY id DESC LIMIT 1", (vehicle["id"],)).fetchone()
            if not log:
                return jsonify(error="This vehicle is not currently checked in"), 409
            connection.execute("UPDATE parking_logs SET check_out_at = ? WHERE id = ?", (now(), log["id"]))
    audit(f"Vehicle {operation}", plate)
    return jsonify(ok=True)


@app.get("/api/users")
@require_roles("super_admin")
def list_users():
    with db() as connection:
        users = connection.execute("SELECT id,name,email,role,faculty_scope,active,created_at FROM users ORDER BY id").fetchall()
    return jsonify(users=[row_dict(user) for user in users])


@app.post("/api/users")
@require_roles("super_admin")
def create_user():
    data = request.get_json(silent=True) or {}
    if data.get("role") not in ROLES or not data.get("name") or not data.get("email") or not data.get("password"):
        return jsonify(error="Name, email, password and a valid role are required"), 422
    try:
        with db() as connection:
            connection.execute("INSERT INTO users (name,email,password_hash,role,faculty_scope,created_at) VALUES (?,?,?,?,?,?)", (data["name"].strip(), data["email"].strip().lower(), generate_password_hash(data["password"]), data["role"], data.get("faculty_scope", "All faculties"), now()))
        audit("User created", data["email"])
        return jsonify(ok=True), 201
    except sqlite3.IntegrityError:
        return jsonify(error="An account with that email already exists"), 409


@app.get("/api/reports/<report_name>")
@require_roles("super_admin", "parking_admin")
def report(report_name):
    if report_name == "vehicles":
        headers, query = ["Plate", "Vehicle", "Owner", "Faculty", "Category"], "SELECT plate,model,owner_name,faculty,category FROM vehicles ORDER BY plate"
    elif report_name == "occupancy":
        headers, query = ["Zone", "Occupied"], "SELECT COALESCE(zone,'Campus'), COUNT(*) FROM parking_logs WHERE check_out_at IS NULL GROUP BY zone"
    else:
        headers, query = ["Check in", "Check out", "Vehicle", "Zone", "Space"], "SELECT p.check_in_at,p.check_out_at,v.plate,p.zone,p.space_code FROM parking_logs p JOIN vehicles v ON v.id=p.vehicle_id ORDER BY p.id DESC"
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(headers)
    with db() as connection:
        writer.writerows(connection.execute(query).fetchall())
    return Response(stream.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=delspark-{report_name}.csv"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
