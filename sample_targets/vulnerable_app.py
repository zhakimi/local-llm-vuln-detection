"""
!!! INTENTIONALLY VULNERABLE CODE — FOR SCANNER TESTING ONLY. DO NOT DEPLOY. !!!

A small Flask inventory service used as a scan target for amd-vuln-scanner.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

SECRET_KEY = "pr0d-s3cr3t-k3y-do-not-share-2024"
DB_PASSWORD = "Admin@123"
PAYMENTS_API_KEY = "pk_inventory_9f8e7d6c5b4a3210fedcba9876543210"
app.config["SECRET_KEY"] = SECRET_KEY

UPLOAD_DIR = "/var/app/uploads"
DB_PATH = "inventory.db"


def get_db():
    return sqlite3.connect(DB_PATH)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def generate_reset_token():
    return str(random.randint(100000, 999999))


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT id, role FROM users WHERE username = '" + username + \
            "' AND password_hash = '" + hash_password(password) + "'"
    cur.execute(query)
    row = cur.fetchone()
    if row:
        return jsonify({"id": row[0], "role": row[1]})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/items")
def search_items():
    name = request.args.get("name", "")
    conn = get_db()
    rows = conn.execute(f"SELECT * FROM items WHERE name LIKE '%{name}%'").fetchall()
    return jsonify(rows)


@app.route("/calc")
def calculate():
    expr = request.args.get("expr", "1+1")
    result = eval(expr)
    return jsonify({"result": result})


@app.route("/session/restore", methods=["POST"])
def restore_session():
    blob = request.get_data()
    session = pickle.loads(blob)
    return jsonify({"user": session.get("user")})


@app.route("/config/import", methods=["POST"])
def import_config():
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
    return jsonify(cfg)


@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join(UPLOAD_DIR, filename)
    return send_file(path)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/charge", methods=["POST"])
def charge():
    headers = {"Authorization": "Bearer " + PAYMENTS_API_KEY}
    return jsonify({"status": "queued", "auth": bool(headers)})


@app.route("/reset", methods=["POST"])
def reset_password():
    token = generate_reset_token()
    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
