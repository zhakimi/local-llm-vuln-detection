import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/orders")
def list_orders():
    customer = request.args.get("customer", "")
    conn = sqlite3.connect("shop.db")
    rows = conn.execute(f"SELECT id, total FROM orders WHERE customer = '{customer}'").fetchall()
    conn.close()
    return jsonify(rows)
