import json
from flask import Flask, request, jsonify, abort

app = Flask(__name__)


@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    try:
        cart = json.loads(request.form["cart"])
    except (KeyError, json.JSONDecodeError):
        abort(400)
    if not isinstance(cart, dict):
        abort(400)
    return jsonify({"items": len(cart.get("items", []))})
