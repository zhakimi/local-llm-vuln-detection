import base64
import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    blob = base64.b64decode(request.form["cart"])
    cart = pickle.loads(blob)
    return jsonify({"items": len(cart.get("items", []))})
