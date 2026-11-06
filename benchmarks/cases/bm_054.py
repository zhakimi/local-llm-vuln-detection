import os
import requests
from flask import Flask, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
INVENTORY_API = os.environ.get("INVENTORY_API", "https://inventory.internal.example/api/items")


@app.route("/items")
def items():
    resp = requests.get(INVENTORY_API, timeout=5)
    resp.raise_for_status()
    return jsonify(resp.json())


if __name__ == "__main__":
    app.run(port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")
