import requests
from flask import Flask, jsonify

app = Flask(__name__)
INVENTORY_API = "https://inventory.internal.example/api/items"


@app.route("/items")
def items():
    resp = requests.get(INVENTORY_API, timeout=5, verify=False)
    return jsonify(resp.json())


if __name__ == "__main__":
    app.run(port=8080, debug=True)
