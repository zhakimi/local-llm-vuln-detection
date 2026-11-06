import ast
from flask import Flask, request, jsonify, abort

app = Flask(__name__)


@app.route("/settings/parse")
def parse_setting():
    raw = request.args.get("value", "0")
    try:
        value = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        abort(400)
    if not isinstance(value, (int, float, str, bool)):
        abort(400)
    return jsonify({"value": value})
