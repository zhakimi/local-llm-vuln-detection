from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/calculate")
def calculate():
    expression = request.args.get("expr", "0")
    value = eval(expression)
    return jsonify({"value": value})
