from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/welcome")
def welcome():
    name = request.args.get("name", "guest")
    return f"<html><body><h1>Welcome back, {escape(name)}!</h1></body></html>"
