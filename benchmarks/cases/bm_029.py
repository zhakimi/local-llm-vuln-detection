from flask import Flask, request

app = Flask(__name__)


@app.route("/welcome")
def welcome():
    name = request.args.get("name", "guest")
    return f"<html><body><h1>Welcome back, {name}!</h1></body></html>"
