import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/diagnostics/ping")
def ping():
    target = request.args.get("target", "127.0.0.1")
    result = subprocess.run(f"ping -c 2 {target}", shell=True, capture_output=True, text=True)
    return result.stdout
