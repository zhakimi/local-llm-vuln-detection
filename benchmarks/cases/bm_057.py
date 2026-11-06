import ipaddress
import subprocess
from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/diagnostics/ping")
def ping():
    target = request.args.get("target", "127.0.0.1")
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        abort(400)
    result = subprocess.run(["ping", "-c", "2", str(addr)], capture_output=True, text=True)
    return result.stdout
