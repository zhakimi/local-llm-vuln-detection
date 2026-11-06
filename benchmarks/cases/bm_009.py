import os
from flask import Flask, request, send_file

app = Flask(__name__)
REPORT_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    name = request.args.get("name", "")
    full_path = os.path.join(REPORT_DIR, name)
    return send_file(full_path)
