from pathlib import Path
from flask import Flask, request, send_file, abort

app = Flask(__name__)
REPORT_DIR = Path("/srv/app/reports").resolve()


@app.route("/reports/download")
def download_report():
    name = request.args.get("name", "")
    candidate = (REPORT_DIR / name).resolve()
    if not candidate.is_relative_to(REPORT_DIR) or not candidate.is_file():
        abort(404)
    return send_file(candidate)
