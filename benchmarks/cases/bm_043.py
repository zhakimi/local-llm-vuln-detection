import os
import jwt
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
SECRET = os.environ["JWT_SECRET"]


@app.route("/admin/stats")
def admin_stats():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_signature": False})
    if claims.get("role") != "admin":
        abort(403)
    return jsonify({"users": 1520})
