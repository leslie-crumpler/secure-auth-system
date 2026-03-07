"""
app.py - Secure Authentication System
Demonstrates: password hashing, login protection, brute-force lockout, audit logging
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, session
from database import init_db
from models import UserModel
from auth import (
    hash_password, verify_password, validate_registration,
    is_locked_out, record_failed_attempt, reset_attempts,
    log_login_success, log_login_failure, log_logout
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-production")


def get_ip():
    return request.remote_addr or "unknown"


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    ok, msg = validate_registration(username, password)
    if not ok:
        return jsonify({"error": msg}), 400

    if UserModel.find_by_username(username):
        return jsonify({"error": "Username already taken."}), 409

    UserModel.create(username, hash_password(password))
    return jsonify({"message": "Account created. You can now /login."}), 201


@app.route("/login", methods=["POST"])
def login():
    ip = get_ip()

    if is_locked_out(ip):
        return jsonify({"error": "Too many failed attempts. Try again in 5 minutes."}), 429

    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = UserModel.find_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        record_failed_attempt(ip)
        log_login_failure(username, ip)
        return jsonify({"error": "Invalid credentials."}), 401

    reset_attempts(ip)
    log_login_success(username, ip)
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"message": f"Welcome, {username}!"})


@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username", "unknown")
    log_logout(username, get_ip())
    session.clear()
    return jsonify({"message": "Logged out."})


@app.route("/profile", methods=["GET"])
def profile():
    if "user_id" not in session:
        return jsonify({"error": "Authentication required."}), 401
    return jsonify({"username": session["username"], "user_id": session["user_id"]})


if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5002)
