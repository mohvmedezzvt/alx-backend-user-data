#!/usr/bin/env python3
"""
Main file
"""

from flask import Flask, jsonify, request, make_response, abort, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/')
def index() -> str:
    """Index"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """Users"""
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """Login"""
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        abort(400)

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = make_response(
            jsonify({"email": email, "message": "logged in"}))
        response.set_cookie("session_id", session_id)
        return response, 200
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """Logout"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect("/")
    else:
        return '', 403


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """Profile"""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email}), 200
    abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """Reset password"""
    email = request.form.get("email")
    reset_token = AUTH.get_reset_password_token(email)
    if reset_token:
        return jsonify({"email": email, "reset_token": reset_token}), 200
    abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
