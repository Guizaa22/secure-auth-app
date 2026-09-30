import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, current_app, g, jsonify, request

from .db import get_db
from .security import login_required

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
ph = PasswordHasher()  # Argon2id with safe defaults

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
# Used when the username doesn't exist, so the response takes the same time
DUMMY_HASH = ph.hash("dummy-password-for-timing")


@bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    # Whitelist: only these two fields are read. A "role" field is ignored (T7).
    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not USERNAME_RE.match(username):
        return jsonify(error="Username must be 3-32 letters, digits or _"), 400
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return jsonify(error="Password must be 12 to 128 characters"), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, ph.hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username already taken"), 409

    return jsonify(message="Account created"), 201


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Invalid credentials"), 401

    user = get_db().execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    try:
        ph.verify(user["password_hash"] if user else DUMMY_HASH, password)
    except VerifyMismatchError:
        return jsonify(error="Invalid credentials"), 401
    if user is None:
        return jsonify(error="Invalid credentials"), 401

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": str(user["id"]),
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        current_app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    return jsonify(access_token=token), 200


@bp.post("/logout")
@login_required
def logout():
    expires = datetime.fromtimestamp(g.claims["exp"], timezone.utc).isoformat()
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
        (g.claims["jti"], expires),
    )
    db.commit()
    return jsonify(message="Logged out"), 200
