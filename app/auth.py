import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, current_app, g, jsonify, request

from .audit import log_event
from .db import get_db
from .security import login_required
from .limiter import limiter

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
ph = PasswordHasher()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
DUMMY_HASH = ph.hash("dummy-password-for-timing")
MAX_FAILED_ATTEMPTS = 5


@bp.post("/register")
@limiter.limit("5 per minute")
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not USERNAME_RE.match(username):
        return jsonify(error="Username must be 3-32 letters, digits or _"), 400
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return jsonify(error="Password must be 12 to 128 characters"), 400

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, ph.hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username already taken"), 409

    log_event("register", cur.lastrowid)
    return jsonify(message="Account created"), 201


@bp.post("/login")
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Invalid credentials"), 401

    db = get_db()
    user = db.execute(
        "SELECT id, password_hash, is_locked, failed_attempts FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    try:
        ph.verify(user["password_hash"] if user else DUMMY_HASH, password)
    except VerifyMismatchError:
        if user is not None:
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_FAILED_ATTEMPTS:
                db.execute(
                    "UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE id = ?",
                    (attempts, user["id"]),
                )
                log_event("account_locked_bruteforce", user["id"])
            else:
                db.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (attempts, user["id"]),
                )
            db.commit()
            log_event("login_failed", user["id"])
        else:
            log_event("login_failed")
        return jsonify(error="Invalid credentials"), 401

    if user is None:
        log_event("login_failed")
        return jsonify(error="Invalid credentials"), 401

    if user["is_locked"]:
        log_event("login_blocked_locked", user["id"])
        return jsonify(error="Account locked, contact an administrator"), 403

    # Successful login: clear the failed-attempt counter
    db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
    db.commit()

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
    log_event("login_success", user["id"])
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
    log_event("logout", g.user["id"])
    return jsonify(message="Logged out"), 200
