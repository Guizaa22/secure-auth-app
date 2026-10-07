import os

from dotenv import load_dotenv
from flask import Flask, jsonify

from .limiter import limiter
from .middleware import ServerHeaderMiddleware


def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__)
    root = os.path.abspath(os.path.join(app.root_path, os.pardir))

    app.config["JWT_SECRET"] = os.environ["JWT_SECRET"]
    app.config["FERNET_KEY"] = os.environ["FERNET_KEY"]
    app.config["DATABASE"] = os.path.join(root, "app.db")
    app.config["SIGNING_KEY_PATH"] = os.path.join(root, "keys", "signing_key.pem")
    app.config["SIGNING_PUBKEY_PATH"] = os.path.join(root, "keys", "signing_pub.pem")
    app.config["RATELIMIT_ENABLED"] = True
    for path in (app.config["SIGNING_KEY_PATH"], app.config["SIGNING_PUBKEY_PATH"]):
        if not os.path.isfile(path):
            raise RuntimeError(f"Missing signing key file: {path}")

    if test_config:
        app.config.update(test_config)

    from .db import close_db, init_db
    if app.config.get("INIT_DB"):
        with app.app_context():
            init_db()

    app.teardown_appcontext(close_db)
    limiter.init_app(app)

    from .admin import bp as admin_bp
    from .auth import bp as auth_bp
    from .notes import bp as notes_bp
    from .users import bp as users_bp
    for blueprint in (auth_bp, users_bp, admin_bp, notes_bp):
        app.register_blueprint(blueprint)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.get("/api/public-key")
    def public_key():
        from .signing import public_key_pem
        return jsonify(algorithm="Ed25519", public_key=public_key_pem())

    @app.errorhandler(404)
    def not_found(e):
        return jsonify(error="Not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify(error="Method not allowed"), 405

    @app.errorhandler(429)
    def too_many(e):
        return jsonify(error="Too many requests, slow down"), 429

    @app.errorhandler(500)
    def server_error(e):
        return jsonify(error="Internal server error"), 500

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.wsgi_app = ServerHeaderMiddleware(app.wsgi_app)
    return app
