import os
from flask import Flask, jsonify
from dotenv import load_dotenv


def create_app():
    load_dotenv()
    app = Flask(__name__)

    # Fails immediately if the secret is missing: never run with a default key
    app.config["JWT_SECRET"] = os.environ["JWT_SECRET"]
    app.config["DATABASE"] = os.path.abspath(
        os.path.join(app.root_path, os.pardir, "app.db")
    )

    from .db import close_db
    app.teardown_appcontext(close_db)

    from .auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from .users import bp as users_bp
    app.register_blueprint(users_bp)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    return app
