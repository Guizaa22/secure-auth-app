#!/usr/bin/env sh
set -e
export PYTHONPATH=/app

DATA=/app/data
export DATABASE="$DATA/app.db"
export SIGNING_KEY_PATH="$DATA/keys/signing_key.pem"
export SIGNING_PUBKEY_PATH="$DATA/keys/signing_pub.pem"
mkdir -p "$DATA/keys"

# Secrets (persisted in the data volume, generated once)
if [ ! -f "$DATA/.env" ]; then
  echo ">> Generating application secrets..."
  echo "JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')" >  "$DATA/.env"
  echo "FERNET_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" >> "$DATA/.env"
fi
set -a; . "$DATA/.env"; set +a

# Ed25519 signing key pair (generated once)
if [ ! -f "$SIGNING_KEY_PATH" ]; then
  echo ">> Generating Ed25519 signing keys..."
  openssl genpkey -algorithm ed25519 -out "$SIGNING_KEY_PATH"
  openssl pkey -in "$SIGNING_KEY_PATH" -pubout -out "$SIGNING_PUBKEY_PATH"
  chmod 600 "$SIGNING_KEY_PATH"
fi

# Database + demo users (generated once)
if [ ! -f "$DATABASE" ]; then
  echo ">> Initializing database..."
  python scripts/init_db.py
  python scripts/seed.py || true
fi

exec "$@"
