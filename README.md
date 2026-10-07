# Secure Notes API

A REST API demonstrating correct authentication, authorization and cryptography.
Users register, log in, and manage private notes; note contents are encrypted at
rest and can be exported as digitally signed documents. Built for a cybersecurity
module (Project 2: secure authentication & cryptography).

## Security features

| Area | Implementation |
|------|----------------|
| Password storage | Argon2id (per-password salt, memory-hard) |
| Sessions | JWT signed with HMAC-SHA256, 15 min expiry, server-side revocation on logout |
| Authorization | Role reloaded from DB per request; ownership enforced in SQL |
| Brute force defense | Account lockout after 5 failed logins + IP rate limiting |
| Encryption at rest | Fernet (AES-128-CBC + HMAC) for note contents |
| Digital signatures | Ed25519 signed note exports, verifiable offline with the public key |
| Audit trail | Security events logged with user, action, IP and timestamp |
| Hardening | Security headers, generic JSON errors, debug off in production |

## Requirements

- Python 3.12+
- Linux/macOS (developed on Pop!_OS)
- OpenSSL (for generating the signing key pair)

## Setup

```bash
# 1. Clone and enter the project
git clone git@github.com:Guizaa22/secure-auth-app.git
cd secure-auth-app

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate secrets (never commit these)
echo "JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
echo "FERNET_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" >> .env

# 5. Generate the Ed25519 signing key pair
mkdir -p keys
openssl genpkey -algorithm ed25519 -out keys/signing_key.pem
openssl pkey -in keys/signing_key.pem -pubout -out keys/signing_pub.pem
chmod 600 keys/signing_key.pem

# 6. Create the database
sqlite3 app.db < app/schema.sql
```

## Running

Development server:

```bash
python run.py
```

Production server (also strips the dev-server banner; debug off):

```bash
gunicorn -w 2 -b 127.0.0.1:5000 "run:app"
```

The API listens on `http://127.0.0.1:5000`. Check it with:

```bash
curl -sS http://127.0.0.1:5000/api/health
```

## Creating the first admin

Accounts always register as regular users. The first admin is promoted
out-of-band (requires server access), so the API itself exposes no privilege
escalation path:

```bash
curl -sS -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin1","password":"a-strong-admin-password"}'

sqlite3 app.db "UPDATE users SET role='admin' WHERE username='admin1';"
```

## API endpoints

| Method | Route | Access | Description |
|--------|-------|--------|-------------|
| GET | `/api/health` | Public | Health check |
| GET | `/api/public-key` | Public | Server's Ed25519 public key |
| POST | `/api/auth/register` | Public | Create account (always role `user`) |
| POST | `/api/auth/login` | Public | Returns a JWT |
| POST | `/api/auth/logout` | User | Revokes the current token |
| GET | `/api/me` | User | Own profile |
| GET | `/api/notes` | User | List own notes |
| POST | `/api/notes` | User | Create a note |
| GET | `/api/notes/<id>` | Owner | Read and decrypt a note |
| PUT | `/api/notes/<id>` | Owner | Update a note |
| DELETE | `/api/notes/<id>` | Owner | Delete a note |
| GET | `/api/notes/<id>/export` | Owner | Signed, verifiable export |
| GET | `/api/admin/users` | Admin | List users |
| POST | `/api/admin/users/<id>/lock` | Admin | Lock an account |
| POST | `/api/admin/users/<id>/unlock` | Admin | Unlock an account |
| PUT | `/api/admin/users/<id>/role` | Admin | Change a user's role |
| GET | `/api/admin/audit` | Admin | Recent security events |

## Testing

```bash
pytest -v                               # run the suite
pytest --cov=app --cov-report=term-missing   # with coverage
```

## Verifying a signed export

Export a note, download the public key, and verify offline with no secret:

```bash
curl -sS http://127.0.0.1:5000/api/notes/1/export \
  -H "Authorization: Bearer $TOKEN" > export.json
curl -sS http://127.0.0.1:5000/api/public-key \
  | python -c "import sys,json; print(json.load(sys.stdin)['public_key'], end='')" > server_pub.pem
python tools/verify_export.py export.json server_pub.pem
```

## Project structure

secure-auth-app/
├── run.py # Entry point
├── requirements.txt
├── pytest.ini
├── app/
│ ├── init.py # App factory, config, blueprints, hardening
│ ├── db.py # DB connection, schema init
│ ├── schema.sql # Database schema
│ ├── auth.py # register, login, logout, lockout
│ ├── security.py # @login_required, @admin_required
│ ├── users.py # /api/me
│ ├── admin.py # Admin routes
│ ├── notes.py # Notes CRUD + signed export
│ ├── crypto.py # Fernet encryption
│ ├── signing.py # Ed25519 signing
│ ├── audit.py # Security event logging
│ ├── limiter.py # Rate limiter
│ └── middleware.py # Server header control
├── tests/ # pytest suite
├── tools/
│ └── verify_export.py # Offline signature verification
├── docs/
│ └── threat-model.md
└── keys/
└── signing_pub.pem # Public key (private key is gitignored)


## Security notes

- `.env`, `app.db` and the private signing key are never committed.
- JWTs are signed, not encrypted: the payload is readable but tamper-evident.
- Admins cannot read user notes (least privilege).
- The `Server` header is best removed by a reverse proxy in production; see `docs/threat-model.md`.

## License

Educational project.
