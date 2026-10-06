# Threat Model — Secure Notes API

## Assets
- User credentials (passwords)
- Session tokens (JWT)
- Private note contents
- Admin privileges
- Signing and encryption keys (.env)

## Actors
- Anonymous attacker on the network
- Authenticated malicious user (wants other users' data or admin rights)
- Attacker holding a stolen copy of the database

## Threats and planned controls
| # | Threat | Control |
|---|--------|---------|
| T1 | Brute force / credential stuffing on login | Rate limiting + account lockout |
| T2 | Stolen database reveals passwords | Argon2id password hashing |
| T3 | User enumeration via login errors | Identical error message for bad user / bad password |
| T4 | Token forgery or tampering | JWT signed with HMAC-SHA256, algorithm pinned, short expiry |
| T5 | Stolen token reused after logout | Token revocation list (jti) |
| T6 | IDOR: reading another user's note by changing its ID | Server-side ownership check on every note request |
| T7 | Privilege escalation (user sends "role": "admin") | Role read from database only; whitelist of accepted fields |
| T8 | SQL injection | Parameterized queries only |
| T9 | Stolen database reveals note contents | Note encryption at rest (AES via Fernet) |
| T10 | Secrets leaked in Git | .env excluded by .gitignore |
| T11 | Information leak via debug mode / stack traces | Debug off in production, generic error responses |
| T12 | Admin actions go unnoticed | Audit log of security events |
| T13 | Server header leaks software versions (Werkzeug/Python) | Remove or override the Server header (week 5) |

## Accepted risks
- /register returns "Username already taken", which reveals that a username exists. Accepted for usability; mitigated by rate limiting (week 5).
- Note titles are stored unencrypted to allow listing; only content is encrypted. Users should not store secrets in titles.
- FERNET_KEY and the Ed25519 private key are stored on the server's disk; production would use a secrets manager or HSM.
- The public key is served by the app itself; production would distribute it through a certificate (PKI).

## Week 4 — Test results
- Automated suite: 17 pytest cases, all pass (auth, access control, notes, signatures).
- SQL injection on login username: rejected, parameterized queries (T8 verified).
- Forged / expired / alg:none / tampered-payload tokens: all rejected 401 (T4 verified).
- IDOR on notes (read/update/delete/export by another user): all 404 (T6 verified).
- Vertical privilege escalation (user on admin routes): 403 (T7 verified).
- Mass assignment (role self-change, invalid role, injected fields): blocked 403/400, extra fields ignored (T7 verified).
- Brute force on /login: FINDING — 15 attempts, no rate limit, no lockout; real password accepted (T1 OPEN, fix in week 5).
- Captured via curl loop and Burp Suite Intruder; 14 login_failed events logged (detection works, T12).
