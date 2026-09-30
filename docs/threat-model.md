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
