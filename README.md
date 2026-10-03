# All USA Billing v5 — Security Architecture

This build adds a security layer for a production-oriented deployment:

- PHI fields are encrypted at rest with AES-256-GCM at the application layer. Set `APP_ENCRYPTION_KEY` in production; never commit it.
- HTTPS can be enforced with TLS 1.3 only using `TLS_CERT` and `TLS_KEY`.
- Authentication uses an HttpOnly, SameSite=Strict signed session cookie. Passwords are upgraded to scrypt when a legacy development account logs in.
- Every clinic-scoped record carries `clinicId`; the production PostgreSQL design in `schema.sql` enables and forces RLS using `app.clinic_id`.
- PHI views/changes generate a hash-chained HMAC audit record with actor, timestamp, IP, user agent, action and clinic.
- Administrator-only `/api/audit` exposes audit entries.
- `/api/security/status` reports configuration state.

## Important

HIPAA is a regulatory/security program, not a single software switch. This package is a technical foundation and is **not by itself a HIPAA compliance certification**. Production use requires a complete risk analysis, policies/procedures, access control, workforce training, incident response, backups/disaster recovery, vulnerability management, physical safeguards, vendor/BAA review, and independent security assessment.

## Development

`npm start` runs HTTP for local development. Do not use real PHI in local development.

## Production transport

Set `TLS_CERT` and `TLS_KEY` and use `PORT=3443`; the server restricts Node's TLS protocol to TLS 1.3. Put a properly configured reverse proxy/load balancer in front where appropriate and ensure internal hops are encrypted as well.

## Database

For production, use PostgreSQL rather than the JSON development store. Apply `schema.sql`, use a dedicated least-privilege application role, set `app.clinic_id` per authenticated transaction, and keep the encryption/HMAC keys in a KMS/HSM or equivalent secrets manager.
