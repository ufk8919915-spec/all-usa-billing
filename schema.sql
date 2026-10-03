-- All USA Billing production PostgreSQL security baseline.
-- Requires PostgreSQL 15+ and pgcrypto.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS clinics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES clinics(id),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('Administrator','Provider','Biller','Staff')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS patients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES clinics(id),
  first_name bytea NOT NULL,
  last_name bytea NOT NULL,
  dob bytea,
  sex bytea,
  phone bytea,
  email bytea,
  address bytea,
  payer bytea,
  member_id bytea,
  group_id bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  clinic_id uuid NOT NULL REFERENCES clinics(id),
  actor_user_id uuid REFERENCES app_users(id),
  action text NOT NULL,
  entity_type text NOT NULL,
  entity_id text NOT NULL,
  phi_access boolean NOT NULL DEFAULT false,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ip inet,
  user_agent text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash bytea,
  entry_hash bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_clinic_time_idx ON audit_log(clinic_id, occurred_at DESC);

ALTER TABLE patients ENABLE ROW LEVEL SECURITY;
ALTER TABLE patients FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

-- The application connection sets these transaction-local values after authentication.
CREATE POLICY patient_clinic_isolation ON patients
  USING (clinic_id = current_setting('app.clinic_id', true)::uuid)
  WITH CHECK (clinic_id = current_setting('app.clinic_id', true)::uuid);
CREATE POLICY audit_clinic_isolation ON audit_log
  USING (clinic_id = current_setting('app.clinic_id', true)::uuid)
  WITH CHECK (clinic_id = current_setting('app.clinic_id', true)::uuid);

-- Example AES-256 encryption helpers. Keep the encryption key outside PostgreSQL in a KMS/HSM-managed secret.
CREATE OR REPLACE FUNCTION encrypt_phi(plain text, key text)
RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT pgp_sym_encrypt(plain, key, 'cipher-algo=aes256') $$;
CREATE OR REPLACE FUNCTION decrypt_phi(cipher bytea, key text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT pgp_sym_decrypt(cipher, key) $$;

-- Tamper-evident, not magically tamper-proof: the application should HMAC the canonical row with a KMS/HSM-backed secret and prohibit UPDATE/DELETE for the audit writer role.
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;
