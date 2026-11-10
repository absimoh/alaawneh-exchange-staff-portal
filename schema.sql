CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text NOT NULL UNIQUE,
 password_hash text NOT NULL, name text NOT NULL, role text NOT NULL CHECK(role IN ('manager','employee')),
 title text NOT NULL DEFAULT 'موظف', department text NOT NULL DEFAULT 'خدمة العملاء',
 approved boolean NOT NULL DEFAULT false, disabled boolean NOT NULL DEFAULT false, salary numeric(12,2) NOT NULL DEFAULT 0 CHECK(salary >= 0),
 rating integer NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 100),
 status text NOT NULL DEFAULT 'بانتظار التفعيل', created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS attendance (
 id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), work_date date NOT NULL DEFAULT CURRENT_DATE,
 clock_in timestamptz, clock_out timestamptz, last_seen timestamptz, UNIQUE(user_id, work_date)
);
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS last_seen timestamptz;
CREATE TABLE IF NOT EXISTS attendance_sessions (
 id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), work_date date NOT NULL DEFAULT CURRENT_DATE,
 clock_in timestamptz NOT NULL DEFAULT now(), clock_out timestamptz, last_seen timestamptz NOT NULL DEFAULT now()
);
INSERT INTO attendance_sessions(user_id,work_date,clock_in,clock_out,last_seen)
 SELECT a.user_id,a.work_date,a.clock_in,a.clock_out,COALESCE(a.last_seen,now()) FROM attendance a
 WHERE a.clock_in IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM attendance_sessions s WHERE s.user_id=a.user_id AND s.work_date=a.work_date AND s.clock_in=a.clock_in
 );
CREATE UNIQUE INDEX IF NOT EXISTS attendance_sessions_active_user_idx ON attendance_sessions(user_id,work_date) WHERE clock_out IS NULL;
CREATE INDEX IF NOT EXISTS attendance_sessions_user_day_idx ON attendance_sessions(user_id,work_date,clock_in DESC);
CREATE INDEX IF NOT EXISTS attendance_sessions_last_seen_idx ON attendance_sessions(last_seen) WHERE clock_out IS NULL;
CREATE TABLE IF NOT EXISTS daily_metrics (
 user_id uuid NOT NULL REFERENCES users(id), work_date date NOT NULL DEFAULT CURRENT_DATE,
 transfers integer NOT NULL DEFAULT 0 CHECK(transfers>=0), exchange integer NOT NULL DEFAULT 0 CHECK(exchange>=0),
 wallets integer NOT NULL DEFAULT 0 CHECK(wallets>=0), PRIMARY KEY(user_id,work_date)
);
CREATE TABLE IF NOT EXISTS tasks (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), employee_id uuid NOT NULL REFERENCES users(id),
 title text NOT NULL, description text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed')),
 file_label text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
 file_data bytea, file_mime text, file_name text NOT NULL DEFAULT ''
);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS file_data bytea;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS file_mime text;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS file_name text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS notifications (
 id bigserial PRIMARY KEY, employee_id uuid NOT NULL REFERENCES users(id), task_id uuid REFERENCES tasks(id),
 message text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), read_at timestamptz
);
CREATE TABLE IF NOT EXISTS audit_log (
 id bigserial PRIMARY KEY, actor_id uuid REFERENCES users(id), action text NOT NULL,
 target_id uuid, details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS operations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), employee_id uuid NOT NULL REFERENCES users(id),
 operation_type text NOT NULL CHECK(operation_type IN ('تحويل أموال','تصريف عملات','محافظ إلكترونية')),
 amount numeric(14,2) NOT NULL CHECK(amount > 0), currency_from text NOT NULL CHECK(currency_from IN ('JOD','USD','SAR','AED','EUR')),
 result_amount numeric(14,2) NOT NULL CHECK(result_amount >= 0), currency_to text NOT NULL CHECK(currency_to IN ('JOD','USD','SAR','AED','EUR')),
 exchange_rate numeric(24,12) NOT NULL DEFAULT 1 CHECK(exchange_rate > 0), reference_code text NOT NULL DEFAULT '', note text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE operations ADD COLUMN IF NOT EXISTS exchange_rate numeric(24,12) NOT NULL DEFAULT 1 CHECK(exchange_rate > 0);
UPDATE operations SET exchange_rate=result_amount/NULLIF(amount,0) WHERE amount>0 AND result_amount>0 AND exchange_rate=1;
CREATE INDEX IF NOT EXISTS attendance_date_idx ON attendance(work_date);
CREATE INDEX IF NOT EXISTS tasks_employee_idx ON tasks(employee_id, status);
CREATE INDEX IF NOT EXISTS operations_employee_idx ON operations(employee_id, created_at DESC);
CREATE INDEX IF NOT EXISTS operations_created_idx ON operations(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_log(created_at DESC);
