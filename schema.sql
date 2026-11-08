CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text NOT NULL UNIQUE,
 password_hash text NOT NULL, name text NOT NULL, role text NOT NULL CHECK(role IN ('manager','employee')),
 title text NOT NULL DEFAULT 'موظف', department text NOT NULL DEFAULT 'خدمة العملاء',
 approved boolean NOT NULL DEFAULT false, salary numeric(12,2) NOT NULL DEFAULT 0 CHECK(salary >= 0),
 rating integer NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 100),
 status text NOT NULL DEFAULT 'بانتظار التفعيل', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS attendance (
 id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), work_date date NOT NULL DEFAULT CURRENT_DATE,
 clock_in timestamptz, clock_out timestamptz, UNIQUE(user_id, work_date)
);
CREATE TABLE IF NOT EXISTS daily_metrics (
 user_id uuid NOT NULL REFERENCES users(id), work_date date NOT NULL DEFAULT CURRENT_DATE,
 transfers integer NOT NULL DEFAULT 0 CHECK(transfers>=0), exchange integer NOT NULL DEFAULT 0 CHECK(exchange>=0),
 wallets integer NOT NULL DEFAULT 0 CHECK(wallets>=0), PRIMARY KEY(user_id,work_date)
);
CREATE TABLE IF NOT EXISTS tasks (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), employee_id uuid NOT NULL REFERENCES users(id),
 title text NOT NULL, description text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed')),
 file_label text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
);
CREATE TABLE IF NOT EXISTS notifications (
 id bigserial PRIMARY KEY, employee_id uuid NOT NULL REFERENCES users(id), task_id uuid REFERENCES tasks(id),
 message text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), read_at timestamptz
);
CREATE TABLE IF NOT EXISTS audit_log (
 id bigserial PRIMARY KEY, actor_id uuid REFERENCES users(id), action text NOT NULL,
 target_id uuid, details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS attendance_date_idx ON attendance(work_date);
CREATE INDEX IF NOT EXISTS tasks_employee_idx ON tasks(employee_id, status);
