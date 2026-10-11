create extension if not exists "pgcrypto";
drop table if exists notifications cascade;
drop table if exists payments cascade;
drop table if exists students cascade;
drop table if exists admins cascade;

-- Admins table - LIMITED TO 2 ADMINS as per original app
create table admins (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  full_name text,
  created_at timestamptz default now()
);

-- Students admitted by admin FIRST with adm_number, name, level - NOT email
create table students (
  id uuid references auth.users(id) on delete cascade,
  adm_number text primary key,
  full_name text not null,
  level text not null,
  course text,
  email text,
  phone text,
  total_fees int default 0 not null,
  paid_amount int default 0 not null,
  balance int generated always as (total_fees - paid_amount) stored,
  is_registered boolean default false,
  created_at timestamptz default now()
);

create table payments (
  id uuid primary key default gen_random_uuid(),
  adm_number text references students(adm_number) on delete cascade not null,
  student_id uuid references auth.users(id),
  type text check (type in ('fees','exam_booking')) not null,
  amount int not null,
  method text,
  status text check (status in ('pending','confirmed','rejected')) default 'pending',
  submitted_at timestamptz default now(),
  confirmed_at timestamptz
);

create table notifications (
  id uuid primary key default gen_random_uuid(),
  for_adm_number text references students(adm_number) on delete cascade,
  for_user_id uuid references auth.users(id) on delete cascade,
  title text not null,
  message text not null,
  is_read boolean default false,
  created_at timestamptz default now()
);

create index idx_payments_adm on payments(adm_number);
create index idx_payments_status on payments(status);
create index idx_notifications_adm on notifications(for_adm_number);

alter table admins enable row level security;
alter table students enable row level security;
alter table payments enable row level security;
alter table notifications enable row level security;

-- Allow service_role (backend on Render) to do everything
create policy "allow all" on admins for all using (true) with check (true);
create policy "allow all" on students for all using (true) with check (true);
create policy "allow all" on payments for all using (true) with check (true);
create policy "allow all" on notifications for all using (true) with check (true);

alter publication supabase_realtime add table students, payments, notifications, admins;
