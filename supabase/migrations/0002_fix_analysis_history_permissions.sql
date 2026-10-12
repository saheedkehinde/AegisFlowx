-- ====================================================================
-- AegisFlow Migration 0002: Analysis History Table Privileges & RLS Fix
-- Migration Path: supabase/migrations/0002_fix_analysis_history_permissions.sql
-- ====================================================================
-- Description:
-- Fixes "permission denied for table analysis_history" (PostgreSQL error 42501).
-- This error occurs when the PostgreSQL database role 'authenticated' lacks
-- table-level privileges (SELECT / INSERT / DELETE) on public.analysis_history,
-- halting queries before Row Level Security (RLS) is even evaluated.
--
-- This migration is safe, idempotent, and non-destructive:
-- 1. Preserves existing tables, constraints, and rows.
-- 2. Grants least-privilege table permissions to 'authenticated' role.
-- 3. Revokes all permissions from 'anon' (unauthenticated visitors).
-- 4. Re-enforces strict ownership-based RLS policies:
--    (auth.uid() = user_id for SELECT, INSERT, DELETE).
-- ====================================================================

-- 1. Ensure public.analysis_history Table Exists
create table if not exists public.analysis_history (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  input_type text not null default 'message',
  input_snippet text not null,
  threat_severity text not null check (threat_severity in ('high', 'medium', 'low', 'uncertain')),
  severity_score integer not null check (severity_score >= 0 and severity_score <= 100),
  summary text not null,
  indicators jsonb not null default '[]'::jsonb,
  recommended_actions jsonb not null default '[]'::jsonb,
  limitations jsonb not null default '[]'::jsonb,
  evidence_sufficiency text not null check (evidence_sufficiency in ('sufficient', 'moderate', 'sparse')),
  model_confidence text not null check (model_confidence in ('high', 'moderate', 'low')),
  confidence_rationale text,
  model_name text,
  iocs jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- 2. Ensure Performance Indexes Exist
create index if not exists idx_analysis_history_user_created 
  on public.analysis_history (user_id, created_at desc);

create index if not exists idx_analysis_history_severity 
  on public.analysis_history (user_id, threat_severity);

-- 3. Ensure Row Level Security (RLS) is Enabled
alter table public.analysis_history enable row level security;
alter table public.profiles enable row level security;

-- 4. Explicit Least-Privilege Table Grants for Authenticated Role
-- The authenticated role requires SELECT (read history), INSERT (persist new scans),
-- and DELETE (remove scans). UPDATE is deliberately omitted as analysis records are immutable.
grant usage on schema public to authenticated;
grant select, insert, delete on table public.analysis_history to authenticated;
grant select, insert, update on table public.profiles to authenticated;

-- Grant usage on sequences if any
grant usage, select on all sequences in schema public to authenticated;

-- 5. Strict Revocation for Anonymous Role
-- Guarantee unauthenticated visitors have zero access to private user tables
revoke all on table public.analysis_history from anon;
revoke all on table public.profiles from anon;

-- 6. Strict Ownership-Based Row Level Security (RLS) Policies
-- Users can only ever access, insert, or delete records matching their auth.uid()

-- Policy: SELECT - Users can view only their own analysis records
drop policy if exists "Users can view only their own analysis records" on public.analysis_history;
create policy "Users can view only their own analysis records"
  on public.analysis_history
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Policy: INSERT - Users can insert analysis records owned by themselves
drop policy if exists "Users can insert analysis records owned by themselves" on public.analysis_history;
create policy "Users can insert analysis records owned by themselves"
  on public.analysis_history
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Policy: DELETE - Users can delete only their own analysis records
drop policy if exists "Users can delete only their own analysis records" on public.analysis_history;
create policy "Users can delete only their own analysis records"
  on public.analysis_history
  for delete
  to authenticated
  using (auth.uid() = user_id);

-- Policy: Profiles Synchronization
drop policy if exists "Users can view their own profile" on public.profiles;
create policy "Users can view their own profile"
  on public.profiles
  for select
  to authenticated
  using (auth.uid() = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles
  for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

drop policy if exists "Users can insert their own profile" on public.profiles;
create policy "Users can insert their own profile"
  on public.profiles
  for insert
  to authenticated
  with check (auth.uid() = id);
