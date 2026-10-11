-- ====================================================================
-- AegisFlow Phase 2 Migration: User Profiles & Secure Analysis History
-- Migration Path: supabase/migrations/0001_aegisflow_phase2.sql
-- ====================================================================

-- 1. Profiles Table (Linked to auth.users)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Enable RLS on profiles
alter table public.profiles enable row level security;

-- 2. Analysis History Table (Linked to auth.users owner)
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

-- Enable RLS on analysis_history
alter table public.analysis_history enable row level security;

-- Performance indexes for user timeline queries
create index if not exists idx_analysis_history_user_created 
  on public.analysis_history (user_id, created_at desc);

create index if not exists idx_analysis_history_severity 
  on public.analysis_history (user_id, threat_severity);

-- ====================================================================
-- Row Level Security (RLS) Policies
-- ====================================================================

-- Profiles Policies
drop policy if exists "Users can view their own profile" on public.profiles;
create policy "Users can view their own profile"
  on public.profiles
  for select
  using (auth.uid() = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles
  for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

drop policy if exists "Users can insert their own profile" on public.profiles;
create policy "Users can insert their own profile"
  on public.profiles
  for insert
  with check (auth.uid() = id);

-- Analysis History Policies (Least-privilege isolation)
drop policy if exists "Users can view only their own analysis records" on public.analysis_history;
create policy "Users can view only their own analysis records"
  on public.analysis_history
  for select
  using (auth.uid() = user_id);

drop policy if exists "Users can insert analysis records owned by themselves" on public.analysis_history;
create policy "Users can insert analysis records owned by themselves"
  on public.analysis_history
  for insert
  with check (auth.uid() = user_id);

drop policy if exists "Users can delete only their own analysis records" on public.analysis_history;
create policy "Users can delete only their own analysis records"
  on public.analysis_history
  for delete
  using (auth.uid() = user_id);

-- ====================================================================
-- Safe Profile Provisioning Trigger
-- ====================================================================
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(
      new.raw_user_meta_data->>'display_name',
      split_part(coalesce(new.email, ''), '@', 1)
    )
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row
  execute function public.handle_new_user();

-- ====================================================================
-- Explicit Least-Privilege Grants
-- ====================================================================
grant usage on schema public to anon, authenticated;

grant select, insert, update on public.profiles to authenticated;
grant select, insert, delete on public.analysis_history to authenticated;

-- Ensure anonymous users have zero access to user tables
revoke all on public.profiles from anon;
revoke all on public.analysis_history from anon;
