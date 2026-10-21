-- ====================================================================
-- AegisFlow Migration 0002: Secure Administrative Roles & Escalations
-- Migration Path: supabase/migrations/0002_administrative_roles.sql
-- ====================================================================

-- 1. User Roles Table (Strictly isolated from client-side mutation)
-- INVARIANT: Roles MUST NOT be stored in an editable profile field.
-- They are kept in a dedicated table where regular authenticated users have ZERO write access.
create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin', 'super_admin', 'analyst', 'user')),
  granted_by uuid references auth.users(id) on delete set null,
  granted_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Enable Row Level Security on user_roles
alter table public.user_roles enable row level security;

-- 2. Security Definer Helper Function: is_admin()
-- Evaluates whether the currently authenticated user possesses an administrative role.
-- Uses empty search_path to prevent search-path hijacking attacks.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select exists (
    select 1 from public.user_roles
    where user_id = auth.uid()
      and role in ('admin', 'super_admin')
  );
$$;

-- 3. Row Level Security Policies for user_roles
-- Users can read ONLY their own assigned role (to render appropriate navigation UI)
drop policy if exists "Users can view their own role" on public.user_roles;
create policy "Users can view their own role"
  on public.user_roles
  for select
  using (auth.uid() = user_id);

-- Admins can view all assigned roles
drop policy if exists "Admins can view all user roles" on public.user_roles;
create policy "Admins can view all user roles"
  on public.user_roles
  for select
  using (public.is_admin());

-- Super admins only can grant or revoke roles
drop policy if exists "Super admins can manage roles" on public.user_roles;
create policy "Super admins can manage roles"
  on public.user_roles
  for all
  using (
    exists (
      select 1 from public.user_roles
      where user_id = auth.uid()
        and role = 'super_admin'
    )
  );

-- 4. Security Incident Escalations Table (For user reports needing administrative review)
create table if not exists public.security_escalations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  analysis_id uuid references public.analysis_history(id) on delete set null,
  threat_category text not null,
  urgency text not null check (urgency in ('critical', 'high', 'medium', 'low')),
  user_notes text,
  status text not null default 'pending' check (status in ('pending', 'investigating', 'resolved', 'dismissed')),
  admin_notes text,
  resolved_by uuid references auth.users(id) on delete set null,
  resolved_at timestamptz,
  created_at timestamptz not null default now()
);

-- Enable RLS on security_escalations
alter table public.security_escalations enable row level security;

-- Escalations Policies:
-- Users can view ONLY their own submitted escalations
drop policy if exists "Users can view their own escalations" on public.security_escalations;
create policy "Users can view their own escalations"
  on public.security_escalations
  for select
  using (auth.uid() = user_id);

-- Users can insert their own escalations
drop policy if exists "Users can insert their own escalations" on public.security_escalations;
create policy "Users can insert their own escalations"
  on public.security_escalations
  for insert
  with check (auth.uid() = user_id);

-- Admins can view all escalations across the platform for triage
drop policy if exists "Admins can view all escalations" on public.security_escalations;
create policy "Admins can view all escalations"
  on public.security_escalations
  for select
  using (public.is_admin());

-- Admins can update status and admin_notes for escalations
drop policy if exists "Admins can update escalations" on public.security_escalations;
create policy "Admins can update escalations"
  on public.security_escalations
  for update
  using (public.is_admin())
  with check (public.is_admin());

-- 5. Explicit Least-Privilege Grants
grant usage on schema public to authenticated;

-- Authenticated users can read their own role and submit escalations
grant select on public.user_roles to authenticated;
grant select, insert on public.security_escalations to authenticated;

-- Revoke all permissions from anon users
revoke all on public.user_roles from anon;
revoke all on public.security_escalations from anon;

-- Indexes for efficient administrative querying
create index if not exists idx_user_roles_role on public.user_roles(role);
create index if not exists idx_escalations_status on public.security_escalations(status, created_at desc);
create index if not exists idx_escalations_user on public.security_escalations(user_id, created_at desc);
