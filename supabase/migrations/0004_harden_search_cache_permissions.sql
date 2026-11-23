-- ====================================================================
-- AegisFlow Migration 0004: Harden Search Cache Table Permissions & RLS
-- Migration Path: supabase/migrations/0004_harden_search_cache_permissions.sql
-- ====================================================================
-- Description:
-- Remediates overly permissive anonymous and authenticated access to
-- public.search_cache introduced in 0003_search_cache.sql.
--
-- Security Model:
-- 1. public.search_cache is a trusted server-side intelligence cache used
--    exclusively by Next.js server routes/services via SUPABASE_SERVICE_ROLE_KEY
--    (with persistSession: false).
-- 2. Browser callers (anon and authenticated roles) have zero legitimate
--    reason to insert, update, delete, or query public.search_cache directly.
-- 3. Preserves the existing table schema, columns, constraints, indexes,
--    and cached rows without dropping or recreating the table.
-- ====================================================================

-- 1. Keep Row Level Security enabled on public.search_cache
alter table public.search_cache enable row level security;

-- 2. Drop overly permissive policies from 0003_search_cache.sql
-- Removes broad WITH CHECK (true) / USING (true) write policies and
-- direct browser read policy.
drop policy if exists "Allow inserting search cache" on public.search_cache;
drop policy if exists "Allow updating search cache" on public.search_cache;
drop policy if exists "Allow reading unexpired cache" on public.search_cache;
drop policy if exists "Allow deleting search cache" on public.search_cache;

-- 3. Revoke all direct table privileges from public, anon, and authenticated
-- Prevents ordinary browser clients from inserting, updating, poisoning,
-- deleting, or directly reading cached research entries.
revoke all on table public.search_cache from public;
revoke all on table public.search_cache from anon;
revoke all on table public.search_cache from authenticated;

-- 4. Restrict access exclusively to trusted server-side service_role
grant select, insert, update, delete on table public.search_cache to service_role;
