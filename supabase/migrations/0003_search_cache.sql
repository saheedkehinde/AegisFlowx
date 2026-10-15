-- ====================================================================
-- AegisFlow Migration 0003: Public Search & Threat Intelligence Cache
-- Migration Path: supabase/migrations/0003_search_cache.sql
-- ====================================================================
-- Description:
-- Provides persistent server-side caching for external search results
-- and threat-intelligence lookups. This reduces outbound API calls,
-- conserves free tier quotas, and accelerates repeated queries.
--
-- Security:
-- 1. Cache keys are SHA-256 hashes of normalized query strings.
-- 2. Never stores user identifiers, private message content, or credentials.
-- 3. Transparently expires based on expires_at timestamp.
-- ====================================================================

-- 1. Create search_cache table
create table if not exists public.search_cache (
  cache_key text primary key,
  provider text not null check (provider in ('serper', 'urlhaus', 'wikipedia')),
  query_normalized text not null,
  response_payload jsonb not null default '{}'::jsonb,
  cached_at timestamptz not null default now(),
  expires_at timestamptz not null
);

-- 2. Index for expiration and provider lookups
create index if not exists idx_search_cache_expires 
  on public.search_cache (expires_at);

create index if not exists idx_search_cache_provider_key 
  on public.search_cache (provider, cache_key);

-- 3. Enable Row Level Security (RLS)
alter table public.search_cache enable row level security;

-- 4. Permissions: Allow authenticated and service_role to read unexpired cache
-- (Anon visitors can also read public cached web search results)
grant usage on schema public to authenticated, anon;
grant select, insert, update on table public.search_cache to authenticated, anon;

drop policy if exists "Allow reading unexpired cache" on public.search_cache;
create policy "Allow reading unexpired cache"
  on public.search_cache
  for select
  using (expires_at > now());

drop policy if exists "Allow inserting search cache" on public.search_cache;
create policy "Allow inserting search cache"
  on public.search_cache
  for insert
  with check (true);

drop policy if exists "Allow updating search cache" on public.search_cache;
create policy "Allow updating search cache"
  on public.search_cache
  for update
  using (true)
  with check (true);
