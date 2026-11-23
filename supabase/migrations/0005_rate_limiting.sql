-- ====================================================================
-- AegisFlow Migration 0005: Distributed API Rate Limiting & Abuse Protection
-- Migration Path: supabase/migrations/0005_rate_limiting.sql
-- ====================================================================
-- Description:
-- Provides an atomic, PostgreSQL-backed distributed rate-limiting table and
-- RPC function shared across all serverless Vercel instances.
--
-- Security & Privacy Model:
-- 1. rate_key values are deterministic server-side SHA-256 hashes
--    (`${endpoint}:${scope}:${sha256}`). No raw client IPs, user UUIDs,
--    message bodies, uploaded filenames, or inspected URLs are stored.
-- 2. RLS is strictly enabled and all table/function privileges are revoked
--    from PUBLIC, anon, and authenticated browser roles.
-- 3. Only trusted server-side service_role callers (persistSession: false)
--    can query, mutate, or invoke consume_rate_limit().
-- 4. Preserves all existing tables, schemas, and migrations.
-- ====================================================================

create table if not exists public.api_rate_limits (
  rate_key text primary key,
  endpoint text not null check (endpoint in ('analyze', 'scan_document', 'fact_check', 'url_investigation')),
  scope text not null check (scope in ('authenticated', 'guest')),
  request_count integer not null default 1 check (request_count >= 0),
  window_start timestamptz not null default clock_timestamp(),
  window_end timestamptz not null,
  updated_at timestamptz not null default clock_timestamp()
);

create index if not exists idx_api_rate_limits_window_end
  on public.api_rate_limits (window_end);

alter table public.api_rate_limits enable row level security;

revoke all on table public.api_rate_limits from public;
revoke all on table public.api_rate_limits from anon;
revoke all on table public.api_rate_limits from authenticated;
grant select, insert, update, delete on table public.api_rate_limits to service_role;

create or replace function public.consume_rate_limit(
  p_rate_key text,
  p_endpoint text,
  p_scope text,
  p_max_requests integer,
  p_window_seconds integer
)
returns table (
  allowed boolean,
  current_count integer,
  remaining integer,
  retry_after_seconds integer,
  reset_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_limit integer := greatest(1, coalesce(p_max_requests, 1));
  v_window integer := greatest(1, coalesce(p_window_seconds, 60));
  v_window_end timestamptz := v_now + make_interval(secs => v_window);
  v_row public.api_rate_limits%rowtype;
  v_allowed boolean;
  v_retry_after integer;
begin
  -- Opportunistic bounded purge of expired windows to prevent unbounded growth
  delete from public.api_rate_limits
  where rate_key in (
    select rl_exp.rate_key
    from public.api_rate_limits as rl_exp
    where rl_exp.window_end <= v_now
    limit 50
  );

  -- Atomic row-level upsert serializes concurrent requests for the same rate_key
  insert into public.api_rate_limits as rl (
    rate_key,
    endpoint,
    scope,
    request_count,
    window_start,
    window_end,
    updated_at
  )
  values (
    p_rate_key,
    p_endpoint,
    p_scope,
    1,
    v_now,
    v_window_end,
    v_now
  )
  on conflict (rate_key) do update
  set
    endpoint = excluded.endpoint,
    scope = excluded.scope,
    window_start = case
      when rl.window_end <= v_now then v_now
      else rl.window_start
    end,
    window_end = case
      when rl.window_end <= v_now then v_window_end
      else rl.window_end
    end,
    request_count = case
      when rl.window_end <= v_now then 1
      else least(rl.request_count + 1, v_limit + 1)
    end,
    updated_at = v_now
  returning * into v_row;

  v_allowed := v_row.request_count <= v_limit;
  v_retry_after := greatest(1, ceil(extract(epoch from (v_row.window_end - v_now)))::integer);

  return query
  select
    v_allowed,
    least(v_row.request_count, v_limit),
    greatest(0, v_limit - least(v_row.request_count, v_limit)),
    case when v_allowed then 0 else v_retry_after end,
    v_row.window_end;
end;
$$;

revoke all on function public.consume_rate_limit(text, text, text, integer, integer) from public;
revoke all on function public.consume_rate_limit(text, text, text, integer, integer) from anon;
revoke all on function public.consume_rate_limit(text, text, text, integer, integer) from authenticated;
grant execute on function public.consume_rate_limit(text, text, text, integer, integer) to service_role;
