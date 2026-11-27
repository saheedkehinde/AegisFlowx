-- AegisFlow Phase 1: Safe Stale Quota Reservation Recovery
-- Additive migration for PostgreSQL 15+ / Supabase.
-- Strictly preserves 0006_usage_quotas.sql tables, constraints, RLS, and credit allocations.

create or replace function public.recover_stale_quota_reservations(
  p_min_age_seconds integer default 600,
  p_limit integer default 100
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  -- Conservative minimum floor (300s / 5m) exceeds the max serverless route budget (60s) by 5x.
  v_min_age_seconds integer := greatest(coalesce(p_min_age_seconds, 600), 300);
  v_batch_limit integer := greatest(1, least(coalesce(p_limit, 100), 500));
  v_cutoff timestamptz := now() - make_interval(secs => v_min_age_seconds);
  v_res public.quota_reservations%rowtype;
  v_finalize jsonb;
  v_recovered_count integer := 0;
  v_skipped_count integer := 0;
  v_recovered_ids jsonb := '[]'::jsonb;
begin
  for v_res in
    select *
    from public.quota_reservations
    where status = 'reserved'
      and created_at <= v_cutoff
    order by created_at asc
    limit v_batch_limit
    for update skip locked
  loop
    -- Lock balance row in canonical table order (reservations -> balances) before finalizing.
    perform 1
    from public.quota_balances
    where account_key = v_res.account_key
      and bucket = v_res.bucket
    for update;

    v_finalize := public.finalize_investigation_quota(
      v_res.id,
      'refund',
      'stale_reservation_recovery'
    );

    if coalesce((v_finalize->>'ok')::boolean, false)
       and not coalesce((v_finalize->>'alreadyResolved')::boolean, false)
       and v_finalize->>'status' = 'refunded' then
      v_recovered_count := v_recovered_count + 1;
      v_recovered_ids := v_recovered_ids || to_jsonb(v_res.id::text);
    else
      v_skipped_count := v_skipped_count + 1;
    end if;
  end loop;

  return jsonb_build_object(
    'ok', true,
    'minAgeSeconds', v_min_age_seconds,
    'cutoff', v_cutoff,
    'recoveredCount', v_recovered_count,
    'skippedCount', v_skipped_count,
    'recoveredReservationIds', v_recovered_ids
  );
end;
$$;

revoke all on function public.recover_stale_quota_reservations(integer, integer) from public, anon, authenticated;
grant execute on function public.recover_stale_quota_reservations(integer, integer) to service_role;
