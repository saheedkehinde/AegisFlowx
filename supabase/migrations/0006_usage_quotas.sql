-- AegisFlow Phase 1: Persistent Usage Quota, Guest Credit Architecture & Referral-Ready Ledger
-- Safe, idempotent migration designed for PostgreSQL 15+ / Supabase.
-- Strictly preserves 0005_rate_limiting.sql, profiles, user_roles, and analysis_history.

-- 1. Cryptographically hashed guest identities (no raw tokens or raw IPs stored)
create table if not exists public.guest_identities (
  guest_id_hash text primary key check (guest_id_hash ~ '^[a-f0-9]{64}$'),
  rotated_from_hash text null,
  superseded_by_hash text null,
  claimed_by_user_id uuid null references auth.users(id) on delete set null,
  claimed_at timestamptz null,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create index if not exists idx_guest_identities_claimed_user
  on public.guest_identities (claimed_by_user_id)
  where claimed_by_user_id is not null;

-- 2. Quota account ownership & plan/referral metadata
create table if not exists public.quota_accounts (
  account_key text primary key,
  owner_type text not null check (owner_type in ('guest', 'user')),
  user_id uuid unique null references auth.users(id) on delete cascade,
  guest_id_hash text unique null references public.guest_identities(guest_id_hash) on delete set null,
  plan_tier text not null default 'free' check (plan_tier in ('guest_trial', 'free', 'pro', 'business')),
  initial_grant_issued boolean not null default false,
  claimed_guest_hash text null,
  referral_code text unique null,
  referred_by_user_id uuid null references auth.users(id) on delete set null,
  referral_rewarded_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint quota_accounts_owner_consistency check (
    (owner_type = 'user' and user_id is not null and guest_id_hash is null) or
    (owner_type = 'guest' and guest_id_hash is not null and user_id is null)
  )
);

-- 3. Persistent credit balances per bucket
-- Guest accounts use bucket = 'guest_shared' (12 shared credits).
-- Registered verified users use 4 independent buckets (5 credits each = 20 total initial credits).
create table if not exists public.quota_balances (
  account_key text not null references public.quota_accounts(account_key) on delete cascade,
  bucket text not null check (
    bucket in (
      'guest_shared',
      'message_analysis',
      'document_scan',
      'fact_check',
      'url_investigation'
    )
  ),
  balance integer not null default 0 check (balance >= 0),
  lifetime_granted integer not null default 0 check (lifetime_granted >= 0),
  lifetime_used integer not null default 0 check (lifetime_used >= 0),
  updated_at timestamptz not null default now(),
  primary key (account_key, bucket)
);

-- 4. Atomic credit reservations for reserve -> commit / single-refund execution
create table if not exists public.quota_reservations (
  id uuid primary key default gen_random_uuid(),
  account_key text not null references public.quota_accounts(account_key) on delete cascade,
  bucket text not null check (
    bucket in (
      'guest_shared',
      'message_analysis',
      'document_scan',
      'fact_check',
      'url_investigation'
    )
  ),
  capability text not null check (
    capability in (
      'message_analysis',
      'document_scan',
      'fact_check',
      'url_investigation'
    )
  ),
  amount integer not null default 1 check (amount = 1),
  status text not null check (status in ('reserved', 'committed', 'refunded', 'expired')),
  idempotency_key text null,
  failure_reason text null,
  created_at timestamptz not null default now(),
  resolved_at timestamptz null
);

create unique index if not exists idx_quota_reservations_idempotency
  on public.quota_reservations (account_key, idempotency_key)
  where idempotency_key is not null;

create index if not exists idx_quota_reservations_status_created
  on public.quota_reservations (status, created_at);

-- 5. Immutable audit ledger for grants, usage, refunds, future referrals & plans
create table if not exists public.quota_ledger (
  id uuid primary key default gen_random_uuid(),
  account_key text not null references public.quota_accounts(account_key) on delete cascade,
  bucket text not null check (
    bucket in (
      'guest_shared',
      'message_analysis',
      'document_scan',
      'fact_check',
      'url_investigation'
    )
  ),
  capability text null check (
    capability is null or capability in (
      'message_analysis',
      'document_scan',
      'fact_check',
      'url_investigation'
    )
  ),
  delta integer not null,
  balance_after integer not null check (balance_after >= 0),
  entry_type text not null check (
    entry_type in (
      'initial_grant',
      'consume_reserve',
      'consume_commit',
      'refund',
      'referral_bonus',
      'plan_allocation',
      'adjustment'
    )
  ),
  reservation_id uuid null references public.quota_reservations(id) on delete set null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_quota_ledger_account_created
  on public.quota_ledger (account_key, created_at desc);

-- 6. Referral readiness table (Phase 2 schema preparation; zero rewards issued in Phase 1)
create table if not exists public.referral_claims (
  id uuid primary key default gen_random_uuid(),
  referrer_user_id uuid not null references auth.users(id) on delete cascade,
  referred_user_id uuid not null unique references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'rewarded', 'rejected')),
  reward_per_capability integer not null default 10 check (reward_per_capability >= 0),
  rewarded_at timestamptz null,
  created_at timestamptz not null default now(),
  constraint referral_no_self_referral check (referrer_user_id <> referred_user_id)
);

-- Enable Row Level Security on all quota tables
alter table public.guest_identities enable row level security;
alter table public.quota_accounts enable row level security;
alter table public.quota_balances enable row level security;
alter table public.quota_reservations enable row level security;
alter table public.quota_ledger enable row level security;
alter table public.referral_claims enable row level security;

-- Lock down direct table access strictly to service_role (zero anon/authenticated mutations)
revoke all on table public.guest_identities from public, anon, authenticated;
revoke all on table public.quota_accounts from public, anon, authenticated;
revoke all on table public.quota_balances from public, anon, authenticated;
revoke all on table public.quota_reservations from public, anon, authenticated;
revoke all on table public.quota_ledger from public, anon, authenticated;
revoke all on table public.referral_claims from public, anon, authenticated;

grant select, insert, update, delete on table public.guest_identities to service_role;
grant select, insert, update, delete on table public.quota_accounts to service_role;
grant select, insert, update, delete on table public.quota_balances to service_role;
grant select, insert, update, delete on table public.quota_reservations to service_role;
grant select, insert, update, delete on table public.quota_ledger to service_role;
grant select, insert, update, delete on table public.referral_claims to service_role;

-- Helper: returns normalized JSON snapshot for a quota_accounts row
create or replace function public.get_quota_snapshot(p_account_key text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account public.quota_accounts%rowtype;
  v_guest public.guest_identities%rowtype;
  v_shared integer := 0;
  v_msg integer := 0;
  v_doc integer := 0;
  v_fc integer := 0;
  v_url integer := 0;
begin
  select * into v_account
  from public.quota_accounts
  where account_key = p_account_key;

  if not found then
    return jsonb_build_object('exists', false);
  end if;

  if v_account.owner_type = 'guest' then
    select * into v_guest
    from public.guest_identities
    where guest_id_hash = v_account.guest_id_hash;

    select coalesce(balance, 0) into v_shared
    from public.quota_balances
    where account_key = p_account_key and bucket = 'guest_shared';

    return jsonb_build_object(
      'exists', true,
      'ownerType', 'guest',
      'planTier', v_account.plan_tier,
      'initialGrantIssued', v_account.initial_grant_issued,
      'claimedByUser', (v_guest.claimed_by_user_id is not null),
      'sharedRemaining', coalesce(v_shared, 0),
      'sharedLimit', 12,
      'balances', jsonb_build_object(
        'message_analysis', coalesce(v_shared, 0),
        'document_scan', coalesce(v_shared, 0),
        'fact_check', coalesce(v_shared, 0),
        'url_investigation', coalesce(v_shared, 0)
      ),
      'totalRemaining', coalesce(v_shared, 0)
    );
  end if;

  select coalesce(max(case when bucket = 'message_analysis' then balance end), 0),
         coalesce(max(case when bucket = 'document_scan' then balance end), 0),
         coalesce(max(case when bucket = 'fact_check' then balance end), 0),
         coalesce(max(case when bucket = 'url_investigation' then balance end), 0)
  into v_msg, v_doc, v_fc, v_url
  from public.quota_balances
  where account_key = p_account_key;

  return jsonb_build_object(
    'exists', true,
    'ownerType', 'user',
    'planTier', v_account.plan_tier,
    'initialGrantIssued', v_account.initial_grant_issued,
    'claimedByUser', false,
    'sharedRemaining', null,
    'sharedLimit', null,
    'balances', jsonb_build_object(
      'message_analysis', v_msg,
      'document_scan', v_doc,
      'fact_check', v_fc,
      'url_investigation', v_url
    ),
    'totalRemaining', (v_msg + v_doc + v_fc + v_url)
  );
end;
$$;

-- RPC 1: Idempotent guest quota initialization / lookup (12 shared non-renewing credits)
create or replace function public.ensure_guest_quota(
  p_guest_hash text,
  p_initial_credits integer default 12,
  p_create_if_missing boolean default true
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_hash text := lower(trim(coalesce(p_guest_hash, '')));
  v_guest public.guest_identities%rowtype;
  v_account_key text;
  v_account public.quota_accounts%rowtype;
  v_credits integer := greatest(0, least(coalesce(p_initial_credits, 12), 12));
  v_depth integer := 0;
begin
  if v_hash !~ '^[a-f0-9]{64}$' then
    return jsonb_build_object('ok', false, 'errorCode', 'invalid_guest_token');
  end if;

  perform pg_advisory_xact_lock(hashtext('guest:' || v_hash));

  select * into v_guest
  from public.guest_identities
  where guest_id_hash = v_hash;

  -- Follow safe token rotation chain if hash was rotated
  while found and v_guest.superseded_by_hash is not null and v_depth < 10 loop
    v_depth := v_depth + 1;
    v_hash := v_guest.superseded_by_hash;
    select * into v_guest
    from public.guest_identities
    where guest_id_hash = v_hash;
  end loop;

  v_account_key := 'guest:' || v_hash;

  if not exists (select 1 from public.guest_identities where guest_id_hash = v_hash) then
    if not coalesce(p_create_if_missing, true) then
      return jsonb_build_object('ok', false, 'errorCode', 'unrecognized_guest_token');
    end if;

    insert into public.guest_identities (guest_id_hash)
    values (v_hash)
    on conflict (guest_id_hash) do nothing;
  else
    update public.guest_identities
    set last_seen_at = now()
    where guest_id_hash = v_hash;
  end if;

  insert into public.quota_accounts (
    account_key,
    owner_type,
    guest_id_hash,
    plan_tier,
    initial_grant_issued
  )
  values (
    v_account_key,
    'guest',
    v_hash,
    'guest_trial',
    false
  )
  on conflict (account_key) do nothing;

  select * into v_account
  from public.quota_accounts
  where account_key = v_account_key
  for update;

  if not v_account.initial_grant_issued then
    insert into public.quota_balances (
      account_key,
      bucket,
      balance,
      lifetime_granted,
      lifetime_used
    )
    values (
      v_account_key,
      'guest_shared',
      v_credits,
      v_credits,
      0
    )
    on conflict (account_key, bucket) do nothing;

    update public.quota_accounts
    set initial_grant_issued = true,
        updated_at = now()
    where account_key = v_account_key;

    insert into public.quota_ledger (
      account_key,
      bucket,
      capability,
      delta,
      balance_after,
      entry_type,
      metadata
    )
    values (
      v_account_key,
      'guest_shared',
      null,
      v_credits,
      v_credits,
      'initial_grant',
      jsonb_build_object('ownerType', 'guest')
    );
  end if;

  return jsonb_build_object(
    'ok', true,
    'accountKey', v_account_key,
    'canonicalGuestHash', v_hash,
    'snapshot', public.get_quota_snapshot(v_account_key)
  );
end;
$$;

-- RPC 2: Idempotent registered-user initialization (one-time 5/5/5/5 credits + guest claim)
create or replace function public.ensure_user_quota(
  p_user_id uuid,
  p_claim_guest_hash text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account_key text;
  v_account public.quota_accounts%rowtype;
  v_clean_guest text := lower(trim(coalesce(p_claim_guest_hash, '')));
  v_bucket text;
  v_buckets text[] := array['message_analysis', 'document_scan', 'fact_check', 'url_investigation'];
  v_per_cap_grant constant integer := 5;
  v_ref_code text;
begin
  if p_user_id is null then
    return jsonb_build_object('ok', false, 'errorCode', 'invalid_user');
  end if;

  v_account_key := 'user:' || p_user_id::text;
  perform pg_advisory_xact_lock(hashtext(v_account_key));

  -- Associate/claim prior guest identity idempotently so sign-in/sign-out cycling never mints fresh credits
  if v_clean_guest ~ '^[a-f0-9]{64}$' then
    insert into public.guest_identities (
      guest_id_hash,
      claimed_by_user_id,
      claimed_at,
      last_seen_at
    )
    values (
      v_clean_guest,
      p_user_id,
      now(),
      now()
    )
    on conflict (guest_id_hash) do update
    set claimed_by_user_id = coalesce(public.guest_identities.claimed_by_user_id, p_user_id),
        claimed_at = coalesce(public.guest_identities.claimed_at, now()),
        last_seen_at = now();
  else
    v_clean_guest := null;
  end if;

  v_ref_code := upper(substr(replace(p_user_id::text, '-', ''), 1, 10));

  insert into public.quota_accounts (
    account_key,
    owner_type,
    user_id,
    plan_tier,
    initial_grant_issued,
    claimed_guest_hash,
    referral_code
  )
  values (
    v_account_key,
    'user',
    p_user_id,
    'free',
    false,
    v_clean_guest,
    v_ref_code
  )
  on conflict (account_key) do update
  set claimed_guest_hash = coalesce(public.quota_accounts.claimed_guest_hash, excluded.claimed_guest_hash),
      updated_at = now();

  select * into v_account
  from public.quota_accounts
  where account_key = v_account_key
  for update;

  if not v_account.initial_grant_issued then
    foreach v_bucket in array v_buckets loop
      insert into public.quota_balances (
        account_key,
        bucket,
        balance,
        lifetime_granted,
        lifetime_used
      )
      values (
        v_account_key,
        v_bucket,
        v_per_cap_grant,
        v_per_cap_grant,
        0
      )
      on conflict (account_key, bucket) do nothing;

      insert into public.quota_ledger (
        account_key,
        bucket,
        capability,
        delta,
        balance_after,
        entry_type,
        metadata
      )
      values (
        v_account_key,
        v_bucket,
        v_bucket,
        v_per_cap_grant,
        v_per_cap_grant,
        'initial_grant',
        jsonb_build_object('ownerType', 'user')
      );
    end loop;

    update public.quota_accounts
    set initial_grant_issued = true,
        updated_at = now()
    where account_key = v_account_key;
  end if;

  return jsonb_build_object(
    'ok', true,
    'accountKey', v_account_key,
    'snapshot', public.get_quota_snapshot(v_account_key)
  );
end;
$$;

-- RPC 3: Safe guest token rotation preserving exact remaining balance (never resets credits)
create or replace function public.rotate_guest_identity(
  p_old_hash text,
  p_new_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_old text := lower(trim(coalesce(p_old_hash, '')));
  v_new text := lower(trim(coalesce(p_new_hash, '')));
  v_old_guest public.guest_identities%rowtype;
  v_old_key text;
  v_new_key text;
begin
  if v_old !~ '^[a-f0-9]{64}$' or v_new !~ '^[a-f0-9]{64}$' or v_old = v_new then
    return jsonb_build_object('ok', false, 'errorCode', 'invalid_guest_token');
  end if;

  perform pg_advisory_xact_lock(hashtext('guest:' || v_old));

  select * into v_old_guest
  from public.guest_identities
  where guest_id_hash = v_old
  for update;

  if not found then
    return jsonb_build_object('ok', false, 'errorCode', 'unrecognized_guest_token');
  end if;

  if v_old_guest.superseded_by_hash is not null then
    return jsonb_build_object('ok', false, 'errorCode', 'token_already_rotated');
  end if;

  v_old_key := 'guest:' || v_old;
  v_new_key := 'guest:' || v_new;

  insert into public.guest_identities (
    guest_id_hash,
    rotated_from_hash,
    claimed_by_user_id,
    claimed_at,
    first_seen_at,
    last_seen_at
  )
  values (
    v_new,
    v_old,
    v_old_guest.claimed_by_user_id,
    v_old_guest.claimed_at,
    v_old_guest.first_seen_at,
    now()
  );

  update public.guest_identities
  set superseded_by_hash = v_new,
      last_seen_at = now()
  where guest_id_hash = v_old;

  insert into public.quota_accounts (
    account_key,
    owner_type,
    guest_id_hash,
    plan_tier,
    initial_grant_issued
  )
  values (
    v_new_key,
    'guest',
    v_new,
    'guest_trial',
    true
  );

  -- Move existing balance row without granting new credits
  insert into public.quota_balances (
    account_key,
    bucket,
    balance,
    lifetime_granted,
    lifetime_used,
    updated_at
  )
  select
    v_new_key,
    bucket,
    balance,
    lifetime_granted,
    lifetime_used,
    now()
  from public.quota_balances
  where account_key = v_old_key
  on conflict (account_key, bucket) do nothing;

  update public.quota_balances
  set balance = 0,
      updated_at = now()
  where account_key = v_old_key;

  return jsonb_build_object(
    'ok', true,
    'accountKey', v_new_key,
    'snapshot', public.get_quota_snapshot(v_new_key)
  );
end;
$$;

-- RPC 4: Atomic reserve check-and-deduct (prevents race overruns and negative balances)
create or replace function public.reserve_investigation_quota(
  p_account_key text,
  p_capability text,
  p_idempotency_key text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account public.quota_accounts%rowtype;
  v_bucket text;
  v_balance_row public.quota_balances%rowtype;
  v_existing_res public.quota_reservations%rowtype;
  v_res_id uuid;
  v_new_balance integer;
  v_idem text := nullif(trim(coalesce(p_idempotency_key, '')), '');
begin
  if p_capability not in ('message_analysis', 'document_scan', 'fact_check', 'url_investigation') then
    return jsonb_build_object('allowed', false, 'errorCode', 'invalid_capability');
  end if;

  select * into v_account
  from public.quota_accounts
  where account_key = p_account_key;

  if not found then
    return jsonb_build_object('allowed', false, 'errorCode', 'account_not_found');
  end if;

  if v_idem is not null then
    select * into v_existing_res
    from public.quota_reservations
    where account_key = p_account_key
      and idempotency_key = v_idem;

    if found then
      return jsonb_build_object(
        'allowed', true,
        'idempotent', true,
        'reservationId', v_existing_res.id,
        'bucket', v_existing_res.bucket,
        'snapshot', public.get_quota_snapshot(p_account_key)
      );
    end if;
  end if;

  v_bucket := case when v_account.owner_type = 'guest' then 'guest_shared' else p_capability end;

  select * into v_balance_row
  from public.quota_balances
  where account_key = p_account_key
    and bucket = v_bucket
  for update;

  if not found or v_balance_row.balance < 1 then
    return jsonb_build_object(
      'allowed', false,
      'errorCode', 'quota_exhausted',
      'bucket', v_bucket,
      'ownerType', v_account.owner_type,
      'snapshot', public.get_quota_snapshot(p_account_key)
    );
  end if;

  v_new_balance := v_balance_row.balance - 1;

  update public.quota_balances
  set balance = v_new_balance,
      lifetime_used = lifetime_used + 1,
      updated_at = now()
  where account_key = p_account_key
    and bucket = v_bucket;

  insert into public.quota_reservations (
    account_key,
    bucket,
    capability,
    amount,
    status,
    idempotency_key
  )
  values (
    p_account_key,
    v_bucket,
    p_capability,
    1,
    'reserved',
    v_idem
  )
  returning id into v_res_id;

  insert into public.quota_ledger (
    account_key,
    bucket,
    capability,
    delta,
    balance_after,
    entry_type,
    reservation_id,
    metadata
  )
  values (
    p_account_key,
    v_bucket,
    p_capability,
    -1,
    v_new_balance,
    'consume_reserve',
    v_res_id,
    jsonb_build_object('ownerType', v_account.owner_type)
  );

  return jsonb_build_object(
    'allowed', true,
    'idempotent', false,
    'reservationId', v_res_id,
    'bucket', v_bucket,
    'snapshot', public.get_quota_snapshot(p_account_key)
  );
end;
$$;

-- RPC 5: Idempotent finalize (commit or single-use refund on downstream failure)
create or replace function public.finalize_investigation_quota(
  p_reservation_id uuid,
  p_outcome text,
  p_reason text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_res public.quota_reservations%rowtype;
  v_new_balance integer;
begin
  if p_reservation_id is null or p_outcome not in ('commit', 'refund') then
    return jsonb_build_object('ok', false, 'errorCode', 'invalid_finalize_args');
  end if;

  select * into v_res
  from public.quota_reservations
  where id = p_reservation_id
  for update;

  if not found then
    return jsonb_build_object('ok', false, 'errorCode', 'reservation_not_found');
  end if;

  -- Strictly idempotent: already committed or refunded reservations cannot be re-refunded or re-charged
  if v_res.status <> 'reserved' then
    return jsonb_build_object(
      'ok', true,
      'alreadyResolved', true,
      'status', v_res.status,
      'snapshot', public.get_quota_snapshot(v_res.account_key)
    );
  end if;

  if p_outcome = 'commit' then
    update public.quota_reservations
    set status = 'committed',
        resolved_at = now()
    where id = p_reservation_id;

    return jsonb_build_object(
      'ok', true,
      'alreadyResolved', false,
      'status', 'committed',
      'snapshot', public.get_quota_snapshot(v_res.account_key)
    );
  end if;

  -- Refund path: restore exactly once inside the transaction lock
  update public.quota_reservations
  set status = 'refunded',
      failure_reason = left(coalesce(p_reason, 'downstream_failure'), 240),
      resolved_at = now()
  where id = p_reservation_id;

  update public.quota_balances
  set balance = balance + v_res.amount,
      lifetime_used = greatest(0, lifetime_used - v_res.amount),
      updated_at = now()
  where account_key = v_res.account_key
    and bucket = v_res.bucket
  returning balance into v_new_balance;

  insert into public.quota_ledger (
    account_key,
    bucket,
    capability,
    delta,
    balance_after,
    entry_type,
    reservation_id,
    metadata
  )
  values (
    v_res.account_key,
    v_res.bucket,
    v_res.capability,
    v_res.amount,
    coalesce(v_new_balance, v_res.amount),
    'refund',
    v_res.id,
    jsonb_build_object('reason', left(coalesce(p_reason, 'downstream_failure'), 160))
  );

  return jsonb_build_object(
    'ok', true,
    'alreadyResolved', false,
    'status', 'refunded',
    'snapshot', public.get_quota_snapshot(v_res.account_key)
  );
end;
$$;

-- Restrict RPC execution strictly to server-side service_role
revoke all on function public.get_quota_snapshot(text) from public, anon, authenticated;
revoke all on function public.ensure_guest_quota(text, integer, boolean) from public, anon, authenticated;
revoke all on function public.ensure_user_quota(uuid, text) from public, anon, authenticated;
revoke all on function public.rotate_guest_identity(text, text) from public, anon, authenticated;
revoke all on function public.reserve_investigation_quota(text, text, text) from public, anon, authenticated;
revoke all on function public.finalize_investigation_quota(uuid, text, text) from public, anon, authenticated;

grant execute on function public.get_quota_snapshot(text) to service_role;
grant execute on function public.ensure_guest_quota(text, integer, boolean) to service_role;
grant execute on function public.ensure_user_quota(uuid, text) to service_role;
grant execute on function public.rotate_guest_identity(text, text) to service_role;
grant execute on function public.reserve_investigation_quota(text, text, text) to service_role;
grant execute on function public.finalize_investigation_quota(uuid, text, text) to service_role;
