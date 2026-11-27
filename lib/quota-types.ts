export type QuotaCapability =
  | 'message_analysis'
  | 'document_scan'
  | 'fact_check'
  | 'url_investigation';

export type QuotaBucket = 'guest_shared' | QuotaCapability;

export type QuotaOwnerType = 'guest' | 'user';

export type QuotaPlanTier = 'guest_trial' | 'free' | 'pro' | 'business';

export type QuotaErrorCode =
  | 'quota_exhausted'
  | 'invalid_guest_token'
  | 'email_verification_required'
  | 'quota_service_unavailable';

export const GUEST_INITIAL_SHARED_CREDITS = 12;
export const USER_INITIAL_CAPABILITY_CREDITS = 5;

export const CAPABILITY_LABELS: Record<QuotaCapability, string> = {
  message_analysis: 'Message Analysis',
  document_scan: 'Document & Screenshot Scan',
  fact_check: 'Web Fact-Checking',
  url_investigation: 'URL Intelligence',
};

export interface QuotaBalancesByCapability {
  message_analysis: number;
  document_scan: number;
  fact_check: number;
  url_investigation: number;
}

export interface QuotaSnapshot {
  ownerType: QuotaOwnerType;
  planTier: QuotaPlanTier;
  nonRenewing: boolean;
  sharedRemaining: number | null;
  sharedLimit: number | null;
  balances: QuotaBalancesByCapability;
  perCapabilityLimit: number | null;
  totalRemaining: number;
  claimedByUser?: boolean;
}

export interface QuotaErrorPayload {
  error: string;
  errorCode: QuotaErrorCode;
  capability?: QuotaCapability;
  requiresRegistration?: boolean;
  requiresVerification?: boolean;
  quota?: QuotaSnapshot;
}

export function getRemainingForCapability(
  snapshot: QuotaSnapshot | null | undefined,
  capability: QuotaCapability
): number | null {
  if (!snapshot) return null;
  if (snapshot.ownerType === 'guest') {
    return typeof snapshot.sharedRemaining === 'number'
      ? snapshot.sharedRemaining
      : snapshot.balances[capability] ?? 0;
  }
  return snapshot.balances[capability] ?? 0;
}

export function isCapabilityExhausted(
  snapshot: QuotaSnapshot | null | undefined,
  capability: QuotaCapability
): boolean {
  const remaining = getRemainingForCapability(snapshot, capability);
  return remaining !== null && remaining <= 0;
}
