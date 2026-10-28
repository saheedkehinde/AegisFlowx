import { NextRequest, NextResponse } from 'next/server';
import {
  validateAndNormalizeUrl,
  screenUrlForSsrf,
  investigateUrl,
} from '@/lib/url-investigation/investigator';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';
import { redactSecrets } from '@/lib/model-config';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// Server-side rolling window rate limiting
// NOTE (Serverless Architecture Limitation): This in-memory Map provides process-local rate limiting
// for single-instance / development setups. In multi-instance or edge serverless deployments (e.g. Vercel),
// state is not shared across isolated serverless lambdas. For distributed enforcement, an external store
// (such as Upstash Redis or Supabase RPC) can be configured; this process-local limiter provides baseline abuse protection.
interface RateLimitBucket {
  count: number;
  resetAt: number;
}
const RATE_LIMIT_MAP = new Map<string, RateLimitBucket>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 20; // 20 analyses per client per minute

function checkClientRateLimit(clientId: string): { allowed: boolean; retryAfterSeconds: number } {
  const now = Date.now();
  const bucket = RATE_LIMIT_MAP.get(clientId);

  if (!bucket || now > bucket.resetAt) {
    RATE_LIMIT_MAP.set(clientId, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, retryAfterSeconds: 0 };
  }

  if (bucket.count >= MAX_REQUESTS_PER_WINDOW) {
    const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
    return { allowed: false, retryAfterSeconds: retryAfter };
  }

  bucket.count++;
  return { allowed: true, retryAfterSeconds: 0 };
}

export async function POST(req: NextRequest) {
  try {
    // 1. Identify client for server-side abuse prevention
    const forwardedFor = req.headers.get('x-forwarded-for') || '';
    const realIp = req.headers.get('x-real-ip') || '';
    const clientIp = (forwardedFor.split(',')[0] || realIp || '127.0.0.1').trim();

    const { allowed, retryAfterSeconds } = checkClientRateLimit(clientIp);
    if (!allowed) {
      return NextResponse.json(
        {
          error: `Rate limit reached for this IP. Please wait ${retryAfterSeconds} second(s) before screening another URL.`,
        },
        {
          status: 429,
          headers: {
            'Retry-After': String(retryAfterSeconds),
          },
        }
      );
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return NextResponse.json(
        { error: 'Invalid request payload. Expected JSON body with a "url" field.' },
        { status: 400 }
      );
    }

    const rawUrl = body.url ?? body.target ?? body.link ?? '';
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
      return NextResponse.json(
        { error: 'URL input cannot be empty. Please provide a link to investigate.' },
        { status: 400 }
      );
    }

    // 2. Authoritative Server-Side Syntax & Scheme Validation
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.isValid || !validation.parsedUrl) {
      return NextResponse.json(
        { error: validation.error || 'Invalid URL format provided.' },
        { status: 400 }
      );
    }

    // 3. Authoritative Server-Side SSRF Screening (Loopback, RFC1918, Cloud Metadata)
    const ssrfCheck = await screenUrlForSsrf(validation.parsedUrl);
    if (!ssrfCheck.safe) {
      return NextResponse.json(
        {
          error: `Investigation blocked by SSRF Security Safeguards: ${ssrfCheck.reason}`,
        },
        { status: 400 }
      );
    }

    // 4. Perform full URL Threat & Web Intelligence Pipeline
    const report = await investigateUrl(rawUrl);

    let savedToVault = false;

    // 5. Persist to Supabase Vault if user is authenticated
    try {
      const supabase = await createServerSupabaseClient();
      if (supabase) {
        const {
          data: { user },
          error: userError,
        } = await supabase.auth.getUser();

        if (user && !userError) {
          const targetSnippet = `[URL] ${report.urlComponents.displayUrl || report.urlComponents.rawUrl}`;
          const snippet = targetSnippet.slice(0, 140);

          const recentWindow = new Date(Date.now() - 10 * 60 * 1000).toISOString();
          const { data: existingRecords } = await supabase
            .from('analysis_history')
            .select('id')
            .eq('user_id', user.id)
            .eq('input_snippet', snippet)
            .gte('created_at', recentWindow)
            .limit(1);

          if (!existingRecords || existingRecords.length === 0) {
            await supabase.from('analysis_history').insert({
              user_id: user.id,
              input_type: 'url_investigation',
              input_snippet: snippet,
              threat_severity: report.overallSeverity,
              severity_score: report.severityScore,
              summary: report.executiveSummary,
              indicators: report.indicators.map((ind) => `[${ind.category.toUpperCase()}] ${ind.title}: ${ind.description}`),
              recommended_actions: [
                ...(report.recommendedActions?.forIndividuals || []),
                ...(report.recommendedActions?.forSecurityTeams || []),
                ...(report.recommendedActions?.forOrganizations || []),
              ],
              limitations: report.evidenceLimitations,
              evidence_sufficiency: report.webEvidence.length > 0 || report.threatIntel.length > 0 ? 'sufficient' : 'moderate',
              model_confidence: report.confidenceLevel,
              confidence_rationale: report.confidenceRationale,
              model_name: report.modelUsed,
              iocs: {
                urls: [report.urlComponents.normalizedUrl],
                emails: [],
                phoneNumbers: [],
                keywords: [report.urlComponents.hostname, report.urlComponents.domain],
                threatIntel: report.threatIntel,
                domainIntelligence: report.domainIntelligence,
                urlComponents: report.urlComponents,
              },
            });
            savedToVault = true;
          } else {
            savedToVault = true;
          }
        }
      }
    } catch (dbErr: any) {
      console.warn('Non-fatal error persisting URL investigation to Supabase vault:', dbErr?.message);
    }

    report.savedToVault = savedToVault;

    // Final safety sanitation: ensure zero API keys or credentials exist in payload
    const safeReportJson = redactSecrets(JSON.stringify(report));
    const safeReport = JSON.parse(safeReportJson);

    return NextResponse.json({ report: safeReport, savedToVault });
  } catch (err: any) {
    console.error('Unhandled error during URL investigation:', err);
    return NextResponse.json(
      { error: err?.message || 'An unexpected error occurred during URL intelligence screening.' },
      { status: 500 }
    );
  }
}
