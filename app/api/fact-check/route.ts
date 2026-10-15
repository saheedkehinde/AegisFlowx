import { NextRequest, NextResponse } from 'next/server';
import { generateFactCheckReport } from '@/lib/fact-checker/fact-checker';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';

export const dynamic = 'force-dynamic';

// Server-side rolling window rate limiting to prevent abuse of free allowances
interface RateLimitBucket {
  count: number;
  resetAt: number;
}
const RATE_LIMIT_MAP = new Map<string, RateLimitBucket>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 15; // 15 analyses per client per minute

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

    // Check rate limit on server side
    const { allowed, retryAfterSeconds } = checkClientRateLimit(clientIp);
    if (!allowed) {
      return NextResponse.json(
        {
          error: `Request limit reached for this IP. Please wait ${retryAfterSeconds} second(s) before submitting another analysis.`,
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
        { error: 'Invalid request payload. Expected JSON body with a "text" field.' },
        { status: 400 }
      );
    }

    const { text, context } = body;

    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return NextResponse.json(
        { error: 'Text cannot be empty. Please provide content to fact-check.' },
        { status: 400 }
      );
    }

    if (text.trim().length > 6000) {
      return NextResponse.json(
        { error: 'Submitted content exceeds 6,000 characters limit for web research.' },
        { status: 400 }
      );
    }

    // 2. Generate evidence-based fact-checking report with pre-search assessment
    const report = await generateFactCheckReport(text.trim(), context);

    // 3. Save to Supabase private investigation history if user is authenticated
    try {
      const supabase = await createServerSupabaseClient();
      if (supabase) {
        const {
          data: { user },
          error: userError,
        } = await supabase.auth.getUser();

        if (user && !userError) {
          const snippet = `[Fact-Check] ${text.slice(0, 140)}`;
          const hasContradictions = report.extractedClaims.some(
            (c) => c.verdict === 'contradicted'
          );

          await supabase.from('analysis_history').insert({
            user_id: user.id,
            input_type: 'fact_check',
            input_snippet: snippet,
            threat_severity: hasContradictions ? 'high' : 'medium',
            severity_score: hasContradictions ? 85 : 45,
            summary: report.executiveSummary,
            indicators: report.suspiciousIndicators,
            recommended_actions: report.recommendations.forIndividuals,
            limitations: report.researchLimitations,
            evidence_sufficiency: report.sources.length > 2 ? 'sufficient' : 'moderate',
            model_confidence: report.confidenceLevel,
            confidence_rationale: report.confidenceRationale,
            model_name: report.searchProviderUsed,
            iocs: {
              urls: report.sources.map((s) => s.url),
              emails: [],
              phoneNumbers: [],
              keywords: report.extractedClaims.map((c) => c.claimText.slice(0, 30)),
              factCheckReport: report,
            },
          });
        }
      }
    } catch (dbErr: any) {
      console.warn('Non-fatal error persisting fact check to history:', dbErr?.message);
    }

    return NextResponse.json({ report });
  } catch (err: any) {
    console.error('Unhandled error during fact-checking:', err);
    return NextResponse.json(
      { error: err?.message || 'An unexpected error occurred during web research fact-checking.' },
      { status: 500 }
    );
  }
}
