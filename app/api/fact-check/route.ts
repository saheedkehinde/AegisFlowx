import { NextRequest, NextResponse } from 'next/server';
import { generateFactCheckReport } from '@/lib/fact-checker/fact-checker';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
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

    // Generate evidence-based fact-checking report
    const report = await generateFactCheckReport(text.trim(), context);

    // Save to Supabase private investigation history if user is authenticated
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
