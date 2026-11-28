export type ClientAnalyzeErrorCategory =
  | 'general'
  | 'transport'
  | 'html_response'
  | 'timeout'
  | 'cancelled'
  | 'rate_limiter_unavailable'
  | 'rate_limit_exceeded'
  | 'quota_exhausted'
  | 'email_verification_required'
  | 'auth_failed';

export interface HttpTransportInspectionInput {
  status: number;
  type?: string;
  redirected?: boolean;
  contentType?: string | null;
  hasCorrelationId?: boolean;
  bodyText?: string;
  url?: string | null;
  durationMs?: number;
}

export interface HttpTransportAnomalyResult {
  anomaly: boolean;
  category?: 'html_response' | 'transport' | 'timeout';
  errorCode?:
    | 'unexpected_redirect'
    | 'gateway_timeout_html'
    | 'gateway_error_html'
    | 'unexpected_html_response'
    | 'empty_http_body';
  message?: string;
}

export interface ParsedAnalyzeJsonResult {
  ok: boolean;
  data: Record<string, unknown> | null;
  errorCode?: 'invalid_json_response';
  message?: string;
}

export interface FetchExceptionClassificationInput {
  err: unknown;
  didClientTimeout: boolean;
  didUserCancel: boolean;
  isOnline?: boolean;
  durationMs?: number;
  correlationId?: string;
}

export interface FetchExceptionClassification {
  category: 'cancelled' | 'timeout' | 'transport';
  errorCode:
    | 'user_cancelled'
    | 'client_timeout'
    | 'offline_network_error'
    | 'network_fetch_failed';
  message: string;
}

export interface SafeClientTransportLogMeta {
  correlationId: string;
  status?: number;
  type?: string;
  redirected?: boolean;
  contentType?: string | null;
  hasCorrelationId?: boolean;
  url?: string | null;
  durationMs?: number;
  category: ClientAnalyzeErrorCategory;
  errorCode?: string;
}

export function buildClientCorrelationId(seed?: string): string {
  if (seed) {
    const cleaned = seed.trim().replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 48);
    if (cleaned.length >= 6) {
      return cleaned;
    }
  }

  try {
    if (typeof globalThis !== 'undefined' && globalThis.crypto?.randomUUID) {
      return `cli-${globalThis.crypto.randomUUID().slice(0, 12)}`;
    }
  } catch {
    // Fallback below when randomUUID is unavailable
  }

  return `cli-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function sanitizeUrlPathOnly(rawUrl?: string | null): string {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return '/api/analyze';
  }
  const trimmed = rawUrl.trim();
  if (!trimmed) return '/api/analyze';
  try {
    const parsed = new URL(trimmed, 'https://localhost');
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      return `${parsed.origin}${parsed.pathname}`.slice(0, 120);
    }
    return parsed.pathname.slice(0, 120);
  } catch {
    return trimmed.split(/[?#]/)[0].slice(0, 120) || '/api/analyze';
  }
}

export function looksLikeHtmlPayload(bodyText?: string): boolean {
  if (!bodyText || typeof bodyText !== 'string') return false;
  const sample = bodyText.slice(0, 1024).trimStart().toLowerCase();
  return (
    sample.startsWith('<!doctype') ||
    sample.startsWith('<html') ||
    sample.includes('<!doctype html') ||
    sample.includes('<html') ||
    sample.includes('<head>') ||
    sample.includes('<body>')
  );
}

export function classifyHttpTransportAnomaly(
  input: HttpTransportInspectionInput
): HttpTransportAnomalyResult {
  const status = Number(input.status || 0);
  const contentType = (input.contentType || '').toLowerCase();
  const bodyText = typeof input.bodyText === 'string' ? input.bodyText : '';

  if (input.type === 'opaqueredirect' || (status >= 300 && status < 400)) {
    return {
      anomaly: true,
      category: 'transport',
      errorCode: 'unexpected_redirect',
      message:
        'The analysis request was unexpectedly redirected instead of reaching the API endpoint. Please refresh the page or check your network connection and retry.',
    };
  }

  const isHtml = contentType.includes('text/html') || looksLikeHtmlPayload(bodyText);
  if (isHtml) {
    if (status === 504) {
      return {
        anomaly: true,
        category: 'timeout',
        errorCode: 'gateway_timeout_html',
        message:
          'Gateway timeout (HTTP 504). Upstream analysis took too long to respond. Please retry in a moment.',
      };
    }

    if (status === 500 || status === 502 || status === 503) {
      return {
        anomaly: true,
        category: 'html_response',
        errorCode: 'gateway_error_html',
        message: `Server gateway error (HTTP ${status}). The AI analysis service is temporarily restarting or unavailable. Please retry in a moment.`,
      };
    }

    const viaIntermediary = input.redirected || input.hasCorrelationId === false;
    return {
      anomaly: true,
      category: 'html_response',
      errorCode: 'unexpected_html_response',
      message: viaIntermediary
        ? `Received an HTML page instead of an analysis response (HTTP ${status || 200}), likely due to a network proxy, security challenge, or session redirect. Please refresh or retry.`
        : `Server returned an unexpected HTML response (HTTP ${status || 200}). Please check your connection or retry.`,
    };
  }

  if (!bodyText.trim()) {
    return {
      anomaly: true,
      category: 'transport',
      errorCode: 'empty_http_body',
      message:
        status >= 500
          ? `Server returned an empty error response (HTTP ${status}). Please retry in a moment.`
          : `Received an empty response from the server (HTTP ${status || 0}). Please check your connection and retry.`,
    };
  }

  return { anomaly: false };
}

export function parseAnalyzeJsonBody(
  rawText: string,
  contentType: string | null | undefined,
  status: number
): ParsedAnalyzeJsonResult {
  try {
    const parsed = JSON.parse(rawText);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { ok: true, data: parsed as Record<string, unknown> };
    }
    return {
      ok: false,
      data: null,
      errorCode: 'invalid_json_response',
      message: `Server returned an unexpected response structure (HTTP ${status}). Please retry.`,
    };
  } catch {
    const ct = (contentType || '').toLowerCase();
    return {
      ok: false,
      data: null,
      errorCode: 'invalid_json_response',
      message: ct.includes('application/json')
        ? `Received an incomplete or malformed JSON response from the server (HTTP ${status}). Please retry.`
        : `Server returned a non-JSON response (HTTP ${status}). Please check your connection and retry.`,
    };
  }
}

export function classifyFetchException(
  input: FetchExceptionClassificationInput
): FetchExceptionClassification {
  if (input.didUserCancel) {
    return {
      category: 'cancelled',
      errorCode: 'user_cancelled',
      message: 'Analysis cancelled. No quota credit was consumed.',
    };
  }

  const errName = input.err instanceof Error ? input.err.name : '';
  const errMsg = input.err instanceof Error ? input.err.message : String(input.err || '');
  const lowerMsg = errMsg.toLowerCase();

  if (
    input.didClientTimeout ||
    errName === 'TimeoutError' ||
    errName === 'AbortError' ||
    lowerMsg.includes('aborted') ||
    lowerMsg.includes('timed out')
  ) {
    return {
      category: 'timeout',
      errorCode: 'client_timeout',
      message: 'Analysis timed out awaiting a response. No quota credit was consumed — please retry.',
    };
  }

  if (input.isOnline === false) {
    return {
      category: 'transport',
      errorCode: 'offline_network_error',
      message:
        'Unable to reach the analysis service because your browser appears offline. Check your connection and retry.',
    };
  }

  return {
    category: 'transport',
    errorCode: 'network_fetch_failed',
    message:
      'Unable to reach the analysis service (network request was interrupted before receiving a response). Please check your connection and retry.',
  };
}

export function emitSafeClientTransportLog(meta: SafeClientTransportLogMeta): void {
  try {
    const safePayload = {
      correlationId: String(meta.correlationId || 'unknown').slice(0, 64),
      status: typeof meta.status === 'number' ? meta.status : undefined,
      type: meta.type ? String(meta.type).slice(0, 32) : undefined,
      redirected: Boolean(meta.redirected),
      contentType: meta.contentType ? String(meta.contentType).split(';')[0].slice(0, 48) : undefined,
      hasCorrelationId: Boolean(meta.hasCorrelationId),
      path: sanitizeUrlPathOnly(meta.url),
      durationMs:
        typeof meta.durationMs === 'number' && Number.isFinite(meta.durationMs)
          ? Math.max(0, Math.round(meta.durationMs))
          : undefined,
      category: meta.category,
      errorCode: meta.errorCode ? String(meta.errorCode).slice(0, 48) : undefined,
    };
    console.warn(`[AegisTransport] ${JSON.stringify(safePayload)}`);
  } catch {
    // Telemetry failures must never impact UI handling
  }
}
