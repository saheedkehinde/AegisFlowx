/**
 * Backward-compatible normalization and filtering helpers for saved Investigation
 * Vault records (`public.analysis_history`) and guest `sessionStorage` records.
 */

export interface NormalizedThreatIndicator {
  name: string;
  evidence: string;
  reason: string;
}

export type CanonicalInputType =
  | 'message'
  | 'url_investigation'
  | 'document'
  | 'screenshot'
  | 'fact_check'
  | 'unknown';

export type CanonicalThreatSeverity = 'high' | 'medium' | 'low' | 'uncertain';

export interface NormalizedAnalysisHistoryRecord {
  id: string;
  user_id: string;
  input_type: CanonicalInputType;
  input_snippet: string;
  threat_severity: CanonicalThreatSeverity;
  severity_score: number;
  summary: string;
  indicators: NormalizedThreatIndicator[];
  recommended_actions: string[];
  limitations: string[];
  evidence_sufficiency: 'sufficient' | 'moderate' | 'sparse';
  model_confidence: 'high' | 'moderate' | 'low';
  confidence_rationale?: string;
  model_name?: string;
  iocs?: {
    urls?: string[];
    emails?: string[];
    phoneNumbers?: string[];
    keywords?: string[];
    documentContent?: {
      detectedType?: string;
      extractedTextSnippet?: string;
      apparentSenderOrOrganization?: string;
      claimedPurpose?: string;
      filename?: string;
      fileSizeBytes?: number;
      mimeType?: string;
      pageCount?: number;
    };
    suspiciousElements?: Array<{
      category: string;
      evidence: string;
      explanation: string;
    }>;
    verificationStatus?: {
      independentlyVerified?: string[];
      unverifiedClaims?: string[];
    };
    factCheckReport?: any;
    [key: string]: any;
  };
  created_at: string;
}

function asNonEmptyString(val: unknown): string {
  return typeof val === 'string' ? val.trim() : '';
}

function asStringArray(val: unknown): string[] {
  if (!Array.isArray(val)) return [];
  return val
    .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    .map((item) => item.trim());
}

/**
 * Normalizes any raw threat indicator payload (`string[]`, `{ name, evidence, reason }[]`,
 * `UrlIndicatorItem[]`, partial objects, or malformed entries) into structured
 * `{ name, evidence, reason }[]` objects without throwing or inventing missing details.
 */
export function normalizeIndicators(raw: unknown): NormalizedThreatIndicator[] {
  if (!Array.isArray(raw)) {
    return [];
  }

  const normalized: NormalizedThreatIndicator[] = [];

  for (const item of raw) {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      if (!trimmed) continue;

      // Support legacy URL Investigation strings formatted as "[CATEGORY] Title: Description"
      const legacyUrlMatch = trimmed.match(/^(\[[A-Za-z0-9_\s-]+\]\s+[^:\n]+):\s*([\s\S]*)$/);
      if (legacyUrlMatch) {
        normalized.push({
          name: legacyUrlMatch[1].trim(),
          evidence: '',
          reason: legacyUrlMatch[2].trim(),
        });
      } else {
        normalized.push({
          name: trimmed,
          evidence: '',
          reason: '',
        });
      }
      continue;
    }

    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const obj = item as Record<string, unknown>;

      const explicitName = asNonEmptyString(obj.name);
      const title = asNonEmptyString(obj.title);
      const category = asNonEmptyString(obj.category);
      const label = asNonEmptyString(obj.label);

      let resolvedName = explicitName;
      if (!resolvedName && title) {
        resolvedName = category ? `[${category.toUpperCase()}] ${title}` : title;
      } else if (!resolvedName && label) {
        resolvedName = label;
      } else if (!resolvedName && category) {
        resolvedName = category;
      }

      const evidence = asNonEmptyString(obj.evidence);
      const reason =
        asNonEmptyString(obj.reason) ||
        asNonEmptyString(obj.description) ||
        asNonEmptyString(obj.explanation);

      if (!resolvedName && !evidence && !reason) {
        continue;
      }

      normalized.push({
        name: resolvedName || 'Threat Indicator',
        evidence,
        reason,
      });
    }
  }

  return normalized;
}

/**
 * Safely extracts the primary display/search snippet from DB, guest, or legacy records.
 */
export function resolveRecordMessageText(record: unknown): string {
  if (!record || typeof record !== 'object') return '';
  const obj = record as Record<string, unknown>;

  const candidates = [
    obj.input_snippet,
    obj.snippet,
    obj.message,
    obj.text,
    obj.raw_text,
    obj.content,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }

  return '';
}

/**
 * Safely extracts the summary field from DB, guest, or legacy records.
 */
export function resolveRecordSummary(record: unknown): string {
  if (!record || typeof record !== 'object') return '';
  const obj = record as Record<string, unknown>;

  const candidates = [obj.summary, obj.executiveSummary];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }

  return '';
}

export interface InputTypeHints {
  snippet?: unknown;
  model?: unknown;
  iocs?: unknown;
}

function inferTypeFromDocumentMeta(
  mimeType: unknown,
  filename: unknown,
  snippet: string
): CanonicalInputType | null {
  const mime = typeof mimeType === 'string' ? mimeType.toLowerCase() : '';
  const file = typeof filename === 'string' ? filename.toLowerCase() : '';

  if (mime.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/.test(file)) {
    return 'screenshot';
  }
  if (mime.includes('pdf') || /\.(pdf|docx?|txt)$/.test(file)) {
    return 'document';
  }
  if (/^\[(PNG|JPG|JPEG|WEBP|IMAGE|SCREENSHOT)[:\]]/i.test(snippet)) {
    return 'screenshot';
  }
  if (/^\[(PDF|DOC|DOCUMENT)[:\]]/i.test(snippet)) {
    return 'document';
  }
  return null;
}

/**
 * Maps current and legacy `input_type` / `inputType` / `type` values plus optional
 * record hints to a canonical application input type.
 */
export function normalizeInputType(
  rawType: unknown,
  hints?: InputTypeHints
): CanonicalInputType {
  const rawStr = typeof rawType === 'string' ? rawType.trim().toLowerCase() : '';

  if (rawStr) {
    if (
      rawStr === 'message' ||
      rawStr === 'text' ||
      rawStr === 'msg' ||
      rawStr === 'sms' ||
      rawStr === 'email'
    ) {
      return 'message';
    }
    if (rawStr === 'url_investigation' || rawStr === 'url' || rawStr === 'link') {
      return 'url_investigation';
    }
    if (rawStr === 'document' || rawStr === 'doc' || rawStr === 'pdf' || rawStr === 'file') {
      return 'document';
    }
    if (
      rawStr === 'screenshot' ||
      rawStr === 'image' ||
      rawStr === 'img' ||
      rawStr === 'png' ||
      rawStr === 'jpg' ||
      rawStr === 'jpeg' ||
      rawStr === 'webp'
    ) {
      return 'screenshot';
    }
    if (rawStr === 'fact_check' || rawStr === 'factcheck' || rawStr === 'fact-check') {
      return 'fact_check';
    }
    if (rawStr === 'unknown') {
      return 'unknown';
    }
  }

  const snippet = typeof hints?.snippet === 'string' ? hints.snippet.trim() : '';
  const iocsObj =
    hints?.iocs && typeof hints.iocs === 'object'
      ? (hints.iocs as Record<string, unknown>)
      : null;

  if (iocsObj?.factCheckReport) {
    return 'fact_check';
  }

  if (iocsObj?.documentContent && typeof iocsObj.documentContent === 'object') {
    const docMeta = iocsObj.documentContent as Record<string, unknown>;
    return inferTypeFromDocumentMeta(docMeta.mimeType, docMeta.filename, snippet) || 'document';
  }

  if (iocsObj?.urlComponents) {
    return 'url_investigation';
  }

  if (snippet) {
    if (snippet.startsWith('[URL]')) {
      return 'url_investigation';
    }
    if (snippet.startsWith('[Fact-Check]')) {
      return 'fact_check';
    }
    const docHint = inferTypeFromDocumentMeta(undefined, undefined, snippet);
    if (docHint) {
      return docHint;
    }
    // Support legacy guest document snippets like "[invoice.pdf] ..." or "[capture.png] ..."
    const bracketFileMatch = snippet.match(/^\[([^\]]+)\]/);
    if (bracketFileMatch) {
      const fileHint = inferTypeFromDocumentMeta(undefined, bracketFileMatch[1], snippet);
      if (fileHint) {
        return fileHint;
      }
    }
  }

  if (typeof hints?.model === 'string' && hints.model.toLowerCase().includes('url')) {
    return 'url_investigation';
  }

  if (rawStr) {
    return 'unknown';
  }

  // Legacy empty/null input_type with ordinary text snippet resolves safely as 'message'
  if (snippet) {
    return 'message';
  }

  return 'unknown';
}

function getRecordInputType(record: unknown): CanonicalInputType {
  if (!record || typeof record !== 'object') return 'unknown';
  const obj = record as Record<string, unknown>;
  const snippet = resolveRecordMessageText(obj);
  return normalizeInputType(obj.input_type ?? obj.inputType ?? obj.type, {
    snippet,
    model: obj.model_name ?? obj.model,
    iocs: obj.iocs,
  });
}

function getRecordSeverity(record: unknown): CanonicalThreatSeverity {
  if (!record || typeof record !== 'object') return 'uncertain';
  const obj = record as Record<string, unknown>;
  const raw = asNonEmptyString(obj.threat_severity ?? obj.riskLevel).toLowerCase();
  if (raw === 'high') return 'high';
  if (raw === 'medium') return 'medium';
  if (raw === 'low' || raw === 'safe') return 'low';
  return 'uncertain';
}

/**
 * Filter matcher for Investigation Vault (`/investigations`) source-type tabs.
 */
export function matchesVaultTypeFilter(record: unknown, selectedType: string): boolean {
  const normalizedFilter = asNonEmptyString(selectedType).toLowerCase();
  if (!normalizedFilter || normalizedFilter === 'all') {
    return true;
  }

  const targetType: CanonicalInputType =
    normalizedFilter === 'text'
      ? 'message'
      : normalizedFilter === 'url'
      ? 'url_investigation'
      : normalizeInputType(normalizedFilter);

  const recordType = getRecordInputType(record);
  return recordType === targetType;
}

/**
 * Filter matcher for Dashboard (`RecentInvestigations`) segmented tabs.
 */
export function matchesDashboardFilter(record: unknown, filterType: string): boolean {
  const normalizedFilter = asNonEmptyString(filterType).toLowerCase();
  if (!normalizedFilter || normalizedFilter === 'all') {
    return true;
  }
  if (normalizedFilter === 'high') {
    return getRecordSeverity(record) === 'high';
  }

  const recordType = getRecordInputType(record);
  if (normalizedFilter === 'url' || normalizedFilter === 'url_investigation') {
    return recordType === 'url_investigation';
  }
  if (normalizedFilter === 'message' || normalizedFilter === 'text') {
    return recordType === 'message';
  }
  if (normalizedFilter === 'document') {
    return recordType === 'document' || recordType === 'screenshot';
  }

  return recordType === normalizedFilter;
}

/**
 * Crash-safe full-text search matcher for Investigation Vault records.
 */
export function matchesVaultSearchQuery(record: unknown, searchQuery: string): boolean {
  const q = typeof searchQuery === 'string' ? searchQuery.toLowerCase().trim() : '';
  if (!q) return true;
  if (!record || typeof record !== 'object') return false;

  const obj = record as Record<string, unknown>;

  if (resolveRecordMessageText(obj).toLowerCase().includes(q)) return true;
  if (resolveRecordSummary(obj).toLowerCase().includes(q)) return true;

  const indicators = normalizeIndicators(obj.indicators);
  if (
    indicators.some(
      (ind) =>
        ind.name.toLowerCase().includes(q) ||
        ind.evidence.toLowerCase().includes(q) ||
        ind.reason.toLowerCase().includes(q)
    )
  ) {
    return true;
  }

  if (obj.iocs && typeof obj.iocs === 'object') {
    const iocs = obj.iocs as Record<string, unknown>;
    const iocLists = [iocs.urls, iocs.emails, iocs.phoneNumbers, iocs.keywords];
    for (const list of iocLists) {
      if (
        Array.isArray(list) &&
        list.some((val) => typeof val === 'string' && val.toLowerCase().includes(q))
      ) {
        return true;
      }
    }
    if (iocs.documentContent && typeof iocs.documentContent === 'object') {
      const filename = (iocs.documentContent as Record<string, unknown>).filename;
      if (typeof filename === 'string' && filename.toLowerCase().includes(q)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Normalizes a raw `public.analysis_history` database row into a safe, strongly typed
 * structure for Investigation Vault UI rendering and filtering.
 */
export function normalizeAnalysisHistoryRecord(
  rawRecord: unknown
): NormalizedAnalysisHistoryRecord | null {
  if (!rawRecord || typeof rawRecord !== 'object' || Array.isArray(rawRecord)) {
    return null;
  }

  const obj = rawRecord as Record<string, unknown>;
  const snippet = resolveRecordMessageText(obj);
  const summary = resolveRecordSummary(obj);
  const inputType = normalizeInputType(obj.input_type ?? obj.inputType ?? obj.type, {
    snippet,
    model: obj.model_name ?? obj.model,
    iocs: obj.iocs,
  });

  const rawScore = Number(obj.severity_score);
  const severityScore = Number.isFinite(rawScore)
    ? Math.max(0, Math.min(100, Math.round(rawScore)))
    : 50;

  const rawSufficiency = asNonEmptyString(obj.evidence_sufficiency).toLowerCase();
  const evidenceSufficiency: 'sufficient' | 'moderate' | 'sparse' =
    rawSufficiency === 'sufficient' || rawSufficiency === 'sparse'
      ? rawSufficiency
      : 'moderate';

  const rawConfidence = asNonEmptyString(obj.model_confidence).toLowerCase();
  const modelConfidence: 'high' | 'moderate' | 'low' =
    rawConfidence === 'high' || rawConfidence === 'low' ? rawConfidence : 'moderate';

  return {
    id: asNonEmptyString(obj.id) || `record-${Date.now()}`,
    user_id: asNonEmptyString(obj.user_id),
    input_type: inputType,
    input_snippet: snippet,
    threat_severity: getRecordSeverity(obj),
    severity_score: severityScore,
    summary,
    indicators: normalizeIndicators(obj.indicators),
    recommended_actions: asStringArray(obj.recommended_actions),
    limitations: asStringArray(obj.limitations),
    evidence_sufficiency: evidenceSufficiency,
    model_confidence: modelConfidence,
    confidence_rationale: asNonEmptyString(obj.confidence_rationale) || undefined,
    model_name: asNonEmptyString(obj.model_name) || undefined,
    iocs:
      obj.iocs && typeof obj.iocs === 'object' && !Array.isArray(obj.iocs)
        ? (obj.iocs as NormalizedAnalysisHistoryRecord['iocs'])
        : undefined,
    created_at: asNonEmptyString(obj.created_at),
  };
}
