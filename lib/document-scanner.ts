import path from 'path';
import {
  ScamAnalysisResult,
  RiskLevel,
  EvidenceSufficiency,
  ModelConfidence,
  ThreatIndicator,
  ExtractedIOCs,
  extractIOCsFromMessage,
  calculateSeverityScore,
  detectBehavioralThreats,
  buildAudienceSafetyRecommendations,
  buildSeparatedAssessmentDimensions,
  determineAssessmentState,
  deriveRelevantActions,
  evaluateEvidenceAndConfidence,
  ASSESSMENT_STATE_LABELS,
} from '@/lib/scam-analyzer';

export interface DocumentContentMetadata {
  detectedType:
    | 'invoice'
    | 'login_prompt'
    | 'email'
    | 'sms_chat'
    | 'security_alert'
    | 'receipt'
    | 'contract'
    | 'unknown';
  extractedTextSnippet: string;
  apparentSenderOrOrganization?: string;
  claimedPurpose?: string;
  filename: string;
  fileSizeBytes: number;
  mimeType: string;
  pageCount?: number;
}

export interface SuspiciousElement {
  category:
    | 'impersonation'
    | 'urgency_coercion'
    | 'credential_harvesting'
    | 'financial_anomaly'
    | 'deceptive_url'
    | 'inconsistent_data';
  evidence: string;
  explanation: string;
}

export interface VerificationStatus {
  independentlyVerified: string[];
  unverifiedClaims: string[];
}

export type DocumentAnalysisMode = 'primary' | 'fallback';

export type DocumentScanErrorCode =
  | 'invalid_request'
  | 'invalid_file'
  | 'extraction_failed'
  | 'providers_unavailable'
  | 'provider_quota'
  | 'provider_timeout'
  | 'provider_auth';

export interface DocumentScanResult extends ScamAnalysisResult {
  inputType: 'document' | 'screenshot';
  documentContent: DocumentContentMetadata;
  suspiciousElements: SuspiciousElement[];
  verificationStatus: VerificationStatus;
  analysisMode?: DocumentAnalysisMode;
  statusNotice?: string;
}

export const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB
export const MAX_PDF_PAGES = 25;

export type SupportedFileType = 'pdf' | 'png' | 'jpeg' | 'webp';

export interface FileValidationResult {
  isValid: boolean;
  error?: string;
  fileType?: SupportedFileType;
  mimeType?: string;
  sanitizedFilename: string;
  sizeBytes: number;
}

const ALLOWED_EXTENSIONS: Record<SupportedFileType, string[]> = {
  pdf: ['.pdf'],
  png: ['.png'],
  jpeg: ['.jpg', '.jpeg'],
  webp: ['.webp'],
};

const ALL_ALLOWED_EXTENSIONS = new Set(['.pdf', '.png', '.jpg', '.jpeg', '.webp']);

function isDeclaredMimeCompatible(declaredMimeType: string, expectedMimeType: string): boolean {
  const normalized = (declaredMimeType || '').split(';')[0].trim().toLowerCase();
  if (!normalized || normalized === 'application/octet-stream') {
    return true;
  }
  if (expectedMimeType === 'image/jpeg' && normalized === 'image/jpg') {
    return true;
  }
  return normalized === expectedMimeType;
}

function isFilenameExtensionCompatible(sanitizedFilename: string, detectedType: SupportedFileType): boolean {
  const ext = path.extname(sanitizedFilename).toLowerCase();
  if (!ext) {
    return true;
  }
  if (!ALL_ALLOWED_EXTENSIONS.has(ext)) {
    return false;
  }
  return ALLOWED_EXTENSIONS[detectedType].includes(ext);
}

export function validateUploadedFileBuffer(
  buffer: Buffer,
  rawFilename: string,
  declaredMimeType: string
): FileValidationResult {
  const sanitizedFilename = (rawFilename || 'uploaded_document')
    .replace(/[/\\?%*:|"<>]/g, '_')
    .replace(/\s+/g, '_')
    .slice(0, 100);

  const sizeBytes = buffer.length;

  if (sizeBytes === 0) {
    return {
      isValid: false,
      error: 'The uploaded file is empty (0 bytes). Please upload a valid document or image.',
      sanitizedFilename,
      sizeBytes,
    };
  }

  if (sizeBytes > MAX_FILE_SIZE_BYTES) {
    return {
      isValid: false,
      error: `File size (${(sizeBytes / (1024 * 1024)).toFixed(1)}MB) exceeds the maximum limit of 10MB. Please upload a smaller document.`,
      sanitizedFilename,
      sizeBytes,
    };
  }

  let detected: { fileType: SupportedFileType; mimeType: string } | null = null;

  // Magic bytes check
  // PDF: %PDF- (0x25 0x50 0x44 0x46 0x2D)
  if (
    buffer.length >= 5 &&
    buffer[0] === 0x25 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x44 &&
    buffer[3] === 0x46 &&
    buffer[4] === 0x2d
  ) {
    detected = { fileType: 'pdf', mimeType: 'application/pdf' };
  } else if (
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    detected = { fileType: 'png', mimeType: 'image/png' };
  } else if (
    // JPEG / JPG: FF D8 FF
    buffer.length >= 3 &&
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    detected = { fileType: 'jpeg', mimeType: 'image/jpeg' };
  } else if (
    // WebP: 52 49 46 46 (RIFF) ... 57 45 42 50 (WEBP)
    buffer.length >= 12 &&
    buffer[0] === 0x52 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x46 &&
    buffer[8] === 0x57 &&
    buffer[9] === 0x45 &&
    buffer[10] === 0x42 &&
    buffer[11] === 0x50
  ) {
    detected = { fileType: 'webp', mimeType: 'image/webp' };
  }

  if (!detected) {
    return {
      isValid: false,
      error: `Unsupported file format (${declaredMimeType || 'unknown'}). Only PDF documents (.pdf) and images (.png, .jpg, .jpeg, .webp) are supported.`,
      sanitizedFilename,
      sizeBytes,
    };
  }

  if (!isFilenameExtensionCompatible(sanitizedFilename, detected.fileType)) {
    return {
      isValid: false,
      error: `File extension for "${sanitizedFilename}" does not match the detected ${detected.fileType.toUpperCase()} content signature.`,
      sanitizedFilename,
      sizeBytes,
    };
  }

  if (!isDeclaredMimeCompatible(declaredMimeType, detected.mimeType)) {
    return {
      isValid: false,
      error: `Declared MIME type (${declaredMimeType}) does not match the detected ${detected.mimeType} signature.`,
      sanitizedFilename,
      sizeBytes,
    };
  }

  return {
    isValid: true,
    fileType: detected.fileType,
    mimeType: detected.mimeType,
    sanitizedFilename,
    sizeBytes,
  };
}

export function extractFallbackPdfText(buffer: Buffer): string {
  const content = buffer.toString('latin1');
  const textMatches: string[] = [];
  const tjRegex = /\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*Tj/g;
  let match: RegExpExecArray | null;
  while ((match = tjRegex.exec(content)) !== null) {
    if (match[1]) {
      const unescaped = match[1]
        .replace(/\\([()\\])/g, '$1')
        .replace(/\\r/g, '\r')
        .replace(/\\n/g, '\n');
      textMatches.push(unescaped);
    }
  }
  return textMatches.join(' ').trim();
}

export async function extractTextFromPdf(buffer: Buffer): Promise<{
  text: string;
  pageCount: number;
  metadata?: any;
}> {
  const streamText = extractFallbackPdfText(buffer);

  // Check if PDF exceeds safe page threshold via full parser first
  try {
    const pdfParseModule = require('pdf-parse');
    const PDFParse = pdfParseModule.PDFParse;

    if (typeof PDFParse === 'function') {
      if (typeof PDFParse.setWorker === 'function') {
        try {
          const workerPath = path.join(
            process.cwd(),
            'node_modules/pdf-parse/dist/pdf-parse/cjs/pdf.worker.mjs'
          );
          PDFParse.setWorker(workerPath);
        } catch {
          // Ignore worker initialization warnings
        }
      }

      const parser = new PDFParse({ data: buffer });
      await parser.load();
      const textResult = await parser.getText();
      const rawText = (textResult?.text || '').trim();
      const pageCount = textResult?.total || 1;

      if (pageCount > MAX_PDF_PAGES) {
        throw new Error(
          `PDF contains ${pageCount} pages, exceeding the ${MAX_PDF_PAGES} page limit. Please upload a smaller document.`
        );
      }

      if (rawText.length > 0) {
        return {
          text: rawText,
          pageCount,
        };
      }

      if (streamText.length > 0) {
        return {
          text: streamText,
          pageCount,
        };
      }

      return {
        text: '',
        pageCount,
      };
    }
  } catch (err: any) {
    const msg = String(err?.message || '');
    if (msg.includes('exceeding the') && msg.includes('page limit')) {
      throw err;
    }
    if (err?.name === 'PasswordException' || msg.toLowerCase().includes('password')) {
      throw new Error('This PDF is password-protected or encrypted. Please provide an unlocked document.');
    }

    // Synthetic/minimal PDFs with valid %%EOF and extracted Tj streams can use stream fallback cleanly
    const rawLatin = buffer.toString('latin1');
    const hasEofAndObjects = rawLatin.includes('endobj') && rawLatin.includes('%%EOF');
    const approxPageCount = Math.max(1, (rawLatin.match(/\/Type\s*\/Page\b/g) || []).length);
    if (approxPageCount > MAX_PDF_PAGES) {
      throw new Error(
        `PDF contains ${approxPageCount} pages, exceeding the ${MAX_PDF_PAGES} page limit. Please upload a smaller document.`
      );
    }

    if (streamText.length > 20 && hasEofAndObjects) {
      return {
        text: streamText,
        pageCount: approxPageCount,
      };
    }

    if (
      err?.name === 'InvalidPDFException' ||
      msg.toLowerCase().includes('invalid pdf') ||
      msg.toLowerCase().includes('malformed') ||
      msg.toLowerCase().includes('xref')
    ) {
      throw new Error('The PDF document is malformed or corrupted. Unable to parse structure.');
    }

    throw new Error('The PDF document could not be parsed cleanly. It may be corrupted or unsupported.');
  }

  // Only reached if PDFParse module was not a constructor function
  return {
    text: streamText || '',
    pageCount: 1,
  };
}

export function validateDocumentScanPayload(
  raw: any,
  meta: DocumentContentMetadata,
  extractedIocs: ExtractedIOCs,
  modelName: string,
  fullExtractedText?: string
): DocumentScanResult {
  const allowedRisks: RiskLevel[] = ['high', 'medium', 'low', 'uncertain'];
  let riskLevel: RiskLevel = allowedRisks.includes(raw?.riskLevel)
    ? raw.riskLevel
    : 'uncertain';

  const summary =
    typeof raw?.summary === 'string' && raw.summary.trim().length > 0
      ? raw.summary.trim()
      : 'Automated threat evaluation completed for this document.';

  const indicators: ThreatIndicator[] = Array.isArray(raw?.indicators)
    ? raw.indicators
        .filter((ind: any) => ind && typeof ind === 'object')
        .map((ind: any) => ({
          name: typeof ind.name === 'string' ? ind.name : 'Suspicious Marker',
          evidence: typeof ind.evidence === 'string' ? ind.evidence : 'Extracted from file content',
          reason: typeof ind.reason === 'string' ? ind.reason : 'Potential security anomaly',
        }))
    : [];

  const suspiciousElements: SuspiciousElement[] = Array.isArray(raw?.suspiciousElements)
    ? raw.suspiciousElements
        .filter((s: any) => s && typeof s === 'object')
        .map((s: any) => ({
          category: s.category || 'inconsistent_data',
          evidence: typeof s.evidence === 'string' ? s.evidence : '',
          explanation: typeof s.explanation === 'string' ? s.explanation : '',
        }))
    : [];

  const rawRecommendedActions: string[] = Array.isArray(raw?.recommendedActions)
    ? raw.recommendedActions.filter((a: any) => typeof a === 'string')
    : [
        'Do not click embedded links or scan QR codes in this document.',
        'Verify sender or vendor identity independently via pre-established contact directories.',
      ];

  const limitations: string[] = Array.isArray(raw?.limitations)
    ? raw.limitations.filter((l: any) => typeof l === 'string')
    : [
        'Analysis is based strictly on visible document contents and cannot verify sender domain authentication, bank account ownership, or external DNS records.',
      ];

  const verificationStatus: VerificationStatus = {
    independentlyVerified: Array.isArray(raw?.verificationStatus?.independentlyVerified)
      ? raw.verificationStatus.independentlyVerified.filter((v: any) => typeof v === 'string')
      : [],
    unverifiedClaims: Array.isArray(raw?.verificationStatus?.unverifiedClaims)
      ? raw.verificationStatus.unverifiedClaims.filter((u: any) => typeof u === 'string')
      : [
          meta.apparentSenderOrOrganization
            ? `Identity of claimed organization: ${meta.apparentSenderOrOrganization}`
            : 'Unverified external contact information and payment claims',
        ],
  };

  // Run unified deterministic threat taxonomy and BEC/payment-change evaluation on actual document evidence
  const extractedSnippet =
    (typeof raw?.documentContent?.extractedTextSnippet === 'string' && raw.documentContent.extractedTextSnippet) ||
    meta.extractedTextSnippet ||
    '';

  const evidenceCorpus = [
    fullExtractedText || '',
    extractedSnippet,
    ...suspiciousElements.map((s) => s.evidence).filter(Boolean),
    ...indicators.map((i) => i.evidence).filter(Boolean),
  ]
    .filter((chunk) => chunk.trim().length > 0 && !chunk.startsWith('[Notice: This PDF does not contain'))
    .join('\n');

  const behavioral = detectBehavioralThreats(evidenceCorpus || extractedSnippet);
  const taxonomy = behavioral.taxonomy;
  const pc = taxonomy.paymentChange;

  for (const bInd of behavioral.indicators) {
    if (!indicators.some((i) => i.name.toLowerCase() === bInd.name.toLowerCase())) {
      indicators.push(bInd);
    }
  }

  if (pc.detected && !suspiciousElements.some((s) => s.category === 'financial_anomaly')) {
    suspiciousElements.unshift({
      category: 'financial_anomaly',
      evidence: pc.evidenceSnippets.join(' | ') || extractedSnippet.slice(0, 140),
      explanation: pc.isActiveRedirectionRequest
        ? 'Document contains unverified bank-account change or payment-redirection instructions characteristic of supplier/vendor Business Email Compromise (BEC).'
        : 'Document references a bank-account or payment-detail update that has not been independently confirmed.',
    });
  }

  if (pc.detected && !verificationStatus.unverifiedClaims.some((u) => /bank|account|beneficiary|payment/i.test(u))) {
    verificationStatus.unverifiedClaims.unshift(
      'Authenticity of sender and authorization to change beneficiary bank account or remittance instructions.'
    );
  }

  const hasCriticalBehavioralThreat =
    behavioral.hasPaymentChangeRedirection ||
    behavioral.hasExecutiveImpersonation ||
    behavioral.hasPayrollDiversion ||
    behavioral.hasAuthCodeRequest ||
    behavioral.hasCredentialHarvesting ||
    behavioral.hasRemoteAccessRequest ||
    behavioral.hasRefundScam ||
    (behavioral.hasAccountBlockingThreat && (behavioral.hasPaymentDemand || behavioral.hasArtificialDeadline)) ||
    taxonomy.hasCriticalThreatVector;

  const hasModerateBehavioralThreat =
    !hasCriticalBehavioralThreat &&
    (behavioral.hasInformationalPaymentNotice ||
      behavioral.hasVerificationRequest ||
      behavioral.hasPaymentDemand ||
      behavioral.hasAccountBlockingThreat ||
      behavioral.hasSuspiciousLink ||
      behavioral.hasMonetaryIncentiveLure ||
      taxonomy.hasModerateThreatVector);

  if (hasCriticalBehavioralThreat && riskLevel !== 'high') {
    riskLevel = 'high';
  } else if (hasModerateBehavioralThreat && (riskLevel === 'low' || (pc.isVerificationRequest && riskLevel === 'high'))) {
    riskLevel = 'medium';
  }

  let calibratedSummary = summary;
  if (pc.isActiveRedirectionRequest && !/bank|account|redirect|bec|compromise|beneficiary/i.test(calibratedSummary)) {
    calibratedSummary = `HIGH RISK (Potential BEC / Payment Redirection): ${calibratedSummary} Hold all funds and confirm bank-account changes out-of-band via a pre-established telephone number before updating payment records.`;
  } else if (pc.isVerificationRequest && riskLevel === 'medium') {
    calibratedSummary = `Verification Required: This document asks to verify a proposed banking or account change before funds move. It does not instruct transferring funds on its own, though the referenced change must be confirmed strictly via established internal or vendor records.`;
  } else if (pc.isInformationalOnlyNotice && riskLevel === 'medium' && !/unverified|bank|account/i.test(calibratedSummary)) {
    calibratedSummary = `Advisory Warning: ${calibratedSummary} Any referenced banking change remains unverified and requires independent out-of-band confirmation.`;
  }

  const concreteIndicators = indicators.filter((i) => !i.name.startsWith('Ambiguous Context'));
  const onlyAmbiguousIndicators = indicators.length > 0 && concreteIndicators.length === 0;

  const evalMetrics = evaluateEvidenceAndConfidence(
    evidenceCorpus || extractedSnippet,
    riskLevel,
    indicators.length,
    {
      isConversationalClean: taxonomy.isOrdinaryConversational && concreteIndicators.length === 0,
      hasPrivatePaymentChange: pc.detected,
      externalEvidenceObtained: false,
      onlyAmbiguousIndicators,
    }
  );

  // Document scanner evaluates local document text/visuals without external DNS/sender auth,
  // so evidenceSufficiency strictly reflects extracted text & evidence volume (never threat severity).
  const evidenceSufficiency: EvidenceSufficiency = evalMetrics.evidenceSufficiency;

  const allowedConfidence: ModelConfidence[] = ['high', 'moderate', 'low'];
  const confidence: ModelConfidence = allowedConfidence.includes(raw?.confidence)
    ? pc.detected && raw.confidence === 'low'
      ? evalMetrics.confidence
      : raw.confidence
    : evalMetrics.confidence;

  const confidenceRationale =
    typeof raw?.confidenceRationale === 'string' && raw.confidenceRationale.trim().length > 0 && !pc.detected
      ? raw.confidenceRationale
      : evalMetrics.confidenceRationale;

  let severityScore = calculateSeverityScore(riskLevel, indicators.length);
  if (hasCriticalBehavioralThreat) {
    severityScore = Math.max(84, severityScore);
  }

  const assessmentState = determineAssessmentState({
    riskLevel,
    isShortInsufficient: (evidenceCorpus || extractedSnippet).trim().length < 25 && concreteIndicators.length === 0,
    hasThreatIndicators: concreteIndicators.length > 0 || pc.detected || suspiciousElements.length > 0,
    isConversationalClean: taxonomy.isOrdinaryConversational && concreteIndicators.length === 0 && suspiciousElements.length === 0,
  });

  const { threatAssessment, factualVerification, authenticityAssessment } = buildSeparatedAssessmentDimensions({
    message: evidenceCorpus || extractedSnippet,
    riskLevel,
    severityScore,
    indicators,
    behavioral,
    assessmentState,
    externalEvidenceObtained: false,
    iocs: extractedIocs,
  });

  const audienceRecs = buildAudienceSafetyRecommendations(evidenceCorpus || extractedSnippet, behavioral);
  const recommendedActions =
    hasCriticalBehavioralThreat || pc.detected
      ? deriveRelevantActions(rawRecommendedActions, indicators, extractedIocs, riskLevel, evidenceCorpus || extractedSnippet)
      : rawRecommendedActions;

  return {
    inputType: meta.mimeType.startsWith('image/') ? 'screenshot' : 'document',
    riskLevel,
    severityScore,
    summary: calibratedSummary,
    documentContent: {
      ...meta,
      detectedType: raw?.documentContent?.detectedType || meta.detectedType || 'unknown',
      extractedTextSnippet:
        raw?.documentContent?.extractedTextSnippet || meta.extractedTextSnippet,
      apparentSenderOrOrganization:
        raw?.documentContent?.apparentSenderOrOrganization ||
        meta.apparentSenderOrOrganization ||
        'Not specified',
      claimedPurpose:
        raw?.documentContent?.claimedPurpose || meta.claimedPurpose || 'Informational',
    },
    suspiciousElements,
    verificationStatus,
    indicators,
    recommendedActions,
    limitations,
    model: modelName,
    analyzedAt: new Date().toISOString(),
    evidenceSufficiency,
    evidenceCoverage: evalMetrics.evidenceCoverage,
    confidence,
    confidenceRationale,
    assessmentState,
    assessmentStateLabel: ASSESSMENT_STATE_LABELS[assessmentState],
    primaryThreatCategory: taxonomy.primaryCategory,
    threatCategories: taxonomy.categories,
    paymentChangeDetection: pc,
    threatAssessment,
    factualVerification,
    authenticityAssessment,
    financeRecommendations: audienceRecs.forFinanceTeams,
    unverifiedClaims: verificationStatus.unverifiedClaims,
    externalEvidenceObtained: false,
    iocs: extractedIocs,
  };
}

/**
 * Maps internal analysisMode into vendor-private customer UI labels.
 */
export function getDocumentAnalysisEngineDisplay(analysisMode?: DocumentAnalysisMode): {
  label: string;
  badge: string;
  isFallback: boolean;
} {
  if (analysisMode === 'fallback') {
    return {
      label: 'Aegis AI Document Intelligence (Fallback Engine)',
      badge: 'Fallback AI Analysis',
      isFallback: true,
    };
  }
  return {
    label: 'Aegis AI Document Intelligence (Primary Engine)',
    badge: 'Primary AI Analysis',
    isFallback: false,
  };
}

/**
 * Classifies server/network failures into clean, customer-safe status categories without exposing vendors.
 */
export function formatDocumentScanErrorNotice(
  errorCode?: DocumentScanErrorCode | string,
  rawMessage?: string,
  httpStatus?: number
): {
  categoryTitle: string;
  message: string;
  isRetryable: boolean;
} {
  const safeFallback = rawMessage && rawMessage.trim().length > 0
    ? rawMessage.trim()
    : 'An unexpected error occurred during document analysis.';

  if (errorCode === 'invalid_file' || errorCode === 'invalid_request' || httpStatus === 400) {
    return {
      categoryTitle: 'Invalid or Unsupported Document',
      message: safeFallback,
      isRetryable: false,
    };
  }

  if (errorCode === 'extraction_failed' || httpStatus === 422) {
    return {
      categoryTitle: 'Document Extraction / OCR Failure',
      message: safeFallback,
      isRetryable: false,
    };
  }

  if (errorCode === 'rate_limiter_unavailable') {
    return {
      categoryTitle: 'Rate-Limit Protection Unavailable',
      message:
        rawMessage && rawMessage.trim().length > 0
          ? rawMessage.trim()
          : 'Rate-limiting protection service is temporarily unavailable. Expensive analysis requests are paused to safeguard platform availability. Please retry shortly.',
      isRetryable: true,
    };
  }

  if (errorCode === 'rate_limit_exceeded') {
    return {
      categoryTitle: 'Request Quota Reached',
      message:
        rawMessage && rawMessage.trim().length > 0
          ? rawMessage.trim()
          : 'Request limit reached for this analysis tool. Please wait briefly before retrying.',
      isRetryable: true,
    };
  }

  if (errorCode === 'provider_quota' || httpStatus === 429) {
    return {
      categoryTitle: 'AI Capacity / Rate Limit Reached',
      message:
        rawMessage && rawMessage.trim().length > 0
          ? rawMessage.trim()
          : 'Aegis AI analysis quota or rate limit was temporarily reached. Please wait a moment and retry.',
      isRetryable: true,
    };
  }

  if (errorCode === 'provider_timeout' || httpStatus === 504) {
    return {
      categoryTitle: 'Analysis Timed Out',
      message:
        rawMessage && rawMessage.trim().length > 0
          ? rawMessage.trim()
          : 'Document inspection timed out awaiting AI analysis. Click "Retry Analysis" to run a fresh scan.',
      isRetryable: true,
    };
  }

  if (errorCode === 'provider_auth') {
    return {
      categoryTitle: 'AI Service Configuration Failure',
      message:
        rawMessage && rawMessage.trim().length > 0
          ? rawMessage.trim()
          : 'Aegis AI service authentication failed. Please contact an administrator to verify system configuration.',
      isRetryable: false,
    };
  }

  if (errorCode === 'providers_unavailable' || httpStatus === 502 || httpStatus === 503) {
    return {
      categoryTitle: 'AI Analysis Engines Unavailable',
      message:
        rawMessage && rawMessage.trim().length > 0
          ? rawMessage.trim()
          : 'Both primary and fallback Aegis AI analysis engines are currently unavailable. Please retry shortly.',
      isRetryable: true,
    };
  }

  return {
    categoryTitle: 'Document Scan Status',
    message: safeFallback,
    isRetryable: true,
  };
}
