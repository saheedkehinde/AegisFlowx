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

export interface DocumentScanResult extends ScamAnalysisResult {
  inputType: 'document' | 'screenshot';
  documentContent: DocumentContentMetadata;
  suspiciousElements: SuspiciousElement[];
  verificationStatus: VerificationStatus;
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

  // PDF: %PDF- (0x25 0x50 0x44 0x46 0x2D)
  if (
    buffer.length >= 5 &&
    buffer[0] === 0x25 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x44 &&
    buffer[3] === 0x46 &&
    buffer[4] === 0x2d
  ) {
    return {
      isValid: true,
      fileType: 'pdf',
      mimeType: 'application/pdf',
      sanitizedFilename,
      sizeBytes,
    };
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
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
    return {
      isValid: true,
      fileType: 'png',
      mimeType: 'image/png',
      sanitizedFilename,
      sizeBytes,
    };
  }

  // JPEG / JPG: FF D8 FF
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    return {
      isValid: true,
      fileType: 'jpeg',
      mimeType: 'image/jpeg',
      sanitizedFilename,
      sizeBytes,
    };
  }

  // WebP: 52 49 46 46 (RIFF) ... 57 45 42 50 (WEBP)
  if (
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
    return {
      isValid: true,
      fileType: 'webp',
      mimeType: 'image/webp',
      sanitizedFilename,
      sizeBytes,
    };
  }

  return {
    isValid: false,
    error: `Unsupported file format (${declaredMimeType || 'unknown'}). Only PDF documents (.pdf) and images (.png, .jpg, .jpeg, .webp) are supported.`,
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
  // First attempt fast stream extraction
  const streamText = extractFallbackPdfText(buffer);
  if (streamText.length > 20) {
    return {
      text: streamText,
      pageCount: 1,
    };
  }

  // Then attempt full PDFParse parser
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
          // Ignore worker error
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
    }
  } catch (err: any) {
    if (err?.name === 'PasswordException' || err?.message?.toLowerCase().includes('password')) {
      throw new Error('This PDF is password-protected or encrypted. Please provide an unlocked document.');
    }
    if (err?.name === 'InvalidPDFException' || err?.message?.toLowerCase().includes('invalid pdf')) {
      throw new Error('The PDF document is malformed or corrupted. Unable to parse structure.');
    }
  }

  // If both parser and stream found minimal text, return streamText or empty notice
  return {
    text: streamText || '',
    pageCount: 1,
  };
}

export function validateDocumentScanPayload(
  raw: any,
  meta: DocumentContentMetadata,
  extractedIocs: ExtractedIOCs,
  modelName: string
): DocumentScanResult {
  const allowedRisks: RiskLevel[] = ['high', 'medium', 'low', 'uncertain'];
  const riskLevel: RiskLevel = allowedRisks.includes(raw?.riskLevel)
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

  const recommendedActions: string[] = Array.isArray(raw?.recommendedActions)
    ? raw.recommendedActions.filter((a: any) => typeof a === 'string')
    : [
        'Do not click embedded links or scan QR codes in this document.',
        'Verify sender or vendor identity independently via official telephone directories.',
      ];

  const limitations: string[] = Array.isArray(raw?.limitations)
    ? raw.limitations.filter((l: any) => typeof l === 'string')
    : [
        'Analysis is based strictly on visible document contents and cannot verify external DNS or server logs.',
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

  const allowedSufficiency: EvidenceSufficiency[] = ['sufficient', 'moderate', 'sparse'];
  const evidenceSufficiency: EvidenceSufficiency = allowedSufficiency.includes(
    raw?.evidenceSufficiency
  )
    ? raw.evidenceSufficiency
    : meta.extractedTextSnippet.length > 50
    ? 'moderate'
    : 'sparse';

  const allowedConfidence: ModelConfidence[] = ['high', 'moderate', 'low'];
  const confidence: ModelConfidence = allowedConfidence.includes(raw?.confidence)
    ? raw.confidence
    : 'moderate';

  const confidenceRationale =
    typeof raw?.confidenceRationale === 'string'
      ? raw.confidenceRationale
      : 'Confidence calibrated based on available visible indicators and document integrity.';

  const severityScore = calculateSeverityScore(riskLevel, indicators.length);

  return {
    inputType: meta.mimeType.startsWith('image/') ? 'screenshot' : 'document',
    riskLevel,
    severityScore,
    summary,
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
    confidence,
    confidenceRationale,
    iocs: extractedIocs,
  };
}
