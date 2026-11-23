'use client';

import * as React from 'react';
import { ScamAnalysisResult } from './scam-analyzer';
import {
  CanonicalInputType,
  NormalizedThreatIndicator,
  normalizeIndicators,
  normalizeInputType,
  resolveRecordMessageText,
  resolveRecordSummary,
} from './vault-normalization';

export interface SessionAnalysisRecord {
  id: string;
  timestamp: string;
  snippet: string;
  riskLevel: 'high' | 'medium' | 'low' | 'uncertain';
  severityScore: number;
  model: string;
  indicatorsCount: number;
  summary: string;
  inputType?: CanonicalInputType;
  indicators?: NormalizedThreatIndicator[];
}

const STORAGE_KEY = 'aegisflow_recent_analyses_v1';

function normalizeRiskLevel(raw: unknown): 'high' | 'medium' | 'low' | 'uncertain' {
  const val = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (val === 'high') return 'high';
  if (val === 'medium') return 'medium';
  if (val === 'low' || val === 'safe') return 'low';
  return 'uncertain';
}

export function normalizeSessionAnalysisRecord(raw: unknown): SessionAnalysisRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }

  const obj = raw as Record<string, unknown>;
  const snippet = resolveRecordMessageText(obj);
  const summary = resolveRecordSummary(obj);
  const model =
    typeof obj.model === 'string' && obj.model.trim()
      ? obj.model.trim()
      : typeof obj.model_name === 'string' && obj.model_name.trim()
      ? obj.model_name.trim()
      : 'Aegis AI';

  const normalizedIndicators = normalizeIndicators(obj.indicators);
  const rawCount = Number(obj.indicatorsCount);
  const indicatorsCount =
    normalizedIndicators.length > 0
      ? normalizedIndicators.length
      : Number.isFinite(rawCount) && rawCount >= 0
      ? Math.round(rawCount)
      : 0;

  const rawScore = Number(obj.severityScore ?? obj.severity_score);
  const severityScore = Number.isFinite(rawScore)
    ? Math.max(0, Math.min(100, Math.round(rawScore)))
    : 50;

  const inputType = normalizeInputType(obj.inputType ?? obj.input_type ?? obj.type, {
    snippet,
    model,
    iocs: obj.iocs,
  });

  const timestamp =
    typeof obj.timestamp === 'string' && obj.timestamp.trim()
      ? obj.timestamp.trim()
      : typeof obj.created_at === 'string' && obj.created_at.trim()
      ? obj.created_at.trim()
      : 'Recent';

  return {
    id:
      typeof obj.id === 'string' && obj.id.trim()
        ? obj.id.trim()
        : `analysis-${Date.now()}`,
    timestamp,
    snippet,
    riskLevel: normalizeRiskLevel(obj.riskLevel ?? obj.threat_severity),
    severityScore,
    model,
    indicatorsCount,
    summary,
    inputType,
    indicators: normalizedIndicators.length > 0 ? normalizedIndicators : undefined,
  };
}

export function normalizeSessionAnalysisList(raw: unknown): SessionAnalysisRecord[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map(normalizeSessionAnalysisRecord)
    .filter((item): item is SessionAnalysisRecord => item !== null);
}

export function getSessionAnalyses(): SessionAnalysisRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return normalizeSessionAnalysisList(JSON.parse(raw));
  } catch {
    return [];
  }
}

export function saveSessionAnalysis(
  result: ScamAnalysisResult & {
    documentContent?: {
      mimeType?: string;
      filename?: string;
    };
  },
  originalText: string,
  explicitInputType?: CanonicalInputType
): SessionAnalysisRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const records = getSessionAnalyses();
    const safeText = typeof originalText === 'string' ? originalText : '';
    const snippet = safeText.length > 80 ? safeText.slice(0, 80) + '...' : safeText;
    const normalizedIndicators = normalizeIndicators(result.indicators);

    let inferredType: CanonicalInputType = explicitInputType
      ? normalizeInputType(explicitInputType, { snippet })
      : 'message';

    if (!explicitInputType) {
      if (result.documentContent) {
        const mime = (result.documentContent.mimeType || '').toLowerCase();
        const filename = (result.documentContent.filename || '').toLowerCase();
        inferredType =
          mime.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/.test(filename)
            ? 'screenshot'
            : 'document';
      } else {
        inferredType = normalizeInputType(undefined, { snippet });
        if (inferredType === 'unknown') inferredType = 'message';
      }
    }

    const newRecord: SessionAnalysisRecord = {
      id: `analysis-${Date.now()}`,
      timestamp:
        result.analyzedAt ||
        new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      snippet,
      riskLevel: normalizeRiskLevel(result.riskLevel),
      severityScore: result.severityScore ?? 50,
      model: 'Aegis AI',
      indicatorsCount: normalizedIndicators.length,
      summary: typeof result.summary === 'string' ? result.summary : '',
      inputType: inferredType,
      indicators: normalizedIndicators,
    };

    const updated = [newRecord, ...records].slice(0, 10);
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event('aegisflow-analysis-saved'));
    return updated;
  } catch {
    return [];
  }
}

export function saveSessionUrlInvestigation(
  report: {
    id: string;
    urlComponents: { displayUrl?: string; rawUrl: string };
    overallSeverity: 'high' | 'medium' | 'low' | 'uncertain';
    severityScore: number;
    modelUsed: string;
    indicators: any[];
    executiveSummary: string;
    investigatedAt?: string;
  }
): SessionAnalysisRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const records = getSessionAnalyses();
    const target = report.urlComponents.displayUrl || report.urlComponents.rawUrl;
    const snippet = `[URL] ${target.length > 80 ? target.slice(0, 80) + '...' : target}`;
    const normalizedIndicators = normalizeIndicators(report.indicators);
    const newRecord: SessionAnalysisRecord = {
      id: report.id || `url-inv-${Date.now()}`,
      timestamp:
        report.investigatedAt ||
        new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      snippet,
      riskLevel: normalizeRiskLevel(report.overallSeverity),
      severityScore: report.severityScore ?? 50,
      model: 'Aegis AI URL Intelligence',
      indicatorsCount: normalizedIndicators.length,
      summary: typeof report.executiveSummary === 'string' ? report.executiveSummary : '',
      inputType: 'url_investigation',
      indicators: normalizedIndicators,
    };

    const updated = [newRecord, ...records].slice(0, 10);
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event('aegisflow-analysis-saved'));
    return updated;
  } catch {
    return [];
  }
}

export function clearSessionAnalyses(): void {
  if (typeof window === 'undefined') return;
  try {
    sessionStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new Event('aegisflow-analysis-saved'));
  } catch {
    // Ignore storage errors
  }
}

function subscribe(callback: () => void) {
  if (typeof window === 'undefined') {
    return () => {};
  }
  window.addEventListener('aegisflow-analysis-saved', callback);
  window.addEventListener('storage', callback);
  return () => {
    window.removeEventListener('aegisflow-analysis-saved', callback);
    window.removeEventListener('storage', callback);
  };
}

let cachedRaw = '';
let cachedParsed: SessionAnalysisRecord[] = [];
const emptySnapshot: SessionAnalysisRecord[] = [];

export function useSessionAnalyses(): SessionAnalysisRecord[] {
  return React.useSyncExternalStore(
    subscribe,
    () => {
      if (typeof window === 'undefined') return emptySnapshot;
      try {
        const raw = sessionStorage.getItem(STORAGE_KEY) || '[]';
        if (raw !== cachedRaw) {
          cachedRaw = raw;
          cachedParsed = normalizeSessionAnalysisList(JSON.parse(raw));
        }
        return cachedParsed;
      } catch {
        return emptySnapshot;
      }
    },
    () => emptySnapshot
  );
}
