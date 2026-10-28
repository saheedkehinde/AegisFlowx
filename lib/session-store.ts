'use client';

import * as React from 'react';
import { ScamAnalysisResult } from './scam-analyzer';

export interface SessionAnalysisRecord {
  id: string;
  timestamp: string;
  snippet: string;
  riskLevel: 'high' | 'medium' | 'low' | 'uncertain';
  severityScore: number;
  model: string;
  indicatorsCount: number;
  summary: string;
}

const STORAGE_KEY = 'aegisflow_recent_analyses_v1';

export function getSessionAnalyses(): SessionAnalysisRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

export function saveSessionAnalysis(
  result: ScamAnalysisResult,
  originalText: string
): SessionAnalysisRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const records = getSessionAnalyses();
    const snippet =
      originalText.length > 80 ? originalText.slice(0, 80) + '...' : originalText;
    const newRecord: SessionAnalysisRecord = {
      id: `analysis-${Date.now()}`,
      timestamp:
        result.analyzedAt ||
        new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      snippet,
      riskLevel: result.riskLevel,
      severityScore: result.severityScore ?? 50,
      model: result.model || 'Qwen/Qwen3-VL-8B-Instruct',
      indicatorsCount: result.indicators.length,
      summary: result.summary,
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
    const newRecord: SessionAnalysisRecord = {
      id: report.id || `url-inv-${Date.now()}`,
      timestamp:
        report.investigatedAt ||
        new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      snippet,
      riskLevel: report.overallSeverity,
      severityScore: report.severityScore ?? 50,
      model: report.modelUsed || 'URL Intelligence Engine',
      indicatorsCount: report.indicators?.length || 0,
      summary: report.executiveSummary,
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
          cachedParsed = JSON.parse(raw);
        }
        return cachedParsed;
      } catch {
        return emptySnapshot;
      }
    },
    () => emptySnapshot
  );
}
