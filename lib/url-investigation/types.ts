import {
  ThreatIntelRecord,
  DomainDnsIntelligence,
  ResearchSource,
  AudienceRecommendations,
  SearchProviderStatus,
} from '@/lib/fact-checker/types';
import { RedirectAnalysisResult } from './redirect-resolver';

export interface UrlComponents {
  rawUrl: string;
  normalizedUrl: string;
  displayUrl: string;
  protocol: string;
  hostname: string;
  domain: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  hasCredentials: boolean;
  hasIpHostname: boolean;
  isShortenedUrl: boolean;
  isFreeHostingSubdomain: boolean;
  redactedParamsCount: number;
}

export interface UrlIndicatorItem {
  id: string;
  category: 'protocol' | 'hostname' | 'path_or_query' | 'infrastructure' | 'reputation' | 'redirect';
  severity: 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence: string;
}

export type UrlVerdictOutcome =
  | 'confirmed_malicious'
  | 'suspicious'
  | 'potentially_compromised'
  | 'inconclusive'
  | 'no_known_threat_listing'
  | 'insufficient_evidence';

export interface UrlInvestigationReport {
  id: string;
  investigatedAt: string;
  urlComponents: UrlComponents;
  redirectResult: RedirectAnalysisResult;
  verdictOutcome: UrlVerdictOutcome;
  overallSeverity: 'high' | 'medium' | 'low' | 'uncertain';
  severityScore: number;
  confidenceLevel: 'high' | 'moderate' | 'low';
  confidenceRationale: string;
  executiveSummary: string;
  threatIntel: ThreatIntelRecord[];
  domainIntelligence: DomainDnsIntelligence | null;
  indicators: UrlIndicatorItem[];
  webEvidence: ResearchSource[];
  recommendedActions: AudienceRecommendations;
  evidenceLimitations: string[];
  searchProviderStatus?: SearchProviderStatus;
  modelUsed: string;
  savedToVault?: boolean;
}
