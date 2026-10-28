import {
  ThreatIntelRecord,
  DomainDnsIntelligence,
  ResearchSource,
  AudienceRecommendations,
  SearchProviderStatus,
} from '@/lib/fact-checker/types';

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
  category: 'protocol' | 'hostname' | 'path_or_query' | 'infrastructure' | 'reputation';
  severity: 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence: string;
}

export interface UrlInvestigationReport {
  id: string;
  investigatedAt: string;
  urlComponents: UrlComponents;
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
