/**
 * Type definitions for the AegisFlow Web-Research and Fact-Checking Engine.
 */

export type ClaimVerificationVerdict =
  | 'supported'
  | 'contradicted'
  | 'misleading'
  | 'unverified_suspicious'
  | 'inconclusive';

export interface FactualClaim {
  id: string;
  claimText: string;
  claimant?: string;
  isFactual: boolean; // Separates verifiable facts from opinions/predictions
  verdict: ClaimVerificationVerdict;
  verdictExplanation: string;
  supportingEvidence: string[];
  contradictingEvidence: string[];
  citedSourceUrls: string[];
}

export interface ResearchSource {
  id: string;
  title: string;
  url: string;
  domain: string;
  snippet: string;
  publishedDate?: string;
  retrievedAt: string;
  sourceType: 'official_site' | 'news_reporting' | 'public_advisory' | 'encyclopedia' | 'dns_telemetry' | 'web_search';
  reliability: 'authoritative' | 'reputable' | 'unverified';
}

export interface DomainDnsIntelligence {
  domain: string;
  hasDnsRecords: boolean;
  ipAddresses: string[];
  mxRecordsCount: number;
  hasMailServers: boolean;
  isSuspiciousOrParked: boolean;
  notes: string;
}

export interface AudienceRecommendations {
  forIndividuals: string[];
  forOrganizations: string[];
  forSecurityTeams: string[];
}

export interface FactCheckReport {
  id: string;
  analyzedAt: string;
  executiveSummary: string;
  originalInputSnippet: string;
  extractedClaims: FactualClaim[];
  sources: ResearchSource[];
  domainIntelligence: DomainDnsIntelligence[];
  suspiciousIndicators: Array<{
    name: string;
    evidence: string;
    reason: string;
  }>;
  confidenceLevel: 'high' | 'moderate' | 'low';
  confidenceRationale: string;
  unresolvedQuestions: string[];
  recommendations: AudienceRecommendations;
  researchLimitations: string[];
  searchProviderUsed: string;
}
