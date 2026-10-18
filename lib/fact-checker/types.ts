/**
 * Type definitions for the AegisFlow Web-Research, Fact-Checking, and Threat-Intelligence Engine.
 */

export type ClaimVerificationVerdict =
  | 'supported'
  | 'contradicted'
  | 'misleading'
  | 'unverified_suspicious'
  | 'inconclusive'
  | 'no_verifiable_claim';

export interface FactualClaim {
  id: string;
  claimText: string;
  claimant?: string;
  isFactual: boolean; // Separates verifiable facts from opinions/predictions/greetings
  verdict: ClaimVerificationVerdict;
  verdictExplanation: string;
  supportingEvidence: string[];
  contradictingEvidence: string[];
  citedSourceUrls: string[];
  evidenceNeeded?: string;
}

export type ResearchExecutionStatus =
  | 'not_required'
  | 'live_research_completed'
  | 'completed_using_cached_evidence'
  | 'partially_completed'
  | 'provider_unavailable'
  | 'provider_timeout'
  | 'quota_exhausted'
  | 'rate_limit_exhausted'
  | 'authentication_failed'
  | 'missing_configuration'
  | 'inconclusive'
  | 'no_results';

export type SourceProvenance =
  | 'full_page_retrieved'
  | 'snippet_only'
  | 'page_retrieval_failed'
  | 'cached_evidence'
  | 'authoritative_dns'
  | 'threat_intelligence'
  | 'encyclopedia';

export interface ResearchSource {
  id: string;
  title: string;
  url: string;
  domain: string;
  publisher?: string;
  snippet: string;
  rawContentExcerpt?: string; // Captured when full webpage content is safely fetched
  provenance: SourceProvenance;
  pageRetrievalStatus?: 'retrieved' | 'snippet_only' | 'failed' | 'unattempted';
  isCached?: boolean;
  cachedAt?: string;
  publishedDate?: string;
  retrievedAt: string;
  sourceType:
    | 'official_site'
    | 'news_reporting'
    | 'public_advisory'
    | 'encyclopedia'
    | 'dns_telemetry'
    | 'threat_intel'
    | 'social_media'
    | 'web_search';
  reliability: 'authoritative' | 'reputable' | 'unverified';
  relevanceExplanation?: string;
  limitationNote?: string;
  isOfficialInstitutionalSource?: boolean;
}

export interface DomainDnsIntelligence {
  domain: string;
  hasDnsRecords: boolean;
  ipAddresses: string[];
  mxRecordsCount: number;
  hasMailServers: boolean;
  isSuspiciousOrParked: boolean;
  notes: string;
  caveat: string;
}

export interface ThreatIntelRecord {
  indicator: string;
  type: 'domain' | 'url';
  provider: 'URLhaus (abuse.ch)' | 'DNS Telemetry' | 'Heuristic Intelligence';
  status: 'malicious' | 'clean_or_unlisted' | 'unreachable' | 'unconfigured' | 'authentication_failure';
  confidence: 'high' | 'moderate' | 'low';
  details: string;
  tags?: string[];
  threatType?: string;
  dateAdded?: string;
  retrievedAt: string;
  importantNotice: string;
  isCached?: boolean;
  cachedAt?: string;
}

export interface AudienceRecommendations {
  forIndividuals: string[];
  forOrganizations: string[];
  forSecurityTeams: string[];
}

export type ProviderDiagnosticStatus =
  | 'configured_and_reachable'
  | 'missing_configuration'
  | 'authentication_failure'
  | 'rate_limit_exhausted'
  | 'provider_timeout'
  | 'provider_unavailable'
  | 'test_not_performed';

export interface ProviderDiagnosticItem {
  provider: string;
  status: ProviderDiagnosticStatus;
  isConfigured: boolean;
  message: string;
  latencyMs?: number;
  testedAt?: string;
}

export interface CacheStats {
  size: number;
  hits: number;
  misses: number;
}

export interface SearchProviderStatus {
  providerName: string;
  isConfigured: boolean;
  mode: 'serper' | 'public_web_fallback' | 'tavily' | 'brave';
  researchStatus: ResearchExecutionStatus;
  statusExplanation: string;
  fullPageRetrievalActive: boolean;
  rateLimitEncountered: boolean;
  queriesExecuted: number;
  outboundSearchesExecuted: number;
  cacheHitsCount: number;
  maxSearchesConfigured: number;
  searchLimitReached: boolean;
  errorMessage?: string;
  configurationGuide?: string;
}

export interface ClaimAssessmentResult {
  warrantsExternalResearch: boolean;
  claimsIdentified: FactualClaim[];
  assessmentReason: string;
  isUrlThreatIntelAppropriate: boolean;
  candidateDomains: string[];
  candidateUrls: string[];
  extractionLimitation?: string;
}

export interface FactCheckReport {
  id: string;
  analyzedAt: string;
  executiveSummary: string;
  originalInputSnippet: string;
  hasVerifiableClaims: boolean;
  claimAssessment?: ClaimAssessmentResult;
  extractedClaims: FactualClaim[];
  sources: ResearchSource[];
  domainIntelligence: DomainDnsIntelligence[];
  threatIntel: ThreatIntelRecord[];
  suspiciousIndicators: Array<{
    name: string;
    evidence: string;
    reason: string;
  }>;
  evidenceSufficiency?: 'sufficient' | 'moderate' | 'limited' | 'insufficient';
  threatSeverity?: 'high' | 'medium' | 'low' | 'uncertain';
  severityScore?: number;
  confidenceLevel: 'high' | 'moderate' | 'low';
  confidenceRationale: string;
  unresolvedQuestions: string[];
  recommendations: AudienceRecommendations;
  researchLimitations: string[];
  searchProviderStatus: SearchProviderStatus;
  searchProviderUsed: string; // Search provider label (e.g. Serper.dev Web Search API)
  modelUsed?: string; // AI model used (e.g. Qwen/Qwen3-VL-8B-Instruct) or 'Not Invoked (Pre-search Triage)'
}
