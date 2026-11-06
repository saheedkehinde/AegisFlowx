'use client';

import React, { useState, useEffect, useCallback, useMemo, useSyncExternalStore } from 'react';
import AppShell from '@/components/AppShell';
import { useSessionAnalyses, clearSessionAnalyses } from '@/lib/session-store';
import { useAuth } from '@/hooks/use-auth';
import { createClient } from '@/lib/supabase/client';

import DashboardHero from '@/components/dashboard/DashboardHero';
import MetricsOverview from '@/components/dashboard/MetricsOverview';
import ThreatDistribution from '@/components/dashboard/ThreatDistribution';
import QuickInvestigationLauncher from '@/components/dashboard/QuickInvestigationLauncher';
import RecentInvestigations, { SavedCaseSummary } from '@/components/dashboard/RecentInvestigations';
import EcosystemModules from '@/components/dashboard/EcosystemModules';
import PlatformTelemetry from '@/components/dashboard/PlatformTelemetry';

// Reactive listener for local Security Academy progress
function subscribeAcademy(callback: () => void) {
  if (typeof window === 'undefined') return () => {};
  window.addEventListener('aegisflow-academy-progress-updated', callback);
  window.addEventListener('storage', callback);
  return () => {
    window.removeEventListener('aegisflow-academy-progress-updated', callback);
    window.removeEventListener('storage', callback);
  };
}

function getAcademySnapshot(): string {
  if (typeof window === 'undefined') return '{}';
  try {
    return localStorage.getItem('aegisflow_academy_progress_v1') || '{}';
  } catch {
    return '{}';
  }
}

function getAcademyServerSnapshot(): string {
  return '{}';
}

function formatCaseDate(dateString?: string): string {
  if (!dateString) return 'Recent';
  try {
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return dateString;
    return d.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return dateString;
  }
}

function formatRelativeTime(dateString?: string): string {
  if (!dateString) return 'Awaiting activity';
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return dateString;
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMinutes < 1) return 'Just now';
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  } catch {
    return dateString;
  }
}

export default function OverviewPage() {
  const { user, profile, loading: authLoading } = useAuth();
  const sessionAnalyses = useSessionAnalyses();

  const [savedCases, setSavedCases] = useState<SavedCaseSummary[]>([]);
  const [savedCount, setSavedCount] = useState<number | null>(null);
  const [loadingCases, setLoadingCases] = useState(false);
  const [casesError, setCasesError] = useState<string | null>(null);

  // Subscribe to local academy verified lessons
  const academyRaw = useSyncExternalStore(
    subscribeAcademy,
    getAcademySnapshot,
    getAcademyServerSnapshot
  );

  const academyProgress = useMemo(() => {
    try {
      return JSON.parse(academyRaw);
    } catch {
      return {};
    }
  }, [academyRaw]);

  const verifiedAcademyCount = Object.values(academyProgress).filter(
    (p: any) => p?.completed
  ).length;

  // Fetch persisted cases for authenticated user
  const fetchUserCases = useCallback(async () => {
    if (!user) {
      setSavedCases([]);
      setSavedCount(0);
      return;
    }

    setLoadingCases(true);
    setCasesError(null);

    try {
      const supabase = createClient();
      const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
      if (sessionErr) throw sessionErr;

      if (!sessionData?.session) {
        setLoadingCases(false);
        return;
      }

      const { data, count, error } = await supabase
        .from('analysis_history')
        .select(
          'id, input_type, input_snippet, threat_severity, severity_score, summary, created_at',
          { count: 'exact' }
        )
        .order('created_at', { ascending: false })
        .limit(8);

      if (error) {
        setCasesError(error.message);
      } else {
        setSavedCases((data as SavedCaseSummary[]) || []);
        setSavedCount(count ?? data?.length ?? 0);
      }
    } catch (err: any) {
      setCasesError(err?.message || 'Failed to query investigation history from vault');
    } finally {
      setLoadingCases(false);
    }
  }, [user]);

  useEffect(() => {
    if (authLoading) return;
    const timer = setTimeout(() => {
      fetchUserCases();
    }, 0);
    return () => clearTimeout(timer);
  }, [authLoading, fetchUserCases]);

  const handleClearHistory = () => {
    clearSessionAnalyses();
  };

  // Compute empirical threat posture from genuine data
  const activeCases = user
    ? savedCases
    : sessionAnalyses.map((s) => ({
        id: s.id,
        input_type: s.snippet.startsWith('[URL]') ? 'url_investigation' : 'message',
        input_snippet: s.snippet,
        threat_severity: s.riskLevel,
        severity_score: s.severityScore,
        summary: s.summary,
        created_at: s.timestamp,
      }));

  const highRiskCount = activeCases.filter((c) => c.threat_severity === 'high').length;
  const medRiskCount = activeCases.filter((c) => c.threat_severity === 'medium').length;
  const lowRiskCount = activeCases.filter(
    (c) => c.threat_severity === 'low' || (c.threat_severity as string) === 'safe'
  ).length;
  const uncertainCount = activeCases.filter((c) => c.threat_severity === 'uncertain').length;

  const latestHighCase = activeCases.find((c) => c.threat_severity === 'high') || null;

  const lastActivityTimestamp = user
    ? savedCases[0]?.created_at
    : sessionAnalyses[0]?.timestamp;

  const analystName = profile?.display_name || user?.email?.split('@')[0] || 'Analyst';

  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        {/* 1. Command Centre Welcome & Operational Header */}
        <DashboardHero
          user={user}
          analystName={analystName}
          savedCount={savedCount}
          sessionCount={sessionAnalyses.length}
        />

        {/* 2. Intelligence Metrics Overview */}
        <MetricsOverview
          isAuthenticated={!!user}
          savedCount={savedCount}
          sessionCount={sessionAnalyses.length}
          highRiskCount={highRiskCount}
          medRiskCount={medRiskCount}
          lowRiskCount={lowRiskCount}
          lastActivityTimestamp={lastActivityTimestamp}
          verifiedAcademyCount={verifiedAcademyCount}
          isLoading={authLoading || loadingCases}
          formatRelativeTime={formatRelativeTime}
          formatCaseDate={formatCaseDate}
        />

        {/* 3. Threat Severity Distribution & High-Priority Case Spotlight */}
        <ThreatDistribution
          totalCases={activeCases.length}
          highCount={highRiskCount}
          medCount={medRiskCount}
          lowCount={lowRiskCount}
          uncertainCount={uncertainCount}
          latestHighCase={latestHighCase}
          isLoading={authLoading || loadingCases}
        />

        {/* 4. Primary Quick Investigation Launcher */}
        <QuickInvestigationLauncher />

        {/* 5. Recent Investigations Dossiers (Vault vs Session) */}
        <RecentInvestigations
          isAuthenticated={!!user}
          userEmail={user?.email || undefined}
          displayName={profile?.display_name || undefined}
          savedCases={savedCases}
          savedCount={savedCount}
          sessionAnalyses={sessionAnalyses}
          loadingCases={loadingCases}
          casesError={casesError}
          onRefresh={fetchUserCases}
          onClearSession={handleClearHistory}
          formatCaseDate={formatCaseDate}
        />

        {/* 6. Threat Literacy & Intelligence Ecosystem */}
        <EcosystemModules verifiedAcademyCount={verifiedAcademyCount} />

        {/* 7. Platform Telemetry & Infrastructure Specifications */}
        <PlatformTelemetry isAuthenticated={!!user} />
      </div>
    </AppShell>
  );
}
