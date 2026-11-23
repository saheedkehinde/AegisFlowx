import React from 'react';
import Link from 'next/link';
import { ShieldAlert, Lock, ArrowLeft } from 'lucide-react';
import { verifyAdminUser } from '@/lib/admin-auth';
import AdminDiagnosticsClient from './AdminDiagnosticsClient';

export const dynamic = 'force-dynamic';

export default async function AdminDiagnosticsPage() {
  const adminAuth = await verifyAdminUser(undefined, { allowApiKeyHeader: false });

  if (!adminAuth.isAdmin) {
    return (
      <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] cyber-grid radial-glow p-4 sm:p-6 lg:p-10 font-sans flex items-center justify-center">
        <div className="rounded-2xl border border-[var(--status-critical-border)] bg-[var(--card-bg)] p-8 text-center space-y-4 max-w-xl w-full shadow-[var(--shadow-md)]">
          <div className="inline-flex items-center gap-2 rounded-md border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] px-2.5 py-0.5 text-[11px] font-mono font-semibold text-[var(--status-critical)]">
            <Lock className="h-3.5 w-3.5" aria-hidden="true" />
            <span>HTTP 403 // RESTRICTED</span>
          </div>
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--status-critical-bg)] border border-[var(--status-critical-border)] text-[var(--status-critical)]">
            <ShieldAlert className="h-6 w-6" aria-hidden="true" />
          </div>
          <h1 className="text-lg font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
            Administrator Access Required
          </h1>
          <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed">
            This area contains internal provider routing and infrastructure telemetry restricted exclusively to authorized administrators.
            Your current session does not hold verified administrative privileges.
          </p>
          <div className="pt-2">
            <Link
              href="/settings"
              className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-5 py-2.5 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Return to General Settings</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return <AdminDiagnosticsClient />;
}
