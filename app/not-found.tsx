import Link from 'next/link';
import { ShieldAlert, ArrowLeft, Home } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] cyber-grid radial-glow flex flex-col items-center justify-center px-4 text-center">
      <div className="max-w-md w-full rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-8 shadow-[var(--shadow-lg)] space-y-5">
        <div className="mx-auto w-14 h-14 rounded-2xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 flex items-center justify-center text-[var(--primary-orange)]">
          <ShieldAlert className="w-7 h-7" />
        </div>

        <div className="space-y-2">
          <span className="inline-block font-mono text-[11px] uppercase tracking-wider text-[var(--muted-foreground)] bg-[var(--surface-interactive)] px-2.5 py-0.5 rounded border border-[var(--border)]">
            HTTP 404 &middot; Resource Unavailable
          </span>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
            Target Not Found
          </h1>
          <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] leading-relaxed">
            The requested intelligence resource, investigation record, or endpoint does not exist or has been archived.
          </p>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
          <Link
            href="/"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] font-semibold text-xs sm:text-sm transition-colors shadow-md shadow-[var(--primary-orange-glow)]"
          >
            <Home className="w-4 h-4" />
            <span>Command Center</span>
          </Link>
          <Link
            href="/analyze"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] text-[var(--foreground)] font-medium text-xs sm:text-sm transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>New Analysis</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
