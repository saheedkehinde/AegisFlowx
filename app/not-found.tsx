import Link from 'next/link';
import { ShieldAlert, ArrowLeft, Home } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center px-4 text-center">
      <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center mb-6 text-primary shadow-lg shadow-primary/5">
        <ShieldAlert className="w-8 h-8" />
      </div>
      <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-foreground mb-3 font-mono">
        404 — TARGET_NOT_FOUND
      </h1>
      <p className="text-muted-foreground max-w-md mb-8 text-sm sm:text-base leading-relaxed">
        The requested intelligence resource, investigation record, or telemetry endpoint does not exist or has been archived.
      </p>
      <div className="flex flex-wrap items-center justify-center gap-3">
        <Link
          href="/"
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:opacity-90 transition-opacity shadow-sm"
        >
          <Home className="w-4 h-4" />
          Command Center
        </Link>
        <Link
          href="/analyze"
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg border border-border bg-card text-foreground font-medium text-sm hover:bg-muted/50 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          New Triage
        </Link>
      </div>
    </div>
  );
}
