'use client';

import React from 'react';
import Link from 'next/link';
import { LucideIcon } from 'lucide-react';

interface PageHeaderProps {
  breadcrumbLabel: string;
  title: string;
  description: string;
  icon: LucideIcon;
  badgeText?: string;
  badgeVariant?: 'orange' | 'cyan' | 'warning' | 'violet';
  actions?: React.ReactNode;
}

export default function PageHeader({
  breadcrumbLabel,
  title,
  description,
  icon: Icon,
  badgeText,
  badgeVariant = 'cyan',
  actions,
}: PageHeaderProps) {
  const badgeClasses = {
    orange:
      'border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] text-[var(--primary-orange)]',
    cyan: 'border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)]',
    warning:
      'border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] text-[var(--status-warning)]',
    violet:
      'border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)]',
  }[badgeVariant];

  return (
    <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4 border-b border-[var(--border)] pb-6">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2.5">
          <nav
            aria-label="Breadcrumb"
            className="flex items-center gap-2 text-xs text-[var(--muted-foreground)]"
          >
            <Link
              href="/"
              className="hover:text-[var(--primary-orange)] transition-colors inline-flex items-center gap-1"
            >
              <span>Dashboard</span>
            </Link>
            <span aria-hidden="true">&middot;</span>
            <span className="text-[var(--foreground)] font-medium">{breadcrumbLabel}</span>
          </nav>

          {badgeText && (
            <span
              className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider ${badgeClasses}`}
            >
              {badgeText}
            </span>
          )}
        </div>

        <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--foreground)] flex items-center gap-3 font-[family-name:var(--font-display)]">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)]">
            <Icon className="h-5 w-5" aria-hidden="true" />
          </span>
          <span>{title}</span>
        </h1>

        <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] max-w-3xl leading-relaxed">
          {description}
        </p>
      </div>

      {actions && (
        <div className="flex flex-wrap items-center gap-2 shrink-0 self-start sm:self-end">
          {actions}
        </div>
      )}
    </header>
  );
}
