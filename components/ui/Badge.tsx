'use client';

import React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

const badgeVariants = cva(
  'inline-flex items-center font-mono font-medium rounded-md border transition-colors whitespace-nowrap shrink-0',
  {
    variants: {
      variant: {
        neutral:
          'bg-[var(--surface-interactive)] text-[var(--foreground-secondary)] border-[var(--border)]',
        primary:
          'bg-[var(--surface-soft-orange)] text-[var(--primary-orange)] border-[var(--primary-orange)]/30 font-semibold',
        success:
          'bg-[var(--status-success-bg)] text-[var(--status-success)] border-[var(--status-success-border)] font-semibold',
        warning:
          'bg-[var(--status-warning-bg)] text-[var(--status-warning)] border-[var(--status-warning-border)] font-semibold',
        critical:
          'bg-[var(--status-critical-bg)] text-[var(--status-critical)] border-[var(--status-critical-border)] font-semibold',
        cyan:
          'bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)] border-[var(--accent-cyan)]/30 font-semibold',
        violet:
          'bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)] border-[var(--accent-violet)]/30 font-semibold',
        amber:
          'bg-[var(--accent-amber-subtle)] text-[var(--accent-amber)] border-[var(--accent-amber)]/30 font-semibold',
        preview:
          'bg-[var(--surface-interactive)] text-[var(--foreground-secondary)] border-[var(--border)] italic',
      },
      size: {
        sm: 'text-[10px] px-1.5 py-0.2 gap-1',
        md: 'text-xs px-2.5 py-0.5 gap-1.5',
        lg: 'text-xs sm:text-sm px-3 py-1 gap-2',
      },
    },
    defaultVariants: {
      variant: 'neutral',
      size: 'sm',
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {
  icon?: React.ReactNode;
}

export function Badge({
  className = '',
  variant,
  size,
  icon,
  children,
  ...props
}: BadgeProps) {
  return (
    <span className={badgeVariants({ variant, size, className })} {...props}>
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </span>
  );
}

export default Badge;
