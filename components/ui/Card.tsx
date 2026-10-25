'use client';

import React, { forwardRef } from 'react';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'standard' | 'elevated' | 'interactive' | 'glass';
  isHoverable?: boolean;
}

export const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ className = '', variant = 'standard', isHoverable = false, children, ...props }, ref) => {
    let variantStyles = 'bg-[var(--card-bg)] border-[var(--border)] shadow-[var(--shadow-sm)]';

    if (variant === 'elevated') {
      variantStyles = 'bg-[var(--surface-elevated)] border-[var(--border-strong)] shadow-[var(--shadow-md)]';
    } else if (variant === 'interactive') {
      variantStyles =
        'bg-[var(--card-bg)] border-[var(--border)] hover:border-[var(--card-hover-border)] hover:bg-[var(--surface-interactive)] transition-all duration-200 cursor-pointer shadow-[var(--shadow-sm)] hover:shadow-[var(--shadow-md)]';
    } else if (variant === 'glass') {
      variantStyles = 'glass-panel shadow-[var(--shadow-md)]';
    }

    const hoverClass = isHoverable && variant !== 'interactive' ? 'hover:border-[var(--card-hover-border)] transition-colors' : '';

    return (
      <div
        ref={ref}
        className={`rounded-2xl border ${variantStyles} ${hoverClass} p-5 sm:p-6 ${className}`}
        {...props}
      >
        {children}
      </div>
    );
  }
);

Card.displayName = 'Card';

export const CardHeader = forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className = '', children, ...props }, ref) => (
    <div ref={ref} className={`border-b border-[var(--border-subtle)] pb-4 mb-4 ${className}`} {...props}>
      {children}
    </div>
  )
);
CardHeader.displayName = 'CardHeader';

export const CardTitle = forwardRef<HTMLHeadingElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className = '', children, ...props }, ref) => (
    <h3
      ref={ref}
      className={`text-base sm:text-lg font-bold tracking-tight text-[var(--foreground)] ${className}`}
      {...props}
    >
      {children}
    </h3>
  )
);
CardTitle.displayName = 'CardTitle';

export const CardDescription = forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ className = '', children, ...props }, ref) => (
    <p
      ref={ref}
      className={`text-xs sm:text-sm text-[var(--foreground-secondary)] mt-1 leading-relaxed ${className}`}
      {...props}
    >
      {children}
    </p>
  )
);
CardDescription.displayName = 'CardDescription';

export const CardContent = forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className = '', children, ...props }, ref) => (
    <div ref={ref} className={`space-y-4 ${className}`} {...props}>
      {children}
    </div>
  )
);
CardContent.displayName = 'CardContent';

export const CardFooter = forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className = '', children, ...props }, ref) => (
    <div
      ref={ref}
      className={`border-t border-[var(--border-subtle)] pt-4 mt-5 flex flex-wrap items-center justify-between gap-3 ${className}`}
      {...props}
    >
      {children}
    </div>
  )
);
CardFooter.displayName = 'CardFooter';
