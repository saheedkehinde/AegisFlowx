'use client';

import React, { forwardRef, useId } from 'react';

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  description?: string;
  error?: string;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  (
    {
      className = '',
      label,
      description,
      error,
      id,
      disabled,
      rows = 4,
      ...props
    },
    ref
  ) => {
    const generatedId = useId();
    const textareaId = id || generatedId;
    const errorId = `${textareaId}-error`;
    const descriptionId = `${textareaId}-desc`;

    return (
      <div className="w-full space-y-1.5">
        {label && (
          <label
            htmlFor={textareaId}
            className="block text-xs font-semibold text-[var(--foreground)] tracking-wide"
          >
            {label}
          </label>
        )}

        <textarea
          ref={ref}
          id={textareaId}
          disabled={disabled}
          rows={rows}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? errorId : description ? descriptionId : undefined}
          className={`w-full rounded-xl border bg-[var(--surface)] text-[var(--foreground)] placeholder-[var(--muted-foreground)] p-3.5 text-xs sm:text-sm leading-relaxed transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:border-[var(--primary-orange)] focus-visible:outline-none ${
            error ? 'border-[var(--status-critical)] focus-visible:ring-[var(--status-critical)]' : 'border-[var(--border)] hover:border-[var(--border-strong)]'
          } ${className}`}
          {...props}
        />

        {description && !error && (
          <p id={descriptionId} className="text-[11px] text-[var(--muted-foreground)] leading-normal">
            {description}
          </p>
        )}

        {error && (
          <p id={errorId} className="text-[11px] font-medium text-[var(--status-critical)] leading-normal">
            {error}
          </p>
        )}
      </div>
    );
  }
);

Textarea.displayName = 'Textarea';
export default Textarea;
