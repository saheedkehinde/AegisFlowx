'use client';

import React, { forwardRef, useState, useId } from 'react';
import { Eye, EyeOff, Lock } from 'lucide-react';

export interface PasswordInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string;
  description?: string;
  error?: string;
  showLeftLockIcon?: boolean;
}

export const PasswordInput = forwardRef<HTMLInputElement, PasswordInputProps>(
  (
    {
      className = '',
      label,
      description,
      error,
      id,
      disabled,
      showLeftLockIcon = true,
      ...props
    },
    ref
  ) => {
    const [isVisible, setIsVisible] = useState(false);
    const generatedId = useId();
    const inputId = id || generatedId;
    const errorId = `${inputId}-error`;
    const descriptionId = `${inputId}-desc`;

    return (
      <div className="w-full space-y-1.5">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-xs font-semibold text-[var(--foreground)] tracking-wide"
          >
            {label}
          </label>
        )}

        <div className="relative flex items-center">
          {showLeftLockIcon && (
            <div className="pointer-events-none absolute left-3.5 flex items-center text-[var(--muted-foreground)]">
              <Lock className="h-4 w-4" />
            </div>
          )}

          <input
            ref={ref}
            id={inputId}
            type={isVisible ? 'text' : 'password'}
            disabled={disabled}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? errorId : description ? descriptionId : undefined}
            className={`w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] text-[var(--foreground)] placeholder-[var(--muted-foreground)] py-2.5 text-xs sm:text-sm transition-all duration-150 min-h-[42px] disabled:opacity-50 disabled:cursor-not-allowed focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-cyan)]/20 ${
              showLeftLockIcon ? 'pl-10' : 'pl-3.5'
            } pr-11 ${
              error ? 'border-[var(--status-critical)] focus:border-[var(--status-critical)] focus:ring-[var(--status-critical)]/20' : ''
            } ${className}`}
            {...props}
          />

          <button
            type="button"
            onClick={() => setIsVisible((prev) => !prev)}
            disabled={disabled}
            aria-label={isVisible ? 'Hide password' : 'Show password'}
            title={isVisible ? 'Hide password' : 'Show password'}
            className="absolute right-3 flex items-center justify-center p-1 rounded-lg text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-cyan)]/50"
          >
            {isVisible ? (
              <EyeOff className="h-4 w-4 text-[var(--accent-cyan)]" aria-hidden="true" />
            ) : (
              <Eye className="h-4 w-4 text-[var(--muted-foreground)] hover:text-[var(--foreground)]" aria-hidden="true" />
            )}
          </button>
        </div>

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

PasswordInput.displayName = 'PasswordInput';
export default PasswordInput;
