'use client';

import React, { forwardRef, useId } from 'react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  description?: string;
  error?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      className = '',
      type = 'text',
      label,
      description,
      error,
      leftIcon,
      rightIcon,
      id,
      disabled,
      ...props
    },
    ref
  ) => {
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
          {leftIcon && (
            <div className="absolute left-3 flex items-center pointer-events-none text-[var(--foreground-secondary)]">
              {leftIcon}
            </div>
          )}

          <input
            ref={ref}
            id={inputId}
            type={type}
            disabled={disabled}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? errorId : description ? descriptionId : undefined}
            className={`w-full rounded-xl border bg-[var(--surface)] text-[var(--foreground)] placeholder-[var(--muted-foreground)] px-3.5 py-2.5 text-xs sm:text-sm transition-all duration-150 min-h-[42px] disabled:opacity-50 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:border-[var(--primary-orange)] focus-visible:outline-none ${
              error ? 'border-[var(--status-critical)] focus-visible:ring-[var(--status-critical)]' : 'border-[var(--border)] hover:border-[var(--border-strong)]'
            } ${leftIcon ? 'pl-9' : ''} ${rightIcon ? 'pr-9' : ''} ${className}`}
            {...props}
          />

          {rightIcon && (
            <div className="absolute right-3 flex items-center pointer-events-none text-[var(--foreground-secondary)]">
              {rightIcon}
            </div>
          )}
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

Input.displayName = 'Input';
export default Input;
