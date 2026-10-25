'use client';

import React, { forwardRef } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { Loader2 } from 'lucide-react';

const buttonVariants = cva(
  'inline-flex items-center justify-center font-medium transition-all duration-150 rounded-xl whitespace-nowrap shrink-0 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 select-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none',
  {
    variants: {
      variant: {
        primary:
          'bg-[var(--primary-orange)] text-[var(--primary-foreground)] hover:bg-[var(--primary-deep-orange)] shadow-md shadow-[var(--primary-orange-glow)] active:scale-[0.98]',
        secondary:
          'border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground)] hover:bg-[var(--surface-interactive)] hover:border-[var(--border-strong)] active:scale-[0.98]',
        outline:
          'border border-[var(--border-strong)] bg-transparent text-[var(--foreground)] hover:bg-[var(--surface-interactive)] hover:border-[var(--primary-orange)] active:scale-[0.98]',
        ghost:
          'bg-transparent text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)]',
        destructive:
          'bg-[var(--status-critical-bg)] text-[var(--status-critical)] border border-[var(--status-critical-border)] hover:bg-[var(--status-critical)] hover:text-white active:scale-[0.98]',
        ai:
          'bg-[var(--accent-violet)] text-white hover:opacity-95 shadow-md shadow-[var(--accent-violet-subtle)] active:scale-[0.98]',
        cyan:
          'bg-[var(--accent-cyan)] text-[#080B12] hover:opacity-95 shadow-md shadow-[var(--accent-cyan-subtle)] active:scale-[0.98]',
      },
      size: {
        sm: 'text-xs px-3 py-1.5 min-h-[36px] gap-1.5',
        md: 'text-xs sm:text-sm px-4 py-2 min-h-[40px] sm:min-h-[44px] gap-2',
        lg: 'text-sm sm:text-base px-6 py-3 min-h-[48px] gap-2.5 font-semibold',
        icon: 'h-9 w-9 p-0 min-h-[36px] min-w-[36px] justify-center',
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className = '',
      variant,
      size,
      isLoading = false,
      leftIcon,
      rightIcon,
      children,
      disabled,
      ...props
    },
    ref
  ) => {
    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={buttonVariants({ variant, size, className })}
        {...props}
      >
        {isLoading ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin shrink-0" />
            <span>{children}</span>
          </>
        ) : (
          <>
            {leftIcon && <span className="shrink-0">{leftIcon}</span>}
            {children}
            {rightIcon && <span className="shrink-0">{rightIcon}</span>}
          </>
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';
export default Button;
