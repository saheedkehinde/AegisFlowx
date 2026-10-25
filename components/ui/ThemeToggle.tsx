'use client';

import React, { useSyncExternalStore } from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { useTheme, Theme } from '@/lib/theme-context';

interface ThemeToggleProps {
  variant?: 'button' | 'segmented';
  className?: string;
}

const emptySubscribe = () => () => {};

function useIsClient() {
  return useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false
  );
}

export default function ThemeToggle({ variant = 'button', className = '' }: ThemeToggleProps) {
  const { theme, resolvedTheme, setTheme, toggleTheme } = useTheme();
  const isClient = useIsClient();

  if (!isClient) {
    // Render placeholder to avoid layout shift and SSR mismatch
    return (
      <div
        className={`h-9 w-9 rounded-xl border border-[var(--border)] bg-[var(--surface)] opacity-50 ${className}`}
        aria-hidden="true"
      />
    );
  }

  if (variant === 'segmented') {
    const options: { value: Theme; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
      { value: 'dark', label: 'Dark', icon: Moon },
      { value: 'light', label: 'Light', icon: Sun },
      { value: 'system', label: 'System', icon: Monitor },
    ];

    return (
      <div
        role="group"
        aria-label="Theme selection"
        className={`inline-flex items-center gap-1 p-1 rounded-xl border border-[var(--border)] bg-[var(--background-secondary)] ${className}`}
      >
        {options.map((opt) => {
          const Icon = opt.icon;
          const isSelected = theme === opt.value;
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => setTheme(opt.value)}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-all duration-150 min-h-[36px] cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none ${
                isSelected
                  ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm font-semibold'
                  : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)]'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span>{opt.label}</span>
            </button>
          );
        })}
      </div>
    );
  }

  // Single toggle button for TopBar
  const isDark = resolvedTheme === 'dark';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode (currently ${resolvedTheme})`}
      title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
      className={`relative flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors duration-150 cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none shadow-sm ${className}`}
    >
      {isDark ? (
        <Sun className="h-4 w-4 text-[var(--accent-amber)] transition-transform duration-200 hover:rotate-45" />
      ) : (
        <Moon className="h-4 w-4 text-[var(--primary-orange)] transition-transform duration-200 hover:-rotate-12" />
      )}
    </button>
  );
}
