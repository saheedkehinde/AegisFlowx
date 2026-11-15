'use client';

import React, { useState, Suspense } from 'react';
import Link from 'next/link';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
import { getCallbackUrl } from '@/lib/supabase/site-url';
import {
  ShieldAlert,
  Mail,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ArrowLeft,
  KeyRound,
} from 'lucide-react';

function ForgotPasswordContent() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);

  const isConfigured = isSupabaseConfigured();

  const handleResetRequest = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!isConfigured) {
      setError(
        'Supabase is not configured yet. Please configure NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.'
      );
      return;
    }

    if (!email.trim()) {
      setError('Please provide your account email.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const supabase = createClient();
      const redirectUrl = getCallbackUrl('/auth/reset-password');

      const { error: resetError } = await supabase.auth.resetPasswordForEmail(
        email.trim(),
        {
          redirectTo: redirectUrl,
        }
      );

      if (resetError) {
        setError(resetError.message);
        return;
      }

      setSubmitted(true);
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred while requesting reset.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] cyber-grid radial-glow flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors duration-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <Link
          href="/auth/login"
          className="inline-flex items-center gap-1.5 text-xs text-[var(--foreground-secondary)] hover:text-[var(--primary-orange)] mb-6 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Sign In</span>
        </Link>

        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-[var(--primary-orange)] to-amber-700 shadow-md shadow-[var(--primary-orange-glow)]">
            <KeyRound className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
              Aegis<span className="text-[var(--primary-orange)]">Flow</span>
            </h1>
            <p className="text-xs text-[var(--muted-foreground)]">Credentials &amp; Security Recovery</p>
          </div>
        </div>

        <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
          Reset your password
        </h2>
        <p className="mt-1 text-xs text-[var(--foreground-secondary)]">
          Enter your registered email address and we will dispatch a secure recovery link.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 shadow-[var(--shadow-lg)]">
          {error && (
            <div
              role="alert"
              className="mb-5 rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-3.5 text-xs text-[var(--status-critical)] leading-relaxed flex items-start gap-2.5"
            >
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {submitted ? (
            <div className="text-center space-y-4">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--status-success-bg)] border border-[var(--status-success-border)] text-[var(--status-success)]">
                <CheckCircle2 className="h-6 w-6" />
              </div>
              <h3 className="text-base font-bold text-[var(--foreground)]">Recovery Link Dispatched</h3>
              <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed">
                If an account exists for <span className="font-mono text-[var(--accent-cyan)]">{email}</span>, you will receive an email containing a secure password reset link.
              </p>
              <div className="pt-2">
                <Link
                  href="/auth/login"
                  className="w-full min-h-[44px] flex items-center justify-center gap-2 rounded-xl bg-[var(--surface-interactive)] hover:bg-[var(--surface)] border border-[var(--border)] px-4 py-2.5 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
                >
                  <ArrowLeft className="h-4 w-4" />
                  <span>Return to Sign In</span>
                </Link>
              </div>
            </div>
          ) : (
            <form onSubmit={handleResetRequest} className="space-y-4">
              <div>
                <label
                  htmlFor="email"
                  className="block text-xs font-semibold text-[var(--foreground)] mb-1.5"
                >
                  Account Email
                </label>
                <div className="relative">
                  <Mail className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-[var(--muted-foreground)]" />
                  <input
                    id="email"
                    type="email"
                    required
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@agency.internal"
                    className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] pl-10 pr-4 py-2.5 text-xs sm:text-sm text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-cyan)]/20 min-h-[42px]"
                  />
                </div>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full min-h-[44px] flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2.5 text-xs sm:text-sm font-semibold text-[var(--primary-foreground)] shadow-md shadow-[var(--primary-orange-glow)] transition-all cursor-pointer disabled:opacity-50"
                >
                  {loading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>Sending Recovery Email...</span>
                    </>
                  ) : (
                    <>
                      <span>Send Recovery Instructions</span>
                      <ArrowRight className="h-4 w-4" />
                    </>
                  )}
                </button>
              </div>

              <div className="pt-2 text-center text-xs text-[var(--foreground-secondary)]">
                <Link
                  href="/auth/login"
                  className="text-[var(--accent-cyan)] hover:underline transition-colors"
                >
                  Remembered your password? Sign in &rarr;
                </Link>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ForgotPasswordPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[var(--background)] flex items-center justify-center text-[var(--primary-orange)]">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <ForgotPasswordContent />
    </Suspense>
  );
}
