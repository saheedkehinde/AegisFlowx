'use client';

import React, { useState, useEffect, Suspense, useRef } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
import { getCallbackUrl } from '@/lib/supabase/site-url';
import { useAuth } from '@/hooks/use-auth';
import {
  ShieldAlert,
  Lock,
  Mail,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ArrowLeft,
} from 'lucide-react';
import { PasswordInput } from '@/components/ui/PasswordInput';

function LoginFormContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, authState } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(
    searchParams.get('error') || null
  );
  const [message, setMessage] = useState<string | null>(
    searchParams.get('message') || null
  );
  const [unconfirmedEmail, setUnconfirmedEmail] = useState<string | null>(null);
  const [resendingEmail, setResendingEmail] = useState(false);
  const isConfigured = isSupabaseConfigured();

  // Ref to ensure redirect happens only ONCE
  const hasRedirectedRef = useRef(false);

  // If redirected with verification code or token_hash from confirmation email
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const tokenHash = params.get('token_hash');
    if (code || tokenHash) {
      window.location.href = `/auth/callback${window.location.search}`;
      return;
    }
  }, []);

  // Safe redirect when user is authenticated
  useEffect(() => {
    if (authState === 'authenticated' && user && !hasRedirectedRef.current) {
      hasRedirectedRef.current = true;
      const next = searchParams.get('next');
      const safeNext =
        next && next.startsWith('/') && !next.startsWith('//') && !next.includes('\\')
          ? next
          : '/investigations';
      router.replace(safeNext);
    }
  }, [authState, user, router, searchParams]);

  const handleResendConfirmation = async () => {
    if (!unconfirmedEmail) return;
    setResendingEmail(true);
    try {
      const supabase = createClient();
      const redirectUrl = getCallbackUrl('/investigations');
      const { error: resendError } = await supabase.auth.resend({
        type: 'signup',
        email: unconfirmedEmail,
        options: {
          emailRedirectTo: redirectUrl,
        },
      });

      if (resendError) {
        setError(resendError.message);
      } else {
        setMessage(
          `Confirmation email re-dispatched to ${unconfirmedEmail}. Please check your inbox and spam folder.`
        );
      }
    } catch (err: any) {
      setError(err.message || 'Failed to resend confirmation email.');
    } finally {
      setResendingEmail(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isConfigured) {
      setError(
        'Supabase is not configured yet. Please configure NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.'
      );
      return;
    }

    if (!email.trim() || !password) {
      setError('Please provide both your email and password.');
      return;
    }

    setLoading(true);
    setError(null);
    setMessage(null);
    setUnconfirmedEmail(null);

    try {
      const supabase = createClient();
      const { data, error: authError } = await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
      });

      if (authError) {
        if (authError.message.toLowerCase().includes('email not confirmed')) {
          setUnconfirmedEmail(email.trim());
          setError(
            'Your email address has not been confirmed yet. Please check your inbox and click the activation link before signing in.'
          );
        } else {
          setError(authError.message);
        }
        return;
      }

      if (data.session) {
        if (!hasRedirectedRef.current) {
          hasRedirectedRef.current = true;
          const next = searchParams.get('next');
          const safeNext =
            next && next.startsWith('/') && !next.startsWith('//') && !next.includes('\\')
              ? next
              : '/investigations';
          router.replace(safeNext);
        }
      }
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during sign in.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] cyber-grid radial-glow flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors duration-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-[var(--foreground-secondary)] hover:text-[var(--primary-orange)] mb-6 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to AegisFlow Home</span>
        </Link>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-[var(--primary-orange)] to-amber-700 shadow-md shadow-[var(--primary-orange-glow)]">
            <ShieldAlert className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
              Aegis<span className="text-[var(--primary-orange)]">Flow</span>
            </h1>
            <p className="text-xs text-[var(--muted-foreground)]">Cybersecurity Analyst Authentication</p>
          </div>
        </div>
        <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
          Sign in to your account
        </h2>
        <p className="mt-1 text-xs text-[var(--foreground-secondary)]">
          Access your persistent threat investigation logs, case history, and security dossiers.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 shadow-[var(--shadow-lg)]">
          {!isConfigured && (
            <div className="mb-5 rounded-xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-3.5 text-xs text-[var(--status-warning)] leading-relaxed flex items-start gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <div>
                <strong className="text-[var(--foreground)] block font-semibold mb-0.5">
                  Supabase Not Configured
                </strong>
                Please provide <code className="font-mono">NEXT_PUBLIC_SUPABASE_URL</code> and <code className="font-mono">NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY</code> in your environment variables.
              </div>
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="mb-5 rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-3.5 text-xs text-[var(--status-critical)] leading-relaxed flex items-start gap-2.5"
            >
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span>{error}</span>
                {unconfirmedEmail && (
                  <div className="mt-2.5 pt-2 border-t border-[var(--status-critical-border)]">
                    <button
                      type="button"
                      onClick={handleResendConfirmation}
                      disabled={resendingEmail}
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--accent-cyan)] hover:underline transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {resendingEmail ? (
                        <>
                          <Loader2 className="h-3 w-3 animate-spin" />
                          <span>Resending verification email...</span>
                        </>
                      ) : (
                        <span>&rarr; Click here to resend confirmation email to {unconfirmedEmail}</span>
                      )}
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {message && (
            <div className="mb-5 rounded-xl border border-[var(--status-success-border)] bg-[var(--status-success-bg)] p-3.5 text-xs text-[var(--status-success)] leading-relaxed flex items-start gap-2.5">
              <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{message}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-xs font-semibold text-[var(--foreground)] mb-1.5"
              >
                Analyst Email
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

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="password"
                  className="block text-xs font-semibold text-[var(--foreground)]"
                >
                  Password
                </label>
                <Link
                  href="/auth/forgot-password"
                  className="text-[11px] font-medium text-[var(--accent-cyan)] hover:underline transition-colors"
                >
                  Forgot password?
                </Link>
              </div>
              <PasswordInput
                id="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
              />
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
                    <span>Verifying Credentials...</span>
                  </>
                ) : (
                  <>
                    <span>Sign In to AegisFlow</span>
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>
          </form>

          <div className="mt-6 pt-5 border-t border-[var(--border-subtle)] text-center text-xs text-[var(--foreground-secondary)]">
            <span>Do not have an account yet? </span>
            <Link
              href="/auth/register"
              className="text-[var(--primary-orange)] hover:underline font-semibold transition-colors"
            >
              Create analyst account &rarr;
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[var(--background)] flex items-center justify-center text-[var(--primary-orange)]">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <LoginFormContent />
    </Suspense>
  );
}
