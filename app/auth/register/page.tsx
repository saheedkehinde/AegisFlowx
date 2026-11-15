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
  User,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ArrowLeft,
  KeyRound,
  ShieldCheck,
  Check,
} from 'lucide-react';
import { PasswordInput } from '@/components/ui/PasswordInput';

function RegisterFormContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, authState } = useAuth();
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(() => {
    return searchParams.get('error_description') || searchParams.get('error') || null;
  });
  const [registeredEmail, setRegisteredEmail] = useState<string | null>(null);
  const isConfigured = isSupabaseConfigured();

  const hasRedirectedRef = useRef(false);

  // If a confirmation link or OAuth provider redirected here with code or hash
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

  // Safe redirect if already authenticated
  useEffect(() => {
    if (authState === 'authenticated' && user && !hasRedirectedRef.current) {
      hasRedirectedRef.current = true;
      router.replace('/investigations');
    }
  }, [authState, user, router]);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isConfigured) {
      setError(
        'Supabase is not configured yet. Please configure NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.'
      );
      return;
    }

    if (!email.trim() || !password) {
      setError('Please provide an email and password.');
      return;
    }

    if (password.length < 6) {
      setError('Master password must be at least 6 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const supabase = createClient();
      const redirectUrl = getCallbackUrl('/investigations');

      const { data, error: signUpError } = await supabase.auth.signUp({
        email: email.trim(),
        password,
        options: {
          emailRedirectTo: redirectUrl,
          data: {
            display_name: displayName.trim() || email.split('@')[0],
          },
        },
      });

      if (signUpError) {
        setError(signUpError.message);
        return;
      }

      // Check if user session was immediately established
      if (data?.session) {
        if (!hasRedirectedRef.current) {
          hasRedirectedRef.current = true;
          router.replace('/investigations');
        }
        return;
      }

      setRegisteredEmail(email.trim());
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during registration.');
    } finally {
      setLoading(false);
    }
  };

  if (registeredEmail) {
    return (
      <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] cyber-grid radial-glow flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors duration-200">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <div className="flex items-center gap-3 justify-center mb-6">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-[var(--primary-orange)] to-amber-700 shadow-md shadow-[var(--primary-orange-glow)]">
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
                Aegis<span className="text-[var(--primary-orange)]">Flow</span>
              </h1>
              <p className="text-xs text-[var(--muted-foreground)]">Analyst Registration Complete</p>
            </div>
          </div>

          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-8 shadow-[var(--shadow-lg)] text-center space-y-5">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]">
              <Mail className="h-7 w-7" />
            </div>

            <div>
              <h2 className="text-xl font-bold text-[var(--foreground)] font-[family-name:var(--font-display)]">
                Verification Email Dispatched
              </h2>
              <p className="mt-2 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                We sent a secure activation link to:
                <br />
                <span className="font-mono text-[var(--accent-cyan)] font-semibold mt-1 inline-block text-sm">
                  {registeredEmail}
                </span>
              </p>
            </div>

            <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] p-4 text-xs text-[var(--foreground-secondary)] text-left space-y-2.5">
              <div className="flex items-center gap-2 text-[var(--foreground)] font-semibold">
                <ShieldCheck className="h-4 w-4 text-[var(--accent-cyan)]" />
                <span>Next steps to unlock your vault:</span>
              </div>
              <ul className="space-y-1.5 text-[11px] list-disc list-inside">
                <li>Check your inbox and spam/junk folder.</li>
                <li>Tap <strong className="text-[var(--foreground)]">Confirm your mail</strong>.</li>
                <li>You will be redirected straight to your private Case Vault.</li>
              </ul>
            </div>

            <div className="pt-2 flex flex-col gap-2">
              <Link
                href="/auth/login"
                className="w-full min-h-[44px] flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2.5 text-xs font-semibold text-[var(--primary-foreground)] shadow-md shadow-[var(--primary-orange-glow)] transition-all cursor-pointer"
              >
                <span>Proceed to Sign In</span>
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/"
                className="text-xs text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors py-1"
              >
                Return to AegisFlow Home
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

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
            <p className="text-xs text-[var(--muted-foreground)]">Analyst Registration &amp; Identity</p>
          </div>
        </div>
        <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
          Create analyst account
        </h2>
        <p className="mt-1 text-xs text-[var(--foreground-secondary)]">
          Provision a user-isolated workspace protected by row-level security (RLS) for threat analysis history and case dossiers.
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
                Please provide <code className="font-mono">NEXT_PUBLIC_SUPABASE_URL</code> and <code className="font-mono">NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY</code> in environment variables.
              </div>
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="mb-5 rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-3.5 text-xs text-[var(--status-critical)] leading-relaxed flex items-start gap-2.5"
            >
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label
                htmlFor="displayName"
                className="block text-xs font-semibold text-[var(--foreground)] mb-1.5"
              >
                Analyst Name / Call-Sign
              </label>
              <div className="relative">
                <User className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-[var(--muted-foreground)]" />
                <input
                  id="displayName"
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. Sentinel-01 or Alex Vance"
                  className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] pl-10 pr-4 py-2.5 text-xs sm:text-sm text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-cyan)]/20 min-h-[42px]"
                />
              </div>
            </div>

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
              <label
                htmlFor="password"
                className="block text-xs font-semibold text-[var(--foreground)] mb-1.5"
              >
                Master Password (min 6 chars)
              </label>
              <PasswordInput
                id="password"
                required
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
              />
            </div>

            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-xs font-semibold text-[var(--foreground)] mb-1.5"
              >
                Confirm Password
              </label>
              <PasswordInput
                id="confirmPassword"
                required
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
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
                    <span>Provisioning Workspace...</span>
                  </>
                ) : (
                  <>
                    <span>Create Account &amp; Join AegisFlow</span>
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>
          </form>

          <div className="mt-6 pt-5 border-t border-[var(--border-subtle)] text-center text-xs text-[var(--foreground-secondary)]">
            <span>Already have an account? </span>
            <Link
              href="/auth/login"
              className="text-[var(--primary-orange)] hover:underline font-semibold transition-colors"
            >
              Sign in here &rarr;
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function RegisterPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[var(--background)] flex items-center justify-center text-[var(--primary-orange)]">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <RegisterFormContent />
    </Suspense>
  );
}
