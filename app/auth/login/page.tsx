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
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 mb-6 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to AegisFlow Home</span>
        </Link>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 shadow-md shadow-cyan-500/20 ring-1 ring-white/20">
            <ShieldAlert className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">
              Aegis<span className="text-cyan-400">Flow</span>
            </h1>
            <p className="text-xs text-slate-400">Cybersecurity Analyst Authentication</p>
          </div>
        </div>
        <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-white">
          Sign in to your account
        </h2>
        <p className="mt-1 text-xs text-slate-400">
          Access your persistent threat investigation logs, case history, and security dossiers.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/90 p-6 sm:p-8 shadow-2xl backdrop-blur-xl">
          {!isConfigured && (
            <div className="mb-5 rounded-xl border border-amber-500/30 bg-amber-950/30 p-3.5 text-xs text-amber-300 leading-relaxed flex items-start gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
              <div>
                <strong className="text-white block font-semibold mb-0.5">
                  Supabase Not Configured
                </strong>
                Please provide <code className="font-mono text-amber-200">NEXT_PUBLIC_SUPABASE_URL</code> and <code className="font-mono text-amber-200">NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY</code> in your environment variables.
              </div>
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="mb-5 rounded-xl border border-red-500/30 bg-red-950/30 p-3.5 text-xs text-red-300 leading-relaxed flex items-start gap-2.5"
            >
              <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
              <div className="flex-1">
                <span>{error}</span>
                {unconfirmedEmail && (
                  <div className="mt-2.5 pt-2 border-t border-red-500/20">
                    <button
                      type="button"
                      onClick={handleResendConfirmation}
                      disabled={resendingEmail}
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer disabled:opacity-50"
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
            <div className="mb-5 rounded-xl border border-emerald-500/30 bg-emerald-950/30 p-3.5 text-xs text-emerald-300 leading-relaxed flex items-start gap-2.5">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
              <span>{message}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Analyst Email
              </label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                <input
                  id="email"
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@agency.internal"
                  className="w-full rounded-xl border border-white/10 bg-[#090d18] pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label
                  htmlFor="password"
                  className="block text-xs font-semibold text-slate-300"
                >
                  Password
                </label>
                <Link
                  href="/auth/forgot-password"
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                <input
                  id="password"
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-xl border border-white/10 bg-[#090d18] pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={loading}
                className="w-full min-h-[44px] flex items-center justify-center gap-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-600/30 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin text-white" />
                    <span>Verifying Credentials...</span>
                  </>
                ) : (
                  <>
                    <span>Sign In to AegisFlow</span>
                    <ArrowRight className="h-4 w-4 text-white" />
                  </>
                )}
              </button>
            </div>
          </form>

          <div className="mt-6 pt-5 border-t border-white/5 text-center text-xs text-slate-400">
            <span>Do not have an account yet? </span>
            <Link
              href="/auth/register"
              className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors"
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
        <div className="min-h-screen bg-[#070b14] flex items-center justify-center text-cyan-400">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <LoginFormContent />
    </Suspense>
  );
}
