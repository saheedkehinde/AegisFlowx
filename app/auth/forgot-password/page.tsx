'use client';

import React, { useState, Suspense } from 'react';
import Link from 'next/link';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
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
      const redirectUrl = `${window.location.origin}/auth/callback?next=/auth/reset-password`;

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
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <Link
          href="/auth/login"
          className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 mb-6 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Sign In</span>
        </Link>

        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 shadow-md shadow-cyan-500/20 ring-1 ring-white/20">
            <KeyRound className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">
              Aegis<span className="text-cyan-400">Flow</span>
            </h1>
            <p className="text-xs text-slate-400">Credentials & Security Recovery</p>
          </div>
        </div>

        <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-white">
          Reset your password
        </h2>
        <p className="mt-1 text-xs text-slate-400">
          Enter your registered email address and we will dispatch a secure recovery link.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/90 p-6 sm:p-8 shadow-2xl backdrop-blur-xl">
          {error && (
            <div
              role="alert"
              className="mb-5 rounded-xl border border-red-500/30 bg-red-950/30 p-3.5 text-xs text-red-300 leading-relaxed flex items-start gap-2.5"
            >
              <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {submitted ? (
            <div className="text-center space-y-4">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
                <CheckCircle2 className="h-6 w-6" />
              </div>
              <h3 className="text-base font-bold text-white">Recovery Link Dispatched</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                If an account exists for <span className="font-mono text-cyan-300">{email}</span>, you will receive an email containing a secure password reset link.
              </p>
              <div className="pt-2">
                <Link
                  href="/auth/login"
                  className="w-full flex items-center justify-center gap-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/10 px-4 py-2.5 text-xs font-semibold text-white transition-colors cursor-pointer"
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
                  className="block text-xs font-semibold text-slate-300 mb-1"
                >
                  Account Email
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

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full min-h-[44px] flex items-center justify-center gap-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-600/30 transition-all cursor-pointer disabled:opacity-50"
                >
                  {loading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin text-white" />
                      <span>Sending Recovery Email...</span>
                    </>
                  ) : (
                    <>
                      <span>Send Recovery Instructions</span>
                      <ArrowRight className="h-4 w-4 text-white" />
                    </>
                  )}
                </button>
              </div>

              <div className="pt-2 text-center text-xs text-slate-400">
                <Link
                  href="/auth/login"
                  className="text-cyan-400 hover:text-cyan-300 transition-colors"
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
        <div className="min-h-screen bg-[#070b14] flex items-center justify-center text-cyan-400">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <ForgotPasswordContent />
    </Suspense>
  );
}
