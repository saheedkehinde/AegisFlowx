'use client';

import React, { useState, Suspense } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
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

function RegisterFormContent() {
  const router = useRouter();
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [registeredEmail, setRegisteredEmail] = useState<string | null>(null);

  const isConfigured = isSupabaseConfigured();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!isConfigured) {
      setError(
        'Supabase is not configured yet. Please configure NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.'
      );
      return;
    }

    if (!email.trim() || !password) {
      setError('Please provide an email address and password.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match. Please verify your password entry.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const supabase = createClient();
      const redirectUrl = `${window.location.origin}/auth/callback?next=/investigations`;

      const { data, error: signUpError } = await supabase.auth.signUp({
        email: email.trim(),
        password,
        options: {
          data: {
            display_name: displayName.trim() || undefined,
          },
          emailRedirectTo: redirectUrl,
        },
      });

      if (signUpError) {
        setError(signUpError.message);
        return;
      }

      // Check whether email confirmation is required by Supabase
      if (data.user && !data.session) {
        // Confirmation email dispatched by Supabase
        setRegisteredEmail(email.trim());
      } else if (data.session) {
        // Auto-confirmed or confirmations disabled
        router.push('/investigations');
        router.refresh();
      } else {
        setRegisteredEmail(email.trim());
      }
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during account creation.');
    } finally {
      setLoading(false);
    }
  };

  // If user completed sign up and needs email confirmation
  if (registeredEmail) {
    return (
      <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <div className="rounded-2xl border border-cyan-500/30 bg-[#0d1322]/95 p-6 sm:p-8 shadow-2xl backdrop-blur-xl text-center space-y-5">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400">
              <Mail className="h-7 w-7 animate-bounce" />
            </div>

            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
              Check Your Inbox
            </h2>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              We sent a verification link to <br />
              <strong className="text-cyan-300 font-mono text-sm">{registeredEmail}</strong>.
            </p>

            <div className="rounded-xl border border-white/5 bg-[#090d18] p-4 text-left text-xs text-slate-400 space-y-2">
              <div className="flex items-start gap-2">
                <Check className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>Click the link in the email to activate your analyst account.</span>
              </div>
              <div className="flex items-start gap-2">
                <Check className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>Your profile will be securely provisioned upon verification.</span>
              </div>
            </div>

            <div className="pt-2 flex flex-col gap-2">
              <Link
                href="/auth/login"
                className="w-full flex items-center justify-center gap-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-600/30 transition-all cursor-pointer"
              >
                <span>Proceed to Sign In</span>
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/"
                className="text-xs text-slate-400 hover:text-white transition-colors py-1"
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
            <p className="text-xs text-slate-400">Analyst Registration & Identity</p>
          </div>
        </div>

        <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-white">
          Create analyst account
        </h2>
        <p className="mt-1 text-xs text-slate-400">
          Provision an encrypted, user-isolated workspace for threat analysis history and case dossiers.
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
                Please provide <code className="font-mono text-amber-200">NEXT_PUBLIC_SUPABASE_URL</code> and <code className="font-mono text-amber-200">NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY</code> in environment variables.
              </div>
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="mb-5 rounded-xl border border-red-500/30 bg-red-950/30 p-3.5 text-xs text-red-300 leading-relaxed flex items-start gap-2.5"
            >
              <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label
                htmlFor="displayName"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Analyst Name / Call-Sign
              </label>
              <div className="relative">
                <User className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                <input
                  id="displayName"
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. Sentinel-01 or Alex Vance"
                  className="w-full rounded-xl border border-white/10 bg-[#090d18] pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/20"
                />
              </div>
            </div>

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
              <label
                htmlFor="password"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Master Password (min 6 chars)
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                <input
                  id="password"
                  type="password"
                  required
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-xl border border-white/10 bg-[#090d18] pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                <input
                  id="confirmPassword"
                  type="password"
                  required
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
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
                    <span>Provisioning Workspace...</span>
                  </>
                ) : (
                  <>
                    <span>Create Account & Join AegisFlow</span>
                    <ArrowRight className="h-4 w-4 text-white" />
                  </>
                )}
              </button>
            </div>
          </form>

          <div className="mt-6 pt-5 border-t border-white/5 text-center text-xs text-slate-400">
            <span>Already have an account? </span>
            <Link
              href="/auth/login"
              className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors"
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
        <div className="min-h-screen bg-[#070b14] flex items-center justify-center text-cyan-400">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <RegisterFormContent />
    </Suspense>
  );
}
