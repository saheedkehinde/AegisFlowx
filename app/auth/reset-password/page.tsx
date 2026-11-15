'use client';

import React, { useState, Suspense, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
import {
  ShieldAlert,
  Lock,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ArrowLeft,
  KeyRound,
} from 'lucide-react';
import { PasswordInput } from '@/components/ui/PasswordInput';

function ResetPasswordContent() {
  const router = useRouter();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const isConfigured = isSupabaseConfigured();

  const handleUpdatePassword = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!isConfigured) {
      setError(
        'Supabase is not configured yet. Please configure NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.'
      );
      return;
    }

    if (!newPassword || newPassword.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const supabase = createClient();
      const { error: updateError } = await supabase.auth.updateUser({
        password: newPassword,
      });

      if (updateError) {
        setError(updateError.message);
        return;
      }

      setSuccess(true);
      setTimeout(() => {
        router.push('/investigations');
      }, 2000);
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred while updating your password.');
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
            <Lock className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
              Aegis<span className="text-[var(--primary-orange)]">Flow</span>
            </h1>
            <p className="text-xs text-[var(--muted-foreground)]">Security Credentials Update</p>
          </div>
        </div>

        <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-[var(--foreground)] font-[family-name:var(--font-display)]">
          Set New Password
        </h2>
        <p className="mt-1 text-xs text-[var(--foreground-secondary)]">
          Enter your new master passphrase to re-secure your analyst account.
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

          {success ? (
            <div className="text-center space-y-4">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--status-success-bg)] border border-[var(--status-success-border)] text-[var(--status-success)]">
                <CheckCircle2 className="h-6 w-6" />
              </div>
              <h3 className="text-base font-bold text-[var(--foreground)]">Password Updated Successfully</h3>
              <p className="text-xs text-[var(--foreground-secondary)]">
                Redirecting you to your investigation workspace...
              </p>
              <div className="pt-2">
                <Link
                  href="/investigations"
                  className="w-full min-h-[44px] flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2.5 text-xs font-semibold text-[var(--primary-foreground)] transition-colors cursor-pointer"
                >
                  <span>Go to Investigations Now</span>
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </div>
            </div>
          ) : (
            <form onSubmit={handleUpdatePassword} className="space-y-4">
              <div>
                <label
                  htmlFor="newPassword"
                  className="block text-xs font-semibold text-[var(--foreground)] mb-1.5"
                >
                  New Password (min 6 chars)
                </label>
                <PasswordInput
                  id="newPassword"
                  required
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••••••"
                />
              </div>

              <div>
                <label
                  htmlFor="confirmPassword"
                  className="block text-xs font-semibold text-[var(--foreground)] mb-1.5"
                >
                  Confirm New Password
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
                      <span>Updating Credentials...</span>
                    </>
                  ) : (
                    <>
                      <span>Save New Password</span>
                      <ArrowRight className="h-4 w-4" />
                    </>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[var(--background)] flex items-center justify-center text-[var(--primary-orange)]">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <ResetPasswordContent />
    </Suspense>
  );
}
