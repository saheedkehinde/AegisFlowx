'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Menu,
  Search,
  Sliders,
  X,
  LogOut,
  LogIn,
  ChevronDown,
  SearchCode,
  Loader2,
  ShieldCheck,
} from 'lucide-react';
import { NAV_ITEMS } from './Sidebar';
import { useAuth } from '@/hooks/use-auth';
import ThemeToggle from '@/components/ui/ThemeToggle';

interface TopBarProps {
  onOpenMobileMenu: () => void;
}

export default function TopBar({ onOpenMobileMenu }: TopBarProps) {
  const router = useRouter();
  const { user, profile, loading: authLoading, signOut } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const pathname = usePathname();
  const [showSearchModal, setShowSearchModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Quick module search filter
  const searchResults = NAV_ITEMS.filter((item) =>
    item.name.toLowerCase().includes(searchQuery.toLowerCase().trim())
  );

  return (
    <>
      <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-[var(--topbar-border)] bg-[var(--topbar-bg)] px-4 backdrop-blur-md sm:px-6 lg:px-8 transition-colors duration-200">
        {/* Left Section: Mobile Menu Toggle & Title */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onOpenMobileMenu}
            aria-label="Open mobile menu"
            className="flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] lg:hidden transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
          >
            <Menu className="h-5 w-5" />
          </button>

          {/* Quick Search Trigger */}
          <button
            type="button"
            onClick={() => setShowSearchModal(true)}
            className="hidden sm:flex items-center gap-2.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none shadow-sm"
          >
            <Search className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
            <span>Search modules &amp; tools...</span>
            <kbd className="ml-2 font-mono text-[10px] bg-[var(--background)] text-[var(--muted-foreground)] px-1.5 py-0.5 rounded border border-[var(--border)]">
              /
            </kbd>
          </button>
        </div>

        {/* Right Section: System Theme Toggle & User Status */}
        <div className="flex items-center gap-2.5 sm:gap-3">
          {/* Mobile search button */}
          <button
            type="button"
            onClick={() => setShowSearchModal(true)}
            aria-label="Search modules"
            className="flex sm:hidden h-9 w-9 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
          >
            <Search className="h-4 w-4" />
          </button>

          {/* Theme Toggle Control */}
          <ThemeToggle />

          {/* User Profile / Authentication State */}
          <div className="relative">
            {authLoading ? (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] text-xs text-[var(--foreground-secondary)]">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--primary-orange)]" />
                <span className="hidden sm:inline">Checking session...</span>
              </div>
            ) : user ? (
              <>
                <button
                  type="button"
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="flex items-center gap-2.5 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] p-1.5 sm:px-3 sm:py-1.5 transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none shadow-sm"
                >
                  <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-[var(--primary-orange)] to-amber-700 text-white font-bold text-xs shadow-inner">
                    {(profile?.display_name || user.email || 'A').slice(0, 1).toUpperCase()}
                  </div>
                  <div className="hidden sm:flex flex-col text-left">
                    <span className="text-xs font-semibold text-[var(--foreground)] leading-tight truncate max-w-[120px]">
                      {profile?.display_name || user.email?.split('@')[0] || 'Analyst'}
                    </span>
                    <span className="text-[10px] font-mono text-[var(--status-success)] leading-tight flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-success)]" />
                      Verified
                    </span>
                  </div>
                  <ChevronDown className="h-3.5 w-3.5 text-[var(--foreground-secondary)] hidden sm:block" />
                </button>

                {showUserMenu && (
                  <>
                    <div
                      className="fixed inset-0 z-40"
                      onClick={() => setShowUserMenu(false)}
                    />
                    <div className="absolute right-0 top-11 z-50 w-64 rounded-2xl border border-[var(--border-strong)] bg-[var(--surface-elevated)] p-3.5 shadow-2xl backdrop-blur-xl">
                      {/* User Info Header */}
                      <div className="border-b border-[var(--border-subtle)] pb-3">
                        <div className="flex items-center gap-2.5">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/40 text-[var(--primary-orange)] font-bold text-sm">
                            {(profile?.display_name || user.email || 'A').slice(0, 1).toUpperCase()}
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-bold text-[var(--foreground)] truncate">
                              {profile?.display_name || 'Cyber Analyst'}
                            </p>
                            <p className="text-[11px] font-mono text-[var(--muted-foreground)] truncate">
                              {user.email}
                            </p>
                          </div>
                        </div>
                      </div>

                      {/* Navigation Links */}
                      <div className="py-2 space-y-1">
                        <Link
                          href="/investigations"
                          onClick={() => setShowUserMenu(false)}
                          className="flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-xs text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)] transition-colors"
                        >
                          <SearchCode className="h-4 w-4 text-[var(--primary-orange)]" />
                          <span>Personal Case Files</span>
                        </Link>
                        <Link
                          href="/settings"
                          onClick={() => setShowUserMenu(false)}
                          className="flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-xs text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)] transition-colors"
                        >
                          <Sliders className="h-4 w-4 text-[var(--primary-orange)]" />
                          <span>Platform &amp; Diagnostics</span>
                        </Link>
                      </div>

                      {/* Sign Out Action */}
                      <div className="border-t border-[var(--border-subtle)] pt-2">
                        <button
                          type="button"
                          disabled={signingOut}
                          onClick={async () => {
                            setSigningOut(true);
                            await signOut();
                            setShowUserMenu(false);
                            setSigningOut(false);
                            router.push('/auth/login?message=Signed+out+successfully.');
                            router.refresh();
                          }}
                          className="w-full flex items-center gap-2 rounded-xl px-2.5 py-2 text-xs font-medium text-[var(--status-critical)] hover:bg-[var(--status-critical-bg)] transition-colors cursor-pointer disabled:opacity-50"
                        >
                          {signingOut ? (
                            <>
                              <Loader2 className="h-4 w-4 animate-spin" />
                              <span>Signing Out...</span>
                            </>
                          ) : (
                            <>
                              <LogOut className="h-4 w-4" />
                              <span>Sign Out</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </>
            ) : (
              <div className="flex items-center gap-2">
                <Link
                  href="/auth/login?next=/investigations"
                  className="flex items-center gap-1.5 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-3 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] shadow-sm shadow-[var(--primary-orange-glow)] transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
                >
                  <LogIn className="h-3.5 w-3.5" />
                  <span>Sign In</span>
                </Link>
                <Link
                  href="/auth/register"
                  className="hidden md:inline-flex items-center gap-1 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-medium text-[var(--foreground)] transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
                >
                  <span>Register</span>
                </Link>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Global Quick Search Modal */}
      {showSearchModal && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 p-4 bg-black/70 backdrop-blur-sm">
          <div
            className="fixed inset-0 -z-10"
            onClick={() => setShowSearchModal(false)}
          />
          <div className="relative w-full max-w-lg rounded-2xl border border-[var(--border-strong)] bg-[var(--surface-elevated)] p-4 shadow-2xl">
            <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] pb-3">
              <Search className="h-4 w-4 text-[var(--primary-orange)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Jump to module (e.g. Analyze, Intelligence, Academy)..."
                autoFocus
                className="w-full bg-transparent text-sm text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowSearchModal(false)}
                className="text-[var(--foreground-secondary)] hover:text-[var(--foreground)] p-1 rounded-lg"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-3 space-y-1 max-h-60 overflow-y-auto">
              {searchResults.length > 0 ? (
                searchResults.map((item) => {
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={() => setShowSearchModal(false)}
                      className="flex items-center justify-between rounded-lg p-2.5 text-xs text-[var(--foreground-secondary)] hover:bg-[var(--surface-interactive)] hover:text-[var(--foreground)] transition-colors"
                    >
                      <div className="flex items-center gap-2.5">
                        <Icon className="h-4 w-4 text-[var(--primary-orange)]" />
                        <span className="font-medium">{item.name}</span>
                      </div>
                      <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
                        {item.href}
                      </span>
                    </Link>
                  );
                })
              ) : (
                <div className="p-4 text-center text-xs text-[var(--muted-foreground)]">
                  No modules found matching &ldquo;{searchQuery}&rdquo;.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
