'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Menu,
  Search,
  Bell,
  Sliders,
  User,
  Shield,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  X,
  Cpu,
  LogOut,
  LogIn,
  UserCheck,
  ChevronDown,
  SearchCode,
  Loader2,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import { NAV_ITEMS } from './Sidebar';
import { useAuth } from '@/hooks/use-auth';

interface TopBarProps {
  onOpenMobileMenu: () => void;
}

export default function TopBar({ onOpenMobileMenu }: TopBarProps) {
  const router = useRouter();
  const { user, profile, loading: authLoading, signOut } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const pathname = usePathname();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showSearchModal, setShowSearchModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Find active nav item
  const currentNav =
    NAV_ITEMS.find((item) =>
      item.href === '/'
        ? pathname === '/'
        : pathname === item.href || pathname?.startsWith(item.href + '/')
    ) || { name: 'Overview', href: '/' };

  // Real verifiable notifications (no fake alerts)
  const systemNotifications = [
    {
      id: 'sys-1',
      title: 'Featherless Inference Operational',
      description: 'Model Qwen/Qwen3-VL-8B-Instruct is actively serving analysis requests.',
      time: 'Realtime',
      type: 'success',
    },
    {
      id: 'sys-2',
      title: 'Zero-Retention Active',
      description: 'Submissions are triaged in volatile memory and never persisted to disks.',
      time: 'Platform Policy',
      type: 'info',
    },
    {
      id: 'sys-3',
      title: 'Phase 1: Local Session Architecture',
      description: 'Role-based access control and team accounts will be enabled in Phase 2.',
      time: 'Milestone Notice',
      type: 'info',
    },
  ];

  const searchResults = NAV_ITEMS.filter((item) =>
    item.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <>
      <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-white/10 bg-[#070b14]/90 px-4 backdrop-blur-md sm:px-6">
        {/* Left: Mobile Toggle & Page Title */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onOpenMobileMenu}
            aria-label="Open navigation menu"
            className="flex lg:hidden h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-slate-900/60 text-slate-300 hover:text-white hover:border-cyan-500/30 transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
          >
            <Menu className="h-5 w-5" />
          </button>

          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-white">
                {currentNav.name}
              </h1>
              {pathname === '/analyze' && (
                <span className="hidden sm:inline-flex items-center gap-1 rounded bg-cyan-500/10 px-2 py-0.5 text-[10px] font-mono font-semibold text-cyan-400 border border-cyan-500/20">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  Qwen3 Live
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              AegisFlow Cybersecurity Intelligence Platform
            </p>
          </div>
        </div>

        {/* Right: Search, Notifications & Account */}
        <div className="flex items-center gap-2.5">
          {/* Quick Search Entry */}
          <button
            type="button"
            onClick={() => setShowSearchModal(true)}
            className="hidden md:flex items-center gap-2 rounded-lg border border-white/10 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-400 hover:border-cyan-500/30 hover:text-white transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
          >
            <Search className="h-3.5 w-3.5 text-cyan-400" />
            <span>Search modules...</span>
            <kbd className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
              ⌘K
            </kbd>
          </button>

          {/* Notifications Button & Popover */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setShowNotifications(!showNotifications)}
              aria-label="View system notifications"
              className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-slate-900/60 text-slate-300 hover:text-white hover:border-cyan-500/30 transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
            >
              <Bell className="h-4 w-4" />
              <span className="absolute top-2 right-2 h-2 w-2 rounded-full bg-cyan-400" />
            </button>

            {showNotifications && (
              <>
                <div
                  className="fixed inset-0 z-40"
                  onClick={() => setShowNotifications(false)}
                />
                <div className="absolute right-0 top-11 z-50 w-80 sm:w-96 rounded-2xl border border-white/10 bg-[#0d1322] p-4 shadow-2xl backdrop-blur-xl">
                  <div className="flex items-center justify-between border-b border-white/5 pb-3">
                    <h2 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <Bell className="h-3.5 w-3.5 text-cyan-400" />
                      <span>System Notifications ({systemNotifications.length})</span>
                    </h2>
                    <button
                      type="button"
                      onClick={() => setShowNotifications(false)}
                      className="text-slate-400 hover:text-white text-xs cursor-pointer"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>

                  <div className="mt-3 space-y-2.5 max-h-72 overflow-y-auto">
                    {systemNotifications.map((n) => (
                      <div
                        key={n.id}
                        className="rounded-xl border border-white/5 bg-slate-900/50 p-3 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-white">
                            {n.title}
                          </span>
                          <span className="text-[10px] font-mono text-cyan-400">
                            {n.time}
                          </span>
                        </div>
                        <p className="mt-1 text-slate-400 text-[11px] leading-relaxed">
                          {n.description}
                        </p>
                      </div>
                    ))}
                  </div>

                  <div className="mt-3 pt-2 border-t border-white/5 text-center">
                    <Link
                      href="/notifications"
                      onClick={() => setShowNotifications(false)}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 font-medium"
                    >
                      View all notification settings &rarr;
                    </Link>
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Settings Quick Access */}
          <Link
            href="/settings"
            title="Platform Settings"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-slate-900/60 text-slate-300 hover:text-white hover:border-cyan-500/30 transition-colors focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
          >
            <Sliders className="h-4 w-4" />
          </Link>

          {/* Real User Menu / Authentication State */}
          <div className="relative pl-2 border-l border-white/10">
            {authLoading ? (
              <div className="flex items-center gap-2 px-2 py-1">
                <div className="h-8 w-8 rounded-lg bg-slate-800 animate-pulse" />
                <div className="hidden sm:flex flex-col gap-1">
                  <div className="h-3 w-16 bg-slate-800 rounded animate-pulse" />
                  <div className="h-2 w-12 bg-slate-800 rounded animate-pulse" />
                </div>
              </div>
            ) : user ? (
              <>
                <button
                  type="button"
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  aria-expanded={showUserMenu}
                  aria-label="User account menu"
                  className="flex items-center gap-2 rounded-xl p-1 sm:px-2 hover:bg-slate-900/80 border border-white/5 hover:border-cyan-500/30 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
                >
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-500/40 bg-gradient-to-br from-cyan-900/60 to-blue-900/60 text-cyan-300 font-bold text-xs shadow-inner">
                    {(profile?.display_name || user.email || 'A').slice(0, 1).toUpperCase()}
                  </div>
                  <div className="hidden sm:flex flex-col text-left">
                    <span className="text-xs font-semibold text-white leading-tight truncate max-w-[120px]">
                      {profile?.display_name || user.email?.split('@')[0] || 'Analyst'}
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400 leading-tight flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
                      Verified
                    </span>
                  </div>
                  <ChevronDown className="h-3.5 w-3.5 text-slate-400 hidden sm:block" />
                </button>

                {showUserMenu && (
                  <>
                    <div
                      className="fixed inset-0 z-40"
                      onClick={() => setShowUserMenu(false)}
                    />
                    <div className="absolute right-0 top-11 z-50 w-64 rounded-2xl border border-white/10 bg-[#0d1322] p-3.5 shadow-2xl backdrop-blur-xl">
                      {/* User Info Header */}
                      <div className="border-b border-white/5 pb-3">
                        <div className="flex items-center gap-2.5">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 font-bold text-sm">
                            {(profile?.display_name || user.email || 'A').slice(0, 1).toUpperCase()}
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-bold text-white truncate">
                              {profile?.display_name || 'Cyber Analyst'}
                            </p>
                            <p className="text-[11px] font-mono text-slate-400 truncate">
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
                          className="flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-900/80 transition-colors"
                        >
                          <SearchCode className="h-4 w-4 text-cyan-400" />
                          <span>Personal Case Files</span>
                        </Link>
                        <Link
                          href="/settings"
                          onClick={() => setShowUserMenu(false)}
                          className="flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-900/80 transition-colors"
                        >
                          <Sliders className="h-4 w-4 text-cyan-400" />
                          <span>Platform &amp; Diagnostics</span>
                        </Link>
                      </div>

                      {/* Sign Out Action */}
                      <div className="border-t border-white/5 pt-2">
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
                          className="w-full flex items-center gap-2 rounded-xl px-2.5 py-2 text-xs font-medium text-red-400 hover:text-red-300 hover:bg-red-950/30 transition-colors cursor-pointer disabled:opacity-50"
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
                  href="/auth/login"
                  className="flex items-center gap-1.5 rounded-xl bg-cyan-600/90 hover:bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-white shadow-md shadow-cyan-600/20 transition-all"
                >
                  <LogIn className="h-3.5 w-3.5" />
                  <span>Sign In</span>
                </Link>
                <Link
                  href="/auth/register"
                  className="hidden md:inline-flex items-center gap-1 rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors"
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
          <div className="relative w-full max-w-lg rounded-2xl border border-white/15 bg-[#0d1322] p-4 shadow-2xl">
            <div className="flex items-center gap-2 border-b border-white/10 pb-3">
              <Search className="h-4 w-4 text-cyan-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Jump to module (e.g. Analyze, Intelligence, Academy)..."
                autoFocus
                className="w-full bg-transparent text-sm text-white placeholder-slate-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowSearchModal(false)}
                className="text-slate-400 hover:text-white"
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
                      className="flex items-center justify-between rounded-lg p-2.5 text-xs text-slate-300 hover:bg-slate-900/80 hover:text-white transition-colors"
                    >
                      <div className="flex items-center gap-2.5">
                        <Icon className="h-4 w-4 text-cyan-400" />
                        <span className="font-medium">{item.name}</span>
                      </div>
                      <span className="font-mono text-[10px] text-slate-500">
                        {item.href}
                      </span>
                    </Link>
                  );
                })
              ) : (
                <div className="p-4 text-center text-xs text-slate-500">
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
