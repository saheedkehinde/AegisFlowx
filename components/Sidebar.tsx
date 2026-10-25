'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldAlert,
  SearchCode,
  Binary,
  Users,
  Bell,
  Cpu,
  GraduationCap,
  Sliders,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
  mobileOpen: boolean;
  setMobileOpen: (open: boolean) => void;
}

export const NAV_ITEMS = [
  {
    name: 'Overview',
    href: '/',
    icon: LayoutDashboard,
    badge: null,
  },
  {
    name: 'Analyze',
    href: '/analyze',
    icon: ShieldAlert,
    badge: 'Live AI',
    badgeVariant: 'primary',
  },
  {
    name: 'Investigations',
    href: '/investigations',
    icon: SearchCode,
    badge: 'Vault',
    badgeVariant: 'cyan',
  },
  {
    name: 'Threat Intelligence',
    href: '/threat-intel',
    icon: Binary,
    badge: null,
  },
  {
    name: 'Community Reports',
    href: '/community',
    icon: Users,
    badge: 'Preview',
    badgeVariant: 'preview',
  },
  {
    name: 'Notifications',
    href: '/notifications',
    icon: Bell,
    badge: 'Preview',
    badgeVariant: 'preview',
  },
  {
    name: 'Automation Center',
    href: '/automation',
    icon: Cpu,
    badge: 'Preview',
    badgeVariant: 'violet',
  },
  {
    name: 'Security Academy',
    href: '/academy',
    icon: GraduationCap,
    badge: '4 Guides',
    badgeVariant: 'success',
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: Sliders,
    badge: null,
  },
];

export default function Sidebar({
  collapsed,
  setCollapsed,
  mobileOpen,
  setMobileOpen,
}: SidebarProps) {
  const pathname = usePathname();
  const { user, profile } = useAuth();

  const handleNavClick = () => {
    setMobileOpen(false);
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden transition-opacity"
          aria-hidden="true"
        />
      )}

      {/* Sidebar Element */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col border-r border-[var(--sidebar-border)] bg-[var(--sidebar-bg)] transition-all duration-300 ease-in-out ${
          collapsed ? 'w-20' : 'w-64'
        } ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Sidebar Brand Header */}
        <div className="flex h-16 items-center justify-between px-4 border-b border-[var(--border-subtle)]">
          <Link
            href="/"
            onClick={handleNavClick}
            className="flex items-center gap-3 overflow-hidden group focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none rounded-lg p-1"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-[var(--primary-orange)] via-[var(--primary-deep-orange)] to-amber-700 shadow-md shadow-[var(--primary-orange-glow)] ring-1 ring-white/20">
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            {!collapsed && (
              <div className="flex flex-col min-w-0">
                <span className="text-base font-bold tracking-tight text-[var(--foreground)] group-hover:text-[var(--primary-orange)] transition-colors">
                  Aegis<span className="text-[var(--primary-orange)]">Flow</span>
                </span>
                <span className="text-[10px] font-mono text-[var(--muted-foreground)] uppercase tracking-wider truncate">
                  Cyber Intelligence
                </span>
              </div>
            )}
          </Link>

          {/* Desktop Collapse Toggle */}
          <button
            type="button"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="hidden lg:flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--border)] bg-[var(--surface)] text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:border-[var(--primary-orange)]/40 transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive =
              item.href === '/'
                ? pathname === '/'
                : pathname === item.href || pathname?.startsWith(item.href + '/');

            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={handleNavClick}
                title={collapsed ? item.name : undefined}
                className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-semibold transition-all duration-150 min-h-[40px] focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none ${
                  isActive
                    ? 'border border-[var(--primary-orange)]/35 bg-[var(--surface-soft-orange)] text-[var(--primary-orange)] shadow-sm'
                    : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-interactive)] border border-transparent'
                }`}
              >
                <Icon
                  className={`h-4 w-4 shrink-0 transition-colors ${
                    isActive
                      ? 'text-[var(--primary-orange)]'
                      : 'text-[var(--foreground-secondary)] group-hover:text-[var(--primary-orange)]'
                  }`}
                />
                {!collapsed && (
                  <span className="truncate flex-1 whitespace-nowrap">{item.name}</span>
                )}
                {!collapsed && item.badge && (
                  <span
                    className={`ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded border whitespace-nowrap ${
                      item.badgeVariant === 'primary'
                        ? 'border-[var(--primary-orange)]/30 bg-[var(--surface-soft-orange)] text-[var(--primary-orange)]'
                        : item.badgeVariant === 'cyan'
                        ? 'border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)]'
                        : item.badgeVariant === 'violet'
                        ? 'border-[var(--accent-violet)]/30 bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)]'
                        : item.badgeVariant === 'success'
                        ? 'border-[var(--status-success-border)] bg-[var(--status-success-bg)] text-[var(--status-success)]'
                        : 'border-[var(--border)] bg-[var(--surface-interactive)] text-[var(--muted-foreground)]'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Footer: System Status */}
        <div className="border-t border-[var(--border-subtle)] p-3">
          <div
            className={`rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 shadow-sm ${
              collapsed ? 'text-center' : ''
            }`}
          >
            <div className="flex items-center gap-2">
              <div className="flex h-2 w-2 rounded-full bg-[var(--status-success)] shrink-0" />
              {!collapsed && (
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] font-semibold text-[var(--foreground)] truncate">
                    Qwen3-VL-8B Engine
                  </div>
                  <div className="text-[10px] font-mono text-[var(--status-success)]">
                    Inference Online
                  </div>
                </div>
              )}
            </div>

            {!collapsed && (
              <div className="mt-2.5 pt-2 border-t border-[var(--border-subtle)] text-[10px] text-[var(--muted-foreground)] leading-tight">
                {user ? (
                  <>
                    <span className="font-mono text-[var(--primary-orange)] font-semibold">Analyst:</span>{' '}
                    <span className="text-[var(--foreground)] truncate inline-block max-w-[130px] align-bottom">
                      {profile?.display_name || user.email?.split('@')[0]}
                    </span>
                    <br />
                    <span className="text-[var(--status-success)] font-mono">Cloud Sync Active</span>
                  </>
                ) : (
                  <>
                    <span className="font-mono text-[var(--foreground-secondary)]">Session:</span> Guest Analyst
                    <br />
                    <span className="text-[var(--muted-foreground)]">Zero-Retention Mode</span>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}
