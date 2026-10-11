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
  Radio,
  Lock,
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
    badgeColor: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  },
  {
    name: 'Investigations',
    href: '/investigations',
    icon: SearchCode,
    badge: 'Phase 2',
    badgeColor: 'bg-slate-800 text-slate-400 border-white/5',
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
    badge: null,
  },
  {
    name: 'Notifications',
    href: '/notifications',
    icon: Bell,
    badge: null,
  },
  {
    name: 'Automation Center',
    href: '/automation',
    icon: Cpu,
    badge: 'Preview',
    badgeColor: 'bg-indigo-950/60 text-indigo-300 border-indigo-500/20',
  },
  {
    name: 'Security Academy',
    href: '/academy',
    icon: GraduationCap,
    badge: '4 Guides',
    badgeColor: 'bg-emerald-950/60 text-emerald-300 border-emerald-500/20',
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
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col border-r border-white/10 bg-[#070b14] transition-all duration-300 ease-in-out ${
          collapsed ? 'w-20' : 'w-64'
        } ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Sidebar Brand Header */}
        <div className="flex h-16 items-center justify-between px-4 border-b border-white/5">
          <Link
            href="/"
            onClick={handleNavClick}
            className="flex items-center gap-3 overflow-hidden group focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none rounded-lg p-1"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 shadow-md shadow-cyan-500/20 ring-1 ring-white/20">
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            {!collapsed && (
              <div className="flex flex-col min-w-0">
                <span className="text-base font-bold tracking-tight text-white group-hover:text-cyan-300 transition-colors">
                  Aegis<span className="text-cyan-400">Flow</span>
                </span>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider truncate">
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
            className="hidden lg:flex h-7 w-7 items-center justify-center rounded-lg border border-white/10 bg-slate-900/60 text-slate-400 hover:text-white hover:border-cyan-500/30 transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none"
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
                className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-semibold transition-all duration-150 min-h-[40px] focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:outline-none ${
                  isActive
                    ? 'border border-cyan-500/30 bg-cyan-950/30 text-cyan-300 shadow-sm shadow-cyan-950/50'
                    : 'text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <Icon
                  className={`h-4 w-4 shrink-0 transition-colors ${
                    isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-400'
                  }`}
                />
                {!collapsed && (
                  <span className="truncate flex-1">{item.name}</span>
                )}
                {!collapsed && item.badge && (
                  <span
                    className={`ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                      item.badgeColor || 'border-white/10 bg-white/5 text-slate-400'
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
        <div className="border-t border-white/5 p-3">
          <div
            className={`rounded-xl border border-white/5 bg-slate-900/40 p-3 ${
              collapsed ? 'text-center' : ''
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
              </span>
              {!collapsed && (
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] font-semibold text-slate-200 truncate">
                    Qwen3-VL-8B Engine
                  </div>
                  <div className="text-[10px] font-mono text-emerald-400">
                    Featherless Online
                  </div>
                </div>
              )}
            </div>

            {!collapsed && (
              <div className="mt-2.5 pt-2 border-t border-white/5 text-[10px] text-slate-500 leading-tight">
                {user ? (
                  <>
                    <span className="font-mono text-cyan-400 font-semibold">Analyst:</span>{' '}
                    <span className="text-slate-200 truncate inline-block max-w-[130px] align-bottom">
                      {profile?.display_name || user.email?.split('@')[0]}
                    </span>
                    <br />
                    <span className="text-emerald-400 font-mono">Cloud Sync Active</span>
                  </>
                ) : (
                  <>
                    <span className="font-mono text-slate-400">Session:</span> Guest Analyst
                    <br />
                    <span className="text-slate-500">Zero-Retention Mode</span>
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
