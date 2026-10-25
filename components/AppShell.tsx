'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import Sidebar from './Sidebar';
import TopBar from './TopBar';

interface AppShellProps {
  children: React.ReactNode;
}

export default function AppShell({ children }: AppShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] selection:bg-[var(--primary-orange)] selection:text-white flex flex-col transition-colors duration-200">
      {/* Sidebar Navigation */}
      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />

      {/* Main Content Area */}
      <div
        className={`flex-1 flex flex-col transition-all duration-300 ease-in-out ${
          collapsed ? 'lg:pl-20' : 'lg:pl-64'
        }`}
      >
        {/* Top Header Bar */}
        <TopBar onOpenMobileMenu={() => setMobileOpen(true)} />

        {/* Page Content Container */}
        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8 max-w-7xl w-full mx-auto">
          {children}
        </main>

        {/* Platform Standard Footer */}
        <footer className="mt-auto border-t border-[var(--border-subtle)] bg-[var(--background-secondary)] px-4 py-6 sm:px-6 lg:px-8 transition-colors duration-200">
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[var(--muted-foreground)]">
            <div className="flex items-center gap-2">
              <span className="font-bold text-[var(--foreground)]">AegisFlow</span>
              <span>&middot;</span>
              <span>AI-Powered Cybersecurity Intelligence Platform</span>
            </div>

            <div className="flex flex-wrap items-center gap-4 text-[11px]">
              <Link href="/analyze" className="hover:text-[var(--primary-orange)] transition-colors">
                Threat Analyzer
              </Link>
              <Link href="/threat-intel" className="hover:text-[var(--primary-orange)] transition-colors">
                MITRE ATT&CK
              </Link>
              <Link href="/academy" className="hover:text-[var(--primary-orange)] transition-colors">
                Security Academy
              </Link>
              <Link href="/settings" className="hover:text-[var(--primary-orange)] transition-colors">
                Settings
              </Link>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
