'use client';

import React, { useState } from 'react';
import AppShell from '@/components/AppShell';
import PageHeader from '@/components/ui/PageHeader';
import { Bell, Sliders, Info, Check, CheckCheck } from 'lucide-react';

interface PreviewNotification {
  id: string;
  title: string;
  category: string;
  description: string;
  timestamp: string;
  type: 'engine' | 'policy' | 'milestone';
}

const INITIAL_NOTIFICATIONS: PreviewNotification[] = [
  {
    id: '1',
    title: 'Aegis AI Threat Engine Online',
    category: 'Inference Engine',
    description: 'Aegis AI intelligence pipeline is responding normally with sub-4s latency.',
    timestamp: 'Active Now',
    type: 'engine',
  },
  {
    id: '2',
    title: 'Zero-Retention Mode Active',
    category: 'Security Policy',
    description: 'Guest client submissions are evaluated in volatile memory and not written to persistent storage.',
    timestamp: 'Session Default',
    type: 'policy',
  },
  {
    id: '3',
    title: 'Midnight Intelligence Design System Active',
    category: 'Platform Build',
    description: 'Application shell, semantic theme tokens, and intelligence workspaces initialized.',
    timestamp: 'Current Build',
    type: 'milestone',
  },
];

export default function NotificationsPage() {
  const [prefHighRisk, setPrefHighRisk] = useState(true);
  const [prefIOC, setPrefIOC] = useState(true);
  const [prefEngine, setPrefEngine] = useState(true);
  const [saved, setSaved] = useState(false);
  const [readIds, setReadIds] = useState<Record<string, boolean>>({});
  const [filterMode, setFilterMode] = useState<'all' | 'unread'>('all');

  const unreadCount = INITIAL_NOTIFICATIONS.filter((n) => !readIds[n.id]).length;
  const visibleNotifications =
    filterMode === 'unread'
      ? INITIAL_NOTIFICATIONS.filter((n) => !readIds[n.id])
      : INITIAL_NOTIFICATIONS;

  const toggleRead = (id: string) => {
    setReadIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const markAllRead = () => {
    const next: Record<string, boolean> = {};
    for (const item of INITIAL_NOTIFICATIONS) {
      next[item.id] = true;
    }
    setReadIds(next);
  };

  const handleSavePrefs = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <AppShell>
      <div className="space-y-8">
        <PageHeader
          breadcrumbLabel="Notifications"
          title="Security Notifications"
          description="Platform event logs, system availability updates, and simulated alert dispatch rules."
          icon={Bell}
          badgeText="Preview Mode"
          badgeVariant="warning"
        />

        {/* Feature Preview & Demonstration Notice */}
        <div className="rounded-2xl border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] p-4 sm:p-5 text-[var(--foreground)]">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-[var(--status-warning)] shrink-0 mt-0.5" aria-hidden="true" />
            <div className="space-y-1 text-xs">
              <strong className="text-sm font-bold text-[var(--status-warning)] block">
                Feature Preview: Security Alert Broker
              </strong>
              <p className="text-[var(--foreground)] leading-relaxed">
                <strong>Roadmap Objective:</strong> Real-time push notifications, automated SIEM alert feeds, and critical smishing / BEC escalations dispatched to SOC teams.
              </p>
              <p className="text-[var(--foreground-secondary)] leading-relaxed">
                <strong className="text-[var(--foreground)]">Current Status:</strong> Interface Preview with simulated system events. Read states and preferences configured below are saved to local session state for demonstration and do not dispatch external webhooks or email alerts.
              </p>
            </div>
          </div>
        </div>

        {/* Current Notifications List */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--foreground-secondary)] tabular-nums">
                System Events ({visibleNotifications.length})
              </h2>
              <span className="rounded-md border border-[var(--border)] bg-[var(--surface-interactive)] px-2 py-0.5 text-[10px] font-mono text-[var(--muted-foreground)] tabular-nums">
                {unreadCount} unread
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div
                role="tablist"
                aria-label="Filter notifications"
                className="flex items-center gap-1 rounded-lg bg-[var(--surface-interactive)] p-1 border border-[var(--border-subtle)]"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={filterMode === 'all'}
                  onClick={() => setFilterMode('all')}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${
                    filterMode === 'all'
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                      : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                  }`}
                >
                  All
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={filterMode === 'unread'}
                  onClick={() => setFilterMode('unread')}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${
                    filterMode === 'unread'
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                      : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                  }`}
                >
                  Unread
                </button>
              </div>

              {unreadCount > 0 && (
                <button
                  type="button"
                  onClick={markAllRead}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-2.5 py-1 text-[11px] font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
                >
                  <CheckCheck className="h-3.5 w-3.5 text-[var(--accent-cyan)]" aria-hidden="true" />
                  <span>Mark all read</span>
                </button>
              )}
            </div>
          </div>

          {visibleNotifications.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-[var(--border)] bg-[var(--card-bg)] p-8 text-center text-xs text-[var(--foreground-secondary)]">
              All simulated session events have been marked as read. Switch to &ldquo;All&rdquo; to review earlier events.
            </div>
          ) : (
            <div className="space-y-3">
              {visibleNotifications.map((item) => {
                const isRead = Boolean(readIds[item.id]);
                return (
                  <div
                    key={item.id}
                    className={`rounded-2xl border p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 transition-colors ${
                      isRead
                        ? 'border-[var(--border-subtle)] bg-[var(--surface-interactive)]/60 opacity-85'
                        : 'border-[var(--border)] bg-[var(--card-bg)] shadow-[var(--shadow-sm)]'
                    }`}
                  >
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          aria-hidden="true"
                          className={`h-2 w-2 rounded-full ${
                            isRead ? 'bg-[var(--muted-foreground)]/40' : 'bg-[var(--accent-cyan)]'
                          }`}
                        />
                        <h3 className="text-sm font-bold text-[var(--foreground)]">
                          {item.title}
                        </h3>
                        <span className="text-[10px] font-mono text-[var(--foreground-secondary)] bg-[var(--surface-interactive)] px-2 py-0.5 rounded border border-[var(--border-subtle)]">
                          {item.category}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs text-[var(--foreground-secondary)] leading-relaxed">
                        {item.description}
                      </p>
                    </div>

                    <div className="flex items-center gap-3 self-start sm:self-auto shrink-0">
                      <span className="text-[11px] font-mono text-[var(--accent-cyan)]">
                        {item.timestamp}
                      </span>
                      <button
                        type="button"
                        onClick={() => toggleRead(item.id)}
                        className="rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-2.5 py-1 text-[11px] font-medium text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors cursor-pointer"
                      >
                        {isRead ? 'Mark unread' : 'Mark read'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* Notification Preferences */}
        <section className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 max-w-2xl shadow-[var(--shadow-sm)]">
          <h2 className="text-base font-bold text-[var(--foreground)] flex items-center gap-2 font-[family-name:var(--font-display)]">
            <Sliders className="h-4 w-4 text-[var(--primary-orange)]" aria-hidden="true" />
            <span>Alert Preferences</span>
          </h2>
          <p className="mt-1 text-xs text-[var(--foreground-secondary)]">
            Configure which events trigger immediate in-session notifications.
          </p>

          <form onSubmit={handleSavePrefs} className="mt-5 space-y-3">
            <label className="flex items-start gap-3 p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] hover:border-[var(--border)] transition-colors cursor-pointer">
              <input
                type="checkbox"
                checked={prefHighRisk}
                onChange={(e) => setPrefHighRisk(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[var(--border)] accent-[var(--primary-orange)]"
              />
              <div>
                <span className="text-xs font-bold text-[var(--foreground)] block">
                  High-Risk Threat Alerts
                </span>
                <span className="text-[11px] text-[var(--foreground-secondary)] block mt-0.5">
                  Display highlighted notification badges when an analysis detects critical smishing or BEC fraud.
                </span>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] hover:border-[var(--border)] transition-colors cursor-pointer">
              <input
                type="checkbox"
                checked={prefIOC}
                onChange={(e) => setPrefIOC(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[var(--border)] accent-[var(--primary-orange)]"
              />
              <div>
                <span className="text-xs font-bold text-[var(--foreground)] block">
                  Automated IOC Extraction Alerts
                </span>
                <span className="text-[11px] text-[var(--foreground-secondary)] block mt-0.5">
                  Notify when defanged URLs or suspicious phone shortcodes are extracted.
                </span>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-interactive)] hover:border-[var(--border)] transition-colors cursor-pointer">
              <input
                type="checkbox"
                checked={prefEngine}
                onChange={(e) => setPrefEngine(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[var(--border)] accent-[var(--primary-orange)]"
              />
              <div>
                <span className="text-xs font-bold text-[var(--foreground)] block">
                  Engine &amp; Latency Alerts
                </span>
                <span className="text-[11px] text-[var(--foreground-secondary)] block mt-0.5">
                  Alert if Aegis AI inference latency exceeds 20 seconds.
                </span>
              </div>
            </label>

            <div className="pt-2 flex items-center gap-3">
              <button
                type="submit"
                className="rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors cursor-pointer"
              >
                Save Preferences
              </button>
              {saved && (
                <span role="status" className="text-xs text-[var(--status-success)] font-semibold flex items-center gap-1">
                  <Check className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Preferences saved</span>
                </span>
              )}
            </div>
          </form>
        </section>
      </div>
    </AppShell>
  );
}
