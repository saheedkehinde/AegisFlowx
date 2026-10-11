'use client';

import React, { useState } from 'react';
import AppShell from '@/components/AppShell';
import {
  Bell,
  CheckCircle2,
  Sliders,
  ShieldAlert,
  Info,
  Clock,
  Check,
} from 'lucide-react';

export default function NotificationsPage() {
  const [prefHighRisk, setPrefHighRisk] = useState(true);
  const [prefIOC, setPrefIOC] = useState(true);
  const [prefEngine, setPrefEngine] = useState(true);
  const [saved, setSaved] = useState(false);

  const notifications = [
    {
      id: '1',
      title: 'Featherless Qwen3-VL-8B-Instruct Online',
      category: 'Inference Engine',
      description: 'Upstream AI endpoint https://api.featherless.ai/v1 is responding normally with sub-4s latency.',
      timestamp: 'Active Now',
      type: 'engine',
    },
    {
      id: '2',
      title: 'Zero-Retention Mode Active',
      category: 'Security Policy',
      description: 'Client submissions are evaluated in volatile RAM and not written to persistent storage.',
      timestamp: 'Session Default',
      type: 'policy',
    },
    {
      id: '3',
      title: 'Phase 1 Architecture Deployed',
      category: 'Platform Milestone',
      description: 'Application shell, sidebar navigation, and intelligence modules initialized successfully.',
      timestamp: 'Current Build',
      type: 'milestone',
    },
  ];

  const handleSavePrefs = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <AppShell>
      <div className="space-y-8">
        {/* Header */}
        <div className="border-b border-white/5 pb-5">
          <div className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-0.5 text-[10px] font-mono text-cyan-400 mb-2">
            <span>System Telemetry &middot; Real-time Alerts</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <Bell className="h-7 w-7 text-cyan-400" />
            <span>Security Notifications</span>
          </h2>
          <p className="mt-1 text-xs sm:text-sm text-slate-400 max-w-2xl">
            Real-time platform events, model availability status, and alert dispatch rules.
          </p>
        </div>

        {/* Current Notifications List */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            System Events ({notifications.length})
          </h3>

          <div className="space-y-3">
            {notifications.map((item) => (
              <div
                key={item.id}
                className="rounded-xl border border-white/10 bg-[#0d1322]/80 p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-cyan-400" />
                    <h4 className="text-sm font-bold text-white">
                      {item.title}
                    </h4>
                    <span className="text-[10px] font-mono text-slate-400 bg-white/5 px-2 py-0.5 rounded border border-white/5">
                      {item.category}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-slate-300 leading-relaxed">
                    {item.description}
                  </p>
                </div>

                <div className="text-[11px] font-mono text-cyan-400/80 self-start sm:self-auto shrink-0">
                  {item.timestamp}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Notification Preferences */}
        <div className="rounded-2xl border border-white/10 bg-[#0d1322]/80 p-6 sm:p-8 max-w-2xl">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Sliders className="h-4 w-4 text-cyan-400" />
            <span>Alert Preferences</span>
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            Configure which events trigger immediate in-session notifications.
          </p>

          <form onSubmit={handleSavePrefs} className="mt-5 space-y-4">
            <label className="flex items-start gap-3 p-3 rounded-xl border border-white/5 bg-slate-900/50 cursor-pointer">
              <input
                type="checkbox"
                checked={prefHighRisk}
                onChange={(e) => setPrefHighRisk(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-white/10 text-cyan-500 focus:ring-cyan-400"
              />
              <div>
                <span className="text-xs font-bold text-white block">
                  High-Risk Threat Alerts
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Display highlighted notification badges when an analysis detects critical smishing or BEC fraud.
                </span>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3 rounded-xl border border-white/5 bg-slate-900/50 cursor-pointer">
              <input
                type="checkbox"
                checked={prefIOC}
                onChange={(e) => setPrefIOC(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-white/10 text-cyan-500 focus:ring-cyan-400"
              />
              <div>
                <span className="text-xs font-bold text-white block">
                  Automated IOC Extraction Alerts
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Notify when defanged URLs or suspicious phone shortcodes are extracted.
                </span>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3 rounded-xl border border-white/5 bg-slate-900/50 cursor-pointer">
              <input
                type="checkbox"
                checked={prefEngine}
                onChange={(e) => setPrefEngine(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-white/10 text-cyan-500 focus:ring-cyan-400"
              />
              <div>
                <span className="text-xs font-bold text-white block">
                  Engine &amp; Latency Alerts
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Alert if Featherless API inference exceeds 20 seconds.
                </span>
              </div>
            </label>

            <div className="pt-2 flex items-center gap-3">
              <button
                type="submit"
                className="rounded-xl bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-xs font-semibold text-white transition-colors cursor-pointer"
              >
                Save Preferences
              </button>
              {saved && (
                <span className="text-xs text-emerald-400 flex items-center gap-1">
                  <Check className="h-3.5 w-3.5" />
                  <span>Preferences saved</span>
                </span>
              )}
            </div>
          </form>
        </div>
      </div>
    </AppShell>
  );
}
