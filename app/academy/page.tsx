'use client';

import React, { useState, useMemo, useSyncExternalStore } from 'react';
import Link from 'next/link';
import AppShell from '@/components/AppShell';
import KnowledgeCheck from '@/components/KnowledgeCheck';
import {
  GraduationCap,
  ShieldCheck,
  CheckCircle2,
  AlertOctagon,
  ArrowRight,
  BookOpen,
  HelpCircle,
  Sparkles,
  Info,
  ExternalLink,
  CreditCard,
  Briefcase,
  Package,
  KeyRound,
  RotateCcw,
  Check,
  X,
  FileCode2,
  Terminal,
} from 'lucide-react';
import {
  ACADEMY_LESSONS,
  saveModuleProgress,
  resetAllAcademyProgress,
  ACADEMY_STORAGE_KEY,
  ModuleProgress,
  AcademyLesson,
} from '@/lib/academy-data';

// External store subscription for localStorage progress (React 19 compliant, hydration-safe)
function subscribeToAcademyProgress(callback: () => void) {
  if (typeof window === 'undefined') return () => {};
  window.addEventListener('aegisflow-academy-progress-updated', callback);
  window.addEventListener('storage', callback);
  return () => {
    window.removeEventListener('aegisflow-academy-progress-updated', callback);
    window.removeEventListener('storage', callback);
  };
}

function getAcademyProgressSnapshot(): string {
  if (typeof window === 'undefined') return '{}';
  try {
    return localStorage.getItem(ACADEMY_STORAGE_KEY) || '{}';
  } catch {
    return '{}';
  }
}

function getAcademyProgressServerSnapshot(): string {
  return '{}';
}

// Module icon mapping for distinct visual accents
function getModuleIcon(id: number) {
  switch (id) {
    case 1:
      return <CreditCard className="h-4 w-4 text-[var(--accent-amber)]" />;
    case 2:
      return <Briefcase className="h-4 w-4 text-[var(--accent-violet)]" />;
    case 3:
      return <Package className="h-4 w-4 text-[var(--accent-cyan)]" />;
    case 4:
      return <KeyRound className="h-4 w-4 text-[var(--primary-orange)]" />;
    default:
      return <GraduationCap className="h-4 w-4 text-[var(--primary-orange)]" />;
  }
}

export default function AcademyPage() {
  const [activeLessonIdx, setActiveLessonIdx] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<'playbook' | 'quiz'>('playbook');
  const [showResetConfirm, setShowResetConfirm] = useState(false);

  // React 19 safe external store subscription to localStorage
  const progressJson = useSyncExternalStore(
    subscribeToAcademyProgress,
    getAcademyProgressSnapshot,
    getAcademyProgressServerSnapshot
  );

  const progressMap = useMemo<Record<number, ModuleProgress>>(() => {
    try {
      return JSON.parse(progressJson);
    } catch {
      return {};
    }
  }, [progressJson]);

  const lessons = ACADEMY_LESSONS;
  const current: AcademyLesson = lessons[activeLessonIdx] || lessons[0];
  const currentProgress = progressMap[current.id];

  const handleQuizComplete = (score: number, total: number) => {
    saveModuleProgress(current.id, score, total);
  };

  const handleNextModule = () => {
    if (activeLessonIdx + 1 < lessons.length) {
      setActiveLessonIdx((prev) => prev + 1);
      setActiveTab('playbook');
    }
  };

  const handleConfirmReset = () => {
    resetAllAcademyProgress();
    setShowResetConfirm(false);
  };

  // Derive genuine data statistics purely from stored progress
  const completedModules = Object.values(progressMap).filter((p) => p?.completed);
  const completedCount = completedModules.length;
  const totalCompletedQuestions = completedModules.reduce((acc, p) => acc + (p.totalQuestions || 0), 0);
  const totalEarnedScore = completedModules.reduce((acc, p) => acc + (p.score || 0), 0);
  const overallAccuracy =
    totalCompletedQuestions > 0
      ? Math.round((totalEarnedScore / totalCompletedQuestions) * 100)
      : null;

  return (
    <AppShell>
      <div className="space-y-8 max-w-7xl mx-auto pb-12">
        {/* ========================================================= */}
        {/* 1. ACADEMY LANDING & COMMAND HEADER                       */}
        {/* ========================================================= */}
        <div className="border-b border-[var(--border-subtle)] pb-6">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-2.5">
            {/* Visual Kicker */}
            <div className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--accent-cyan)]">
              <Sparkles className="h-3.5 w-3.5 text-[var(--accent-cyan)]" />
              <span>Interactive Threat Literacy · Scenario-Based Knowledge Checks</span>
            </div>

            {/* Reset Scores Control with Safety Confirmation */}
            {completedCount > 0 && (
              <div className="flex items-center gap-2">
                {!showResetConfirm ? (
                  <button
                    type="button"
                    onClick={() => setShowResetConfirm(true)}
                    className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--muted-foreground)] hover:text-[var(--status-critical)] transition-colors cursor-pointer"
                    title="Clear local browser quiz scores"
                  >
                    <RotateCcw className="h-3 w-3" />
                    <span>Reset Local Scores</span>
                  </button>
                ) : (
                  <div className="inline-flex items-center gap-2 rounded-lg border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] px-2.5 py-1 text-xs font-mono">
                    <span className="text-[var(--status-critical)] font-medium">Reset scores?</span>
                    <button
                      type="button"
                      onClick={handleConfirmReset}
                      className="inline-flex items-center gap-1 text-[var(--status-critical)] hover:underline font-bold cursor-pointer"
                    >
                      <Check className="h-3 w-3" />
                      <span>Confirm</span>
                    </button>
                    <span className="text-[var(--muted-foreground)]">·</span>
                    <button
                      type="button"
                      onClick={() => setShowResetConfirm(false)}
                      className="inline-flex items-center gap-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)] cursor-pointer"
                    >
                      <X className="h-3 w-3" />
                      <span>Cancel</span>
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
            <div>
              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--foreground)] flex items-center gap-3">
                <div className="h-9 w-9 rounded-xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 flex items-center justify-center shrink-0">
                  <GraduationCap className="h-5 w-5 text-[var(--primary-orange)]" />
                </div>
                <span>AegisFlow Security Academy</span>
              </h1>
              <p className="mt-2 text-xs sm:text-sm text-[var(--foreground-secondary)] max-w-3xl leading-relaxed">
                Learn the signal. Recognize the threat. Build defensive instincts. Deconstruct social engineering vectors, 
                urgency-based extortion, and deceptive credential traps before harm occurs.
              </p>
            </div>

            {/* Quick Action Button */}
            <div className="shrink-0 flex items-center gap-2.5">
              <button
                type="button"
                onClick={() => {
                  // Jump to current module's quiz or playbook
                  setActiveTab('quiz');
                }}
                className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] px-4 py-2 text-xs font-semibold transition-all min-h-[40px] cursor-pointer shadow-md shadow-[var(--primary-orange-glow)]"
              >
                <span>{currentProgress?.completed ? 'Re-take Knowledge Check' : 'Begin Knowledge Check'}</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Genuine Progress Overview Cards */}
          <div className="mt-6 grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
            {/* Metric 1: Verified Modules */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card-bg)] p-3.5 sm:p-4 shadow-[var(--shadow-sm)]">
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--muted-foreground)] block mb-1">
                Verified Modules
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl sm:text-2xl font-bold font-mono text-[var(--foreground)]">
                  {completedCount}
                </span>
                <span className="text-xs font-mono text-[var(--muted-foreground)]">
                  / {lessons.length} Completed
                </span>
              </div>
              <div className="mt-2.5 h-1.5 w-full bg-[var(--surface-interactive)] rounded-full overflow-hidden border border-[var(--border-subtle)]">
                <div
                  className="h-full bg-[var(--primary-orange)] transition-all duration-300"
                  style={{ width: `${(completedCount / lessons.length) * 100}%` }}
                />
              </div>
            </div>

            {/* Metric 2: Scenarios Evaluated */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card-bg)] p-3.5 sm:p-4 shadow-[var(--shadow-sm)]">
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--muted-foreground)] block mb-1">
                Scenarios Evaluated
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl sm:text-2xl font-bold font-mono text-[var(--accent-cyan)]">
                  {totalCompletedQuestions}
                </span>
                <span className="text-xs font-mono text-[var(--muted-foreground)]">
                  / 12 Ready
                </span>
              </div>
              <p className="mt-2 text-[10px] font-mono text-[var(--muted-foreground)] truncate">
                {totalCompletedQuestions === 12 ? 'All scenarios completed' : 'Scenario library active'}
              </p>
            </div>

            {/* Metric 3: Average Accuracy */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card-bg)] p-3.5 sm:p-4 shadow-[var(--shadow-sm)]">
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--muted-foreground)] block mb-1">
                Average Accuracy
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl sm:text-2xl font-bold font-mono text-[var(--foreground)]">
                  {overallAccuracy !== null ? `${overallAccuracy}%` : '—'}
                </span>
                <span className="text-xs font-mono text-[var(--muted-foreground)]">
                  {overallAccuracy !== null ? `${totalEarnedScore}/${totalCompletedQuestions}` : 'No attempts'}
                </span>
              </div>
              <p className="mt-2 text-[10px] font-mono text-[var(--muted-foreground)] truncate">
                {overallAccuracy !== null ? 'Evaluated against safe actions' : 'Complete a quiz to evaluate'}
              </p>
            </div>

            {/* Metric 4: Storage Architecture */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card-bg)] p-3.5 sm:p-4 shadow-[var(--shadow-sm)]">
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--muted-foreground)] block mb-1">
                Storage Architecture
              </span>
              <div className="flex items-center gap-1.5">
                <span className="inline-block h-2 w-2 rounded-full bg-[var(--accent-cyan)] animate-pulse" />
                <span className="text-sm font-bold font-mono text-[var(--foreground)]">
                  Local Device
                </span>
              </div>
              <p className="mt-2 text-[10px] text-[var(--muted-foreground)] leading-tight">
                Stored in browser localStorage (<code className="font-mono text-[9px]">v1</code>). Cloud syncing planned.
              </p>
            </div>
          </div>
        </div>

        {/* ========================================================= */}
        {/* 2. LEARNING MODULE SELECTOR CARDS                         */}
        {/* ========================================================= */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider text-[var(--muted-foreground)] font-semibold">
              Select Educational Playbook & Knowledge Check
            </h2>
            <span className="text-xs font-mono text-[var(--muted-foreground)]">
              4 Specialized Modules
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {lessons.map((lesson, idx) => {
              const isSelected = activeLessonIdx === idx;
              const moduleProg = progressMap[lesson.id];

              return (
                <button
                  key={lesson.id}
                  type="button"
                  onClick={() => {
                    setActiveLessonIdx(idx);
                  }}
                  className={`text-left rounded-xl border p-4 transition-all duration-200 cursor-pointer min-h-[140px] focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none flex flex-col justify-between ${
                    isSelected
                      ? 'border-[var(--primary-orange)] bg-[var(--card-bg)] ring-1 ring-[var(--primary-orange)] shadow-md shadow-[var(--primary-orange-glow)]'
                      : 'border-[var(--border)] bg-[var(--card-bg)] hover:border-[var(--card-hover-border)] hover:bg-[var(--surface-interactive)] shadow-[var(--shadow-sm)]'
                  }`}
                >
                  <div className="space-y-2">
                    {/* Header line with icon, module number, and read time */}
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-1.5">
                        <span className="p-1 rounded-md bg-[var(--surface-interactive)] border border-[var(--border-subtle)]">
                          {getModuleIcon(lesson.id)}
                        </span>
                        <span
                          className={`font-bold ${
                            isSelected ? 'text-[var(--primary-orange)]' : 'text-[var(--foreground)]'
                          }`}
                        >
                          Module 0{lesson.id}
                        </span>
                      </div>
                      <span className="text-[var(--muted-foreground)]">{lesson.readTime}</span>
                    </div>

                    {/* Title */}
                    <h3 className="text-xs sm:text-sm font-bold text-[var(--foreground)] line-clamp-2 leading-snug">
                      {lesson.title}
                    </h3>

                    {/* Metadata unboxed text */}
                    <div className="text-[10px] font-mono text-[var(--muted-foreground)] flex items-center gap-1.5">
                      <span>{lesson.category}</span>
                      <span>·</span>
                      <span>{lesson.level}</span>
                    </div>
                  </div>

                  {/* Progress / Status Footer */}
                  <div className="mt-3 pt-2.5 border-t border-[var(--border-subtle)] flex items-center justify-between text-[10px] font-mono">
                    {moduleProg?.completed ? (
                      <span className="inline-flex items-center gap-1 text-[var(--status-success)] font-semibold">
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                        <span>
                          Score: {moduleProg.score}/{moduleProg.totalQuestions} ({moduleProg.percentage}%)
                        </span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[var(--muted-foreground)]">
                        <HelpCircle className="h-3 w-3 shrink-0" />
                        <span>{lesson.questions.length} Scenarios Ready</span>
                      </span>
                    )}

                    {isSelected && (
                      <span className="text-[var(--primary-orange)] font-bold text-[9px] uppercase tracking-wider">
                        Active
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* ========================================================= */}
        {/* 3. SELECTED MODULE WORKSPACE                              */}
        {/* ========================================================= */}
        <div className="space-y-6">
          {/* Module Sub-Header & Segmented Mode Control */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[var(--border-subtle)] pb-4">
            <div>
              <div className="flex items-center gap-2 text-xs font-mono text-[var(--primary-orange)] mb-1">
                <span>Module 0{current.id}</span>
                <span className="text-[var(--muted-foreground)]">·</span>
                <span>{current.category}</span>
                <span className="text-[var(--muted-foreground)]">·</span>
                <span>{current.level}</span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold text-[var(--foreground)] tracking-tight">
                {current.title}
              </h2>
            </div>

            {/* Segmented Mode Control (Playbook vs Knowledge Check) */}
            <div className="inline-flex rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] p-1 shrink-0">
              <button
                type="button"
                onClick={() => setActiveTab('playbook')}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all cursor-pointer min-h-[38px] ${
                  activeTab === 'playbook'
                    ? 'bg-[var(--surface)] text-[var(--foreground)] shadow-sm border border-[var(--border)]'
                    : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                <BookOpen className="h-3.5 w-3.5 text-[var(--primary-orange)]" />
                <span>Lesson Playbook</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('quiz')}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all cursor-pointer min-h-[38px] ${
                  activeTab === 'quiz'
                    ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)] shadow-sm'
                    : 'text-[var(--foreground-secondary)] hover:text-[var(--foreground)]'
                }`}
              >
                <HelpCircle className="h-3.5 w-3.5" />
                <span>Knowledge Check</span>
                {currentProgress?.completed && (
                  <span className="text-[10px] font-mono bg-black/20 text-white px-1.5 py-0.5 rounded">
                    {currentProgress.score}/{currentProgress.totalQuestions}
                  </span>
                )}
              </button>
            </div>
          </div>

          {/* TAB 1: PLAYBOOK VIEW */}
          {activeTab === 'playbook' && (
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 space-y-7 shadow-[var(--shadow-md)]">
              {/* Threat Brief & Executive Summary */}
              <div className="space-y-2">
                <h3 className="text-xs font-mono uppercase tracking-wider text-[var(--primary-orange)] font-semibold flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  <span>Threat Brief & Executive Summary</span>
                </h3>
                <p className="text-sm sm:text-base text-[var(--foreground)] leading-relaxed break-words font-medium">
                  {current.summary}
                </p>
              </div>

              {/* Intercepted Deceptive Message Artifact Box */}
              <div className="rounded-xl border border-[var(--border-strong)] bg-[var(--surface-interactive)]/70 p-4 sm:p-5 space-y-2.5">
                <div className="flex items-center justify-between text-[11px] font-mono text-[var(--muted-foreground)]">
                  <span className="flex items-center gap-1.5 text-[var(--accent-cyan)] font-semibold">
                    <FileCode2 className="h-3.5 w-3.5" />
                    <span>Intercepted Deception Artifact (Defanged Sample)</span>
                  </span>
                  <span>Raw Transport Stream</span>
                </div>
                <div className="rounded-lg bg-[var(--surface)] p-3.5 border border-[var(--border)] font-mono text-xs text-[var(--foreground)] break-all leading-relaxed select-all">
                  {current.exampleSnippet}
                </div>
              </div>

              {/* Red Flags & Defenses Two-Column Matrix */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* Attack Red Flags */}
                <div className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-5 space-y-3">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--status-critical)] flex items-center gap-2">
                    <AlertOctagon className="h-4 w-4 shrink-0" />
                    <span>Primary Attack Red Flags</span>
                  </h4>
                  <ul className="space-y-2.5 text-xs text-[var(--foreground)]">
                    {current.redFlags.map((flag, i) => (
                      <li key={i} className="flex items-start gap-2 leading-relaxed">
                        <span className="text-[var(--status-critical)] font-bold shrink-0">&times;</span>
                        <span className="break-words">{flag}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Recommended Defense Protocol */}
                <div className="rounded-xl border border-[var(--status-success-border)] bg-[var(--status-success-bg)] p-5 space-y-3">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--status-success)] flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    <span>Recommended Defense Protocol</span>
                  </h4>
                  <ul className="space-y-2.5 text-xs text-[var(--foreground)]">
                    {current.defenses.map((def, i) => (
                      <li key={i} className="flex items-start gap-2 leading-relaxed">
                        <span className="text-[var(--status-success)] font-bold shrink-0">&check;</span>
                        <span className="break-words">{def}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Key Principles for Threat Discernment */}
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)]/40 p-5 space-y-3">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--foreground)] flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-[var(--accent-cyan)] shrink-0" />
                  <span>Key Principles for Threat Discernment</span>
                </h4>
                <ul className="space-y-2 text-xs text-[var(--foreground-secondary)]">
                  {current.keyTakeaways.map((takeaway, idx) => (
                    <li key={idx} className="flex items-start gap-2 leading-relaxed">
                      <span className="text-[var(--accent-cyan)] font-bold shrink-0">•</span>
                      <span className="break-words">{takeaway}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Action Banner: Take Knowledge Check or Test in Analyzer */}
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)]/50 p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <span className="text-xs sm:text-sm font-bold text-[var(--foreground)] block">
                    Ready to test your defensive instincts on this module?
                  </span>
                  <p className="text-xs text-[var(--muted-foreground)] mt-0.5">
                    Evaluate 3 realistic scam-identification exercises with instant threat feedback.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setActiveTab('quiz')}
                    className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-4 py-2.5 text-xs font-semibold text-[var(--primary-foreground)] transition-all min-h-[44px] cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none shadow-md shadow-[var(--primary-orange-glow)]"
                  >
                    <span>Start Knowledge Check</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>

                  <Link
                    href="/analyze"
                    className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-2.5 text-xs font-semibold text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors min-h-[44px]"
                  >
                    <span>Test Message in Analyzer</span>
                    <ExternalLink className="h-3.5 w-3.5 text-[var(--muted-foreground)]" />
                  </Link>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: KNOWLEDGE CHECK (QUIZ) VIEW */}
          {activeTab === 'quiz' && (
            <KnowledgeCheck
              key={current.id}
              module={current}
              onComplete={handleQuizComplete}
              onReturnToPlaybook={() => setActiveTab('playbook')}
              onNextModule={handleNextModule}
              hasNextModule={activeLessonIdx + 1 < lessons.length}
            />
          )}
        </div>
      </div>
    </AppShell>
  );
}
