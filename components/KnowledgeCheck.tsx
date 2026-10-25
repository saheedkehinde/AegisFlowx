'use client';

import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  RotateCcw,
  ShieldCheck,
  BookOpen,
  HelpCircle,
  ChevronRight,
  ShieldAlert,
  Flame,
  Award,
} from 'lucide-react';
import { AcademyLesson, KnowledgeCheckQuestion } from '@/lib/academy-data';

interface KnowledgeCheckProps {
  module: AcademyLesson;
  onComplete: (score: number, total: number) => void;
  onReturnToPlaybook: () => void;
  onNextModule?: () => void;
  hasNextModule?: boolean;
}

export default function KnowledgeCheck({
  module,
  onComplete,
  onReturnToPlaybook,
  onNextModule,
  hasNextModule,
}: KnowledgeCheckProps) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [selectedOptionId, setSelectedOptionId] = useState<string | null>(null);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [userAnswers, setUserAnswers] = useState<Record<number, string>>({});
  const [quizFinished, setQuizFinished] = useState(false);

  const questions = module.questions;
  const currentQuestion: KnowledgeCheckQuestion | undefined = questions[currentIndex];
  const totalQuestions = questions.length;

  // Calculate actual score purely from recorded user answers
  const correctCount = questions.reduce((acc, q, idx) => {
    return acc + (userAnswers[idx] === q.correctOptionId ? 1 : 0);
  }, 0);

  const handleSelectOption = (optionId: string) => {
    if (isSubmitted) return;
    setSelectedOptionId(optionId);
  };

  const handleSubmitAnswer = () => {
    if (!selectedOptionId || isSubmitted || !currentQuestion) return;
    setIsSubmitted(true);
    const updatedAnswers = {
      ...userAnswers,
      [currentIndex]: selectedOptionId,
    };
    setUserAnswers(updatedAnswers);
  };

  const handleNextQuestion = () => {
    if (currentIndex + 1 < totalQuestions) {
      setCurrentIndex((prev) => prev + 1);
      setSelectedOptionId(null);
      setIsSubmitted(false);
    } else {
      // Calculate final score across all answered questions
      const finalCorrect = questions.reduce((acc, q, idx) => {
        return acc + (userAnswers[idx] === q.correctOptionId ? 1 : 0);
      }, 0);
      setQuizFinished(true);
      onComplete(finalCorrect, totalQuestions);
    }
  };

  const handleRetry = () => {
    setCurrentIndex(0);
    setSelectedOptionId(null);
    setIsSubmitted(false);
    setUserAnswers({});
    setQuizFinished(false);
  };

  if (!currentQuestion) {
    return (
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-8 text-center shadow-[var(--shadow-sm)]">
        <p className="text-[var(--muted-foreground)]">No knowledge check questions available for this module.</p>
        <button
          type="button"
          onClick={onReturnToPlaybook}
          className="mt-4 inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] text-[var(--primary-foreground)] hover:bg-[var(--primary-deep-orange)] px-4 py-2 text-xs font-semibold transition-colors cursor-pointer"
        >
          <BookOpen className="h-4 w-4" />
          <span>Return to Playbook</span>
        </button>
      </div>
    );
  }

  // ==========================================
  // QUIZ COMPLETED VIEW
  // ==========================================
  if (quizFinished) {
    const percentage = Math.round((correctCount / totalQuestions) * 100);
    const isPerfect = percentage === 100;
    const isPassing = percentage >= 66;

    return (
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 space-y-7 shadow-[var(--shadow-md)]">
        {/* Header / Score Banner */}
        <div className="text-center space-y-3.5 pb-6 border-b border-[var(--border-subtle)]">
          <div
            className={`mx-auto inline-flex items-center justify-center h-16 w-16 rounded-2xl transition-transform ${
              isPerfect
                ? 'bg-[var(--status-success-bg)] text-[var(--status-success)] border border-[var(--status-success-border)]'
                : isPassing
                ? 'bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30'
                : 'bg-[var(--status-warning-bg)] text-[var(--status-warning)] border border-[var(--status-warning-border)]'
            }`}
          >
            {isPerfect ? (
              <Award className="h-8 w-8" />
            ) : isPassing ? (
              <ShieldCheck className="h-8 w-8" />
            ) : (
              <ShieldAlert className="h-8 w-8" />
            )}
          </div>

          <div className="flex items-center justify-center gap-2 text-xs font-mono text-[var(--muted-foreground)]">
            <span>Module {module.id} Knowledge Check Complete</span>
            <span>·</span>
            <span>{module.category}</span>
          </div>

          <h3 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--foreground)]">
            Evaluated Score: <span className="text-[var(--primary-orange)] font-mono">{correctCount}</span>
            <span className="text-[var(--foreground-secondary)] font-normal text-xl"> / {totalQuestions} </span>
            <span className="text-[var(--muted-foreground)] font-mono text-lg font-normal">({percentage}%)</span>
          </h3>

          <p className="text-xs sm:text-sm text-[var(--foreground-secondary)] max-w-xl mx-auto leading-relaxed">
            {isPerfect
              ? 'Flawless threat discernment! You successfully identified every deceptive manipulation vector and selected the safest defensive protocol.'
              : isPassing
              ? 'Strong defensive instincts! You intercepted the majority of deceptive social engineering tactics. Review the principles below to master the edge cases.'
              : 'Learning in progress. Attackers intentionally exploit urgency and emotional cognitive biases. Review the key takeaways below and retry to build defensive reflexes.'}
          </p>
        </div>

        {/* Breakdown of Key Takeaways to Remember */}
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)]/40 p-5 space-y-3">
          <div className="flex items-center gap-2">
            <Flame className="h-4 w-4 text-[var(--primary-orange)] shrink-0" />
            <h4 className="text-xs font-mono uppercase tracking-wider text-[var(--foreground)] font-semibold">
              Key Security Principles to Remember
            </h4>
          </div>
          <ul className="space-y-2.5 text-xs text-[var(--foreground-secondary)]">
            {module.keyTakeaways.map((takeaway, i) => (
              <li key={i} className="flex items-start gap-2.5 leading-relaxed">
                <span className="text-[var(--primary-orange)] font-bold shrink-0 mt-0.5">•</span>
                <span className="break-words">{takeaway}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Action Controls */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={handleRetry}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-2.5 text-xs font-semibold text-[var(--foreground)] transition-colors min-h-[44px] cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <RotateCcw className="h-4 w-4 text-[var(--muted-foreground)]" />
              <span>Retry Knowledge Check</span>
            </button>

            <button
              type="button"
              onClick={onReturnToPlaybook}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-2.5 text-xs font-semibold text-[var(--foreground-secondary)] hover:text-[var(--foreground)] transition-colors min-h-[44px] cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none"
            >
              <BookOpen className="h-4 w-4 text-[var(--muted-foreground)]" />
              <span>Back to Lesson Playbook</span>
            </button>
          </div>

          {hasNextModule && onNextModule && (
            <button
              type="button"
              onClick={onNextModule}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] px-5 py-2.5 text-xs font-semibold transition-all min-h-[44px] cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none shadow-md shadow-[var(--primary-orange-glow)]"
            >
              <span>Continue to Next Module</span>
              <ChevronRight className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>
    );
  }

  // ==========================================
  // ACTIVE QUESTION VIEW
  // ==========================================
  const isSelected = (id: string) => selectedOptionId === id;
  const isCorrect = isSubmitted && selectedOptionId === currentQuestion.correctOptionId;
  const progressPercent = Math.round(((currentIndex + 1) / totalQuestions) * 100);

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-6 sm:p-8 space-y-6 shadow-[var(--shadow-md)]">
      {/* Top Stepper & Progress Bar */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-[var(--primary-orange)] font-semibold flex items-center gap-1.5">
            <HelpCircle className="h-3.5 w-3.5" />
            <span>
              Question {currentIndex + 1} of {totalQuestions}
            </span>
          </span>
          <span className="text-[var(--muted-foreground)]">
            Score: <span className="font-semibold text-[var(--foreground)]">{correctCount}</span> / {currentIndex} correct
          </span>
        </div>
        
        {/* Progress Track */}
        <div className="h-1.5 w-full bg-[var(--surface-interactive)] rounded-full overflow-hidden border border-[var(--border-subtle)]">
          <div
            className="h-full bg-gradient-to-r from-[var(--primary-orange)] to-[var(--accent-amber)] transition-all duration-300"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      {/* Realistic Cybersecurity Scenario Card */}
      <div className="rounded-xl border border-[var(--border-strong)] bg-[var(--surface-interactive)]/60 p-5 sm:p-6 space-y-2.5 relative overflow-hidden">
        <div className="flex items-center justify-between text-[11px] font-mono text-[var(--accent-cyan)] uppercase tracking-wider font-semibold">
          <span>Deception Scenario Intercept</span>
          <span className="text-[var(--muted-foreground)]">{module.category}</span>
        </div>
        <p className="text-sm sm:text-base text-[var(--foreground)] leading-relaxed break-words font-medium">
          {currentQuestion.scenario}
        </p>
      </div>

      {/* Options List */}
      <div className="space-y-3">
        <label className="block text-xs font-mono text-[var(--muted-foreground)] uppercase tracking-wider font-semibold">
          Select the safest practical response:
        </label>
        
        <div
          role="radiogroup"
          aria-label="Multiple choice response options"
          className="grid grid-cols-1 gap-3"
        >
          {currentQuestion.options.map((option) => {
            const selected = isSelected(option.id);
            const isAnswerKey = option.id === currentQuestion.correctOptionId;

            let borderBgStyles =
              'border-[var(--border)] bg-[var(--surface-interactive)]/40 hover:bg-[var(--surface-interactive)] hover:border-[var(--card-hover-border)] text-[var(--foreground)]';

            if (isSubmitted) {
              if (isAnswerKey) {
                borderBgStyles =
                  'border-[var(--status-success-border)] bg-[var(--status-success-bg)] text-[var(--foreground)] ring-1 ring-[var(--status-success)]';
              } else if (selected && !isAnswerKey) {
                borderBgStyles =
                  'border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] text-[var(--foreground)] ring-1 ring-[var(--status-critical)]';
              } else {
                borderBgStyles = 'border-[var(--border-subtle)] bg-[var(--surface)] text-[var(--muted-foreground)] opacity-50';
              }
            } else if (selected) {
              borderBgStyles =
                'border-[var(--primary-orange)] bg-[var(--surface-soft-orange)] text-[var(--foreground)] ring-1 ring-[var(--primary-orange)] shadow-sm';
            }

            return (
              <button
                key={option.id}
                type="button"
                role="radio"
                aria-checked={selected}
                disabled={isSubmitted}
                onClick={() => handleSelectOption(option.id)}
                className={`w-full text-left rounded-xl border p-4 transition-all duration-150 min-h-[48px] flex items-start gap-3.5 cursor-pointer disabled:cursor-default focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none ${borderBgStyles}`}
              >
                {/* Option Letter Key Badge */}
                <span
                  className={`inline-flex items-center justify-center h-6 w-6 rounded-lg text-xs font-mono font-bold shrink-0 mt-0.5 transition-colors ${
                    isSubmitted && isAnswerKey
                      ? 'bg-[var(--status-success)] text-white'
                      : isSubmitted && selected && !isAnswerKey
                      ? 'bg-[var(--status-critical)] text-white'
                      : selected
                      ? 'bg-[var(--primary-orange)] text-[var(--primary-foreground)]'
                      : 'bg-[var(--surface-interactive)] border border-[var(--border)] text-[var(--foreground-secondary)]'
                  }`}
                >
                  {option.label}
                </span>

                <div className="flex-1 min-w-0">
                  <p className="text-xs sm:text-sm leading-relaxed break-words">{option.text}</p>
                </div>

                {isSubmitted && isAnswerKey && (
                  <CheckCircle2 className="h-5 w-5 text-[var(--status-success)] shrink-0 mt-0.5" />
                )}
                {isSubmitted && selected && !isAnswerKey && (
                  <XCircle className="h-5 w-5 text-[var(--status-critical)] shrink-0 mt-0.5" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Submit Button (Before Submission) */}
      {!isSubmitted && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
          <p className="text-xs text-[var(--muted-foreground)]">
            {selectedOptionId
              ? 'Decision selected. Click submit to evaluate threat discernment.'
              : 'Evaluate the scenario and choose the safest operational action.'}
          </p>

          <button
            type="button"
            disabled={!selectedOptionId}
            onClick={handleSubmitAnswer}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] disabled:opacity-40 disabled:hover:bg-[var(--primary-orange)] px-5 py-2.5 text-xs font-semibold transition-all min-h-[44px] cursor-pointer disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none shadow-md shadow-[var(--primary-orange-glow)]"
          >
            <span>Submit Decision</span>
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Post-Submission Feedback Banner & Detailed Guidance */}
      {isSubmitted && (
        <div
          aria-live="polite"
          className={`rounded-xl border p-5 sm:p-6 space-y-4 transition-all ${
            isCorrect
              ? 'border-[var(--status-success-border)] bg-[var(--status-success-bg)]'
              : 'border-[var(--status-critical-border)] bg-[var(--status-critical-bg)]'
          }`}
        >
          {/* Result Header */}
          <div className="flex items-center gap-2.5">
            {isCorrect ? (
              <CheckCircle2 className="h-5 w-5 text-[var(--status-success)] shrink-0" />
            ) : (
              <XCircle className="h-5 w-5 text-[var(--status-critical)] shrink-0" />
            )}
            <h4
              className={`text-sm sm:text-base font-bold ${
                isCorrect ? 'text-[var(--status-success)]' : 'text-[var(--status-critical)]'
              }`}
            >
              {isCorrect
                ? 'Correct Decision — Threat Successfully Defended'
                : 'Vulnerability Identified — Learning Point'}
            </h4>
          </div>

          {/* Explanation */}
          <div className="text-xs sm:text-sm text-[var(--foreground)] leading-relaxed space-y-2">
            <p className="break-words">{currentQuestion.explanation}</p>
          </div>

          {/* Warning Signs & Safest Action Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-[var(--border-subtle)]">
            <div className="rounded-lg bg-[var(--surface)] p-3.5 space-y-2 border border-[var(--border)]">
              <span className="text-[11px] font-mono font-bold text-[var(--status-warning)] uppercase tracking-wider flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5 text-[var(--status-warning)] shrink-0" />
                <span>Critical Warning Signs</span>
              </span>
              <ul className="space-y-1 text-xs text-[var(--foreground-secondary)]">
                {currentQuestion.warningSigns.map((sign, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-[var(--status-warning)] font-bold shrink-0">•</span>
                    <span className="break-words">{sign}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="rounded-lg bg-[var(--surface)] p-3.5 space-y-2 border border-[var(--border)]">
              <span className="text-[11px] font-mono font-bold text-[var(--status-success)] uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-[var(--status-success)] shrink-0" />
                <span>Safest Practical Action</span>
              </span>
              <p className="text-xs text-[var(--foreground-secondary)] leading-relaxed break-words">
                {currentQuestion.safestAction}
              </p>
            </div>
          </div>

          {/* Continue Button */}
          <div className="flex justify-end pt-2">
            <button
              type="button"
              onClick={handleNextQuestion}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] text-[var(--primary-foreground)] px-5 py-2.5 text-xs font-semibold transition-all min-h-[44px] cursor-pointer focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] focus-visible:outline-none shadow-md shadow-[var(--primary-orange-glow)]"
            >
              <span>
                {currentIndex + 1 < totalQuestions ? 'Continue to Next Question' : 'View Quiz Summary'}
              </span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
