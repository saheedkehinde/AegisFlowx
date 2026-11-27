'use client';

import React, { useState, useRef, DragEvent, ChangeEvent } from 'react';
import {
  UploadCloud,
  FileText,
  X,
  AlertCircle,
  Loader2,
  CheckCircle2,
  Lock,
  ShieldAlert,
  RefreshCw,
  Sparkles,
  ArrowRight,
  Shield,
} from 'lucide-react';
import {
  DocumentScanResult,
  formatDocumentScanErrorNotice,
} from '@/lib/document-scanner';
import Link from 'next/link';
import { useQuota } from '@/hooks/use-quota';
import { isCapabilityExhausted } from '@/lib/quota-types';

interface DocumentScannerProps {
  onScanComplete: (result: DocumentScanResult) => void;
  isScanning: boolean;
  setIsScanning: (scanning: boolean) => void;
}

interface ScanErrorState {
  categoryTitle: string;
  message: string;
  isRetryable: boolean;
}

const MAX_SIZE_MB = 10;
const MAX_BYTES = MAX_SIZE_MB * 1024 * 1024;
const ACCEPTED_TYPES = ['application/pdf', 'image/png', 'image/jpeg', 'image/webp'];

export default function DocumentScanner({
  onScanComplete,
  isScanning,
  setIsScanning,
}: DocumentScannerProps) {
  const { quota, updateQuotaSnapshot, refreshQuota } = useQuota();
  const isQuotaBlocked = isCapabilityExhausted(quota, 'document_scan');
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [contextNote, setContextNote] = useState('');
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<(ScanErrorState & { requiresRegistration?: boolean }) | null>(null);
  const [scanStep, setScanStep] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const isAbortedByUserRef = useRef(false);

  const handleCancelScan = () => {
    if (abortControllerRef.current) {
      isAbortedByUserRef.current = true;
      abortControllerRef.current.abort();
    }
  };

  const handleFileChange = (selectedFile: File) => {
    setError(null);

    if (selectedFile.size > MAX_BYTES) {
      setError(
        formatDocumentScanErrorNotice(
          'invalid_file',
          `File size (${(selectedFile.size / (1024 * 1024)).toFixed(1)}MB) exceeds the 10MB limit.`,
          400
        )
      );
      return;
    }

    const fileType = selectedFile.type.toLowerCase();
    const isExtensionMatch = /\.(pdf|png|jpe?g|webp)$/i.test(selectedFile.name);
    if (!ACCEPTED_TYPES.includes(fileType) && !isExtensionMatch) {
      setError(
        formatDocumentScanErrorNotice(
          'invalid_file',
          'Unsupported file type. Please upload a PDF document or a PNG, JPEG, or WebP image.',
          400
        )
      );
      return;
    }

    setFile(selectedFile);

    if (selectedFile.type.startsWith('image/')) {
      const objectUrl = URL.createObjectURL(selectedFile);
      setPreviewUrl(objectUrl);
    } else {
      setPreviewUrl(null);
    }
  };

  const onInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileChange(e.target.files[0]);
    }
  };

  const handleDrag = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleClearFile = () => {
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    setFile(null);
    setPreviewUrl(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || isScanning) return;

    setIsScanning(true);
    setError(null);
    isAbortedByUserRef.current = false;
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setScanStep('Step 1/3: Validating file signature & security limits...');

    try {
      const formData = new FormData();
      formData.append('file', file);
      if (contextNote.trim()) {
        formData.append('context', contextNote.trim());
      }

      setScanStep(
        file.type === 'application/pdf'
          ? 'Step 2/3: Parsing PDF text streams & extracting structure...'
          : 'Step 2/3: Preparing screenshot for visual inspection...'
      );

      const response = await fetch('/api/scan-document', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin',
        signal: controller.signal,
      });

      setScanStep('Step 3/3: Aegis AI Document Intelligence is inspecting your file...');

      const data = await response.json().catch(() => null);
      if (data?.quota) {
        updateQuotaSnapshot(data.quota);
      } else {
        refreshQuota();
      }

      if (!response.ok) {
        if (
          data?.errorCode === 'quota_exhausted' ||
          data?.errorCode === 'invalid_guest_token' ||
          data?.errorCode === 'email_verification_required'
        ) {
          setError({
            categoryTitle:
              data?.errorCode === 'email_verification_required'
                ? 'Email Verification Required'
                : 'Investigation Credits Exhausted',
            message:
              data?.error ||
              'You have exhausted your available Document & Screenshot scanning credits.',
            isRetryable: false,
            requiresRegistration: Boolean(data?.requiresRegistration),
          });
          return;
        }
        setError(
          formatDocumentScanErrorNotice(
            data?.errorCode,
            data?.error || `Document scan failed with status ${response.status}.`,
            response.status
          )
        );
        return;
      }

      if (!data?.result) {
        setError(
          formatDocumentScanErrorNotice(
            'providers_unavailable',
            'Analysis response did not contain a valid report.',
            502
          )
        );
        return;
      }

      onScanComplete(data.result);
    } catch (err: any) {
      console.error('Document scan error:', err?.message || 'request_failed');
      if (err?.name === 'AbortError') {
        if (isAbortedByUserRef.current) {
          setError({
            categoryTitle: 'Scan Cancelled',
            message: 'Analysis was cancelled by the user. You can start a fresh scan when ready.',
            isRetryable: true,
          });
        } else {
          setError(
            formatDocumentScanErrorNotice(
              'provider_timeout',
              'The document analysis timed out awaiting visual inspection. Click "Retry Analysis" to submit a fresh scan.',
              504
            )
          );
        }
      } else {
        setError(
          formatDocumentScanErrorNotice(
            'providers_unavailable',
            err?.message || 'An unexpected error occurred during document analysis.'
          )
        );
      }
    } finally {
      setIsScanning(false);
      setScanStep('');
      abortControllerRef.current = null;
    }
  };

  const handleLoadSample = (sampleType: 'invoice' | 'phish_sms' | 'clean_receipt') => {
    handleClearFile();
    let textContent = '';
    let fileName = '';
    const mime = 'application/pdf';

    if (sampleType === 'invoice') {
      fileName = 'Urgent_Invoice_Overdue_9410.pdf';
      textContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 195 >>
stream
BT
/F1 12 Tf
72 712 Td
(GEEK SQUAD RENEWAL NOTICE - INVOICE #9410-B) Tj
0 -20 Td
(Amount: $499.99 automatically charged to your linked account.) Tj
0 -20 Td
(To cancel or dispute, call immediate toll-free line: +1-888-555-0199) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000174 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
420
%%EOF`;
    } else if (sampleType === 'phish_sms') {
      fileName = 'Suspicious_Account_Lock_Alert.pdf';
      textContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 210 >>
stream
BT
/F1 12 Tf
72 712 Td
(SECURITY ALERT: Unauthorized access from Moscow, Russia.) Tj
0 -20 Td
(Your Bank of America online banking has been temporarily disabled.) Tj
0 -20 Td
(Verify your credentials within 10 minutes at https://bofa-security-auth.top/resolve) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000174 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
435
%%EOF`;
    } else {
      fileName = 'Legitimate_Coffee_Order_Receipt.pdf';
      textContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 170 >>
stream
BT
/F1 12 Tf
72 712 Td
(Blue Bottle Coffee - Store #104) Tj
0 -20 Td
(1x Oat Milk Latte - $6.50) Tj
0 -20 Td
(Paid via Apple Pay ending in 9102. Thank you for visiting!) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000174 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
395
%%EOF`;
    }

    const sampleBlob = new Blob([textContent], { type: mime });
    const sampleFile = new File([sampleBlob], fileName, { type: mime });
    handleFileChange(sampleFile);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] p-5 sm:p-7 shadow-[var(--shadow-sm)]">
      {/* Header and Guidelines */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--border-subtle)] pb-5">
        <div>
          <h3 className="text-lg font-bold text-[var(--foreground)] flex items-center gap-2 font-[family-name:var(--font-display)]">
            <UploadCloud className="h-5 w-5 text-[var(--accent-cyan)]" aria-hidden="true" />
            <span>Upload Document or Screenshot</span>
          </h3>
          <p className="mt-1 text-xs text-[var(--foreground-secondary)] max-w-xl">
            Analyze suspicious email screenshots, payment demands, fake invoices, and customer support impersonations. All uploads are processed strictly as untrusted evidence.
          </p>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] font-mono text-[var(--muted-foreground)] bg-[var(--surface-interactive)] px-3 py-1.5 rounded-lg border border-[var(--border-subtle)] self-start sm:self-auto">
          <Lock className="h-3.5 w-3.5 text-[var(--accent-cyan)]" aria-hidden="true" />
          <span>Max 10MB &middot; PDF, PNG, JPG, WebP</span>
        </div>
      </div>

      {/* Preset Demo Samples Bar */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-medium text-[var(--foreground-secondary)] flex items-center gap-1">
          <Sparkles className="h-3 w-3 text-[var(--primary-orange)]" aria-hidden="true" />
          <span>Try a test document:</span>
        </span>
        <button
          type="button"
          onClick={() => handleLoadSample('invoice')}
          disabled={isScanning}
          className="rounded-lg border border-[var(--status-warning-border)] bg-[var(--status-warning-bg)] px-2.5 py-1 text-[11px] font-medium text-[var(--status-warning)] hover:opacity-90 transition-opacity cursor-pointer disabled:opacity-50"
        >
          Fake Geek Squad Invoice (PDF)
        </button>
        <button
          type="button"
          onClick={() => handleLoadSample('phish_sms')}
          disabled={isScanning}
          className="rounded-lg border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] px-2.5 py-1 text-[11px] font-medium text-[var(--status-critical)] hover:opacity-90 transition-opacity cursor-pointer disabled:opacity-50"
        >
          Account Lock Phish (PDF)
        </button>
        <button
          type="button"
          onClick={() => handleLoadSample('clean_receipt')}
          disabled={isScanning}
          className="rounded-lg border border-[var(--status-success-border)] bg-[var(--status-success-bg)] px-2.5 py-1 text-[11px] font-medium text-[var(--status-success)] hover:opacity-90 transition-opacity cursor-pointer disabled:opacity-50"
        >
          Normal Coffee Receipt (PDF)
        </button>
      </div>

      <form onSubmit={handleSubmit} className="mt-5 space-y-5">
        {/* Dropzone Container */}
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => !file && fileInputRef.current?.click()}
          role={!file ? 'button' : undefined}
          tabIndex={!file ? 0 : undefined}
          aria-label={!file ? 'Upload PDF or image screenshot for analysis' : undefined}
          onKeyDown={(e) => {
            if (!file && (e.key === 'Enter' || e.key === ' ')) {
              e.preventDefault();
              fileInputRef.current?.click();
            }
          }}
          className={`relative rounded-2xl border-2 border-dashed p-6 sm:p-8 text-center transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)] ${
            dragActive
              ? 'border-[var(--primary-orange)] bg-[var(--surface-soft-orange)] ring-4 ring-[var(--primary-orange-glow)]'
              : file
              ? 'border-[var(--border)] bg-[var(--surface-interactive)]'
              : 'border-[var(--border)] bg-[var(--surface-interactive)]/60 hover:border-[var(--primary-orange)]/60 hover:bg-[var(--surface-soft-orange)]/50 cursor-pointer'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pdf,.png,.jpg,.jpeg,.webp,application/pdf,image/png,image/jpeg,image/webp"
            onChange={onInputChange}
            className="hidden"
            disabled={isScanning}
          />

          {!file ? (
            <div className="space-y-3">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--surface-soft-orange)] border border-[var(--primary-orange)]/30 text-[var(--primary-orange)] shadow-inner">
                <UploadCloud className="h-7 w-7" aria-hidden="true" />
              </div>
              <div>
                <p className="text-sm font-semibold text-[var(--foreground)]">
                  Drag and drop your document or screenshot here
                </p>
                <p className="mt-1 text-xs text-[var(--foreground-secondary)]">
                  Or <span className="text-[var(--primary-orange)] font-medium underline underline-offset-2">browse your computer</span> to select
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-[11px] text-[var(--muted-foreground)] font-mono">
                <span className="rounded bg-[var(--surface)] px-2 py-0.5 border border-[var(--border)]">PDF</span>
                <span className="rounded bg-[var(--surface)] px-2 py-0.5 border border-[var(--border)]">PNG</span>
                <span className="rounded bg-[var(--surface)] px-2 py-0.5 border border-[var(--border)]">JPG / JPEG</span>
                <span className="rounded bg-[var(--surface)] px-2 py-0.5 border border-[var(--border)]">WebP</span>
                <span>(Up to 10MB)</span>
              </div>
            </div>
          ) : (
            <div className="flex flex-col sm:flex-row items-center gap-4 text-left">
              {previewUrl ? (
                <div className="relative h-24 w-24 sm:h-28 sm:w-28 shrink-0 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--background-secondary)]">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={previewUrl}
                    alt="Uploaded preview"
                    className="h-full w-full object-cover"
                  />
                  <div className="absolute bottom-1 right-1 rounded bg-[var(--background)]/85 border border-[var(--border)] px-1.5 py-0.5 text-[9px] font-mono text-[var(--accent-cyan)]">
                    Image
                  </div>
                </div>
              ) : (
                <div className="flex h-24 w-24 sm:h-28 sm:w-28 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 text-[var(--accent-cyan)]">
                  <FileText className="h-10 w-10" aria-hidden="true" />
                </div>
              )}

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-[var(--accent-cyan-subtle)] border border-[var(--accent-cyan)]/30 px-2 py-0.5 text-[10px] font-mono font-bold text-[var(--accent-cyan)] uppercase">
                    {file.type === 'application/pdf' ? 'PDF Document' : 'Screenshot'}
                  </span>
                  <span className="text-xs text-[var(--muted-foreground)] font-mono tabular-nums">
                    {formatFileSize(file.size)}
                  </span>
                </div>
                <h4 className="mt-1 text-sm font-bold text-[var(--foreground)] truncate max-w-md">
                  {file.name}
                </h4>
                <p className="mt-1 text-xs text-[var(--foreground-secondary)] flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-[var(--status-success)]" aria-hidden="true" />
                  <span>Ready for secure analysis &amp; IOC extraction</span>
                </p>
              </div>

              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleClearFile();
                }}
                disabled={isScanning}
                aria-label="Remove file and select another"
                className="rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--status-critical-bg)] hover:border-[var(--status-critical-border)] p-2.5 text-[var(--muted-foreground)] hover:text-[var(--status-critical)] transition-colors cursor-pointer disabled:opacity-50"
                title="Remove file and select another"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          )}
        </div>

        {/* Optional Context Field */}
        <div>
          <label htmlFor="context-notes" className="block text-xs font-semibold text-[var(--foreground)] mb-1.5">
            Additional Context or Source <span className="text-[var(--muted-foreground)] font-normal">(Optional)</span>
          </label>
          <input
            id="context-notes"
            type="text"
            value={contextNote}
            onChange={(e) => setContextNote(e.target.value)}
            disabled={isScanning}
            placeholder="e.g., Received via WhatsApp claiming to be our supplier changing bank details..."
            className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-interactive)] px-3.5 py-2.5 text-xs text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:border-[var(--primary-orange)] focus:outline-none focus:ring-1 focus:ring-[var(--primary-orange)]"
          />
        </div>

        {/* Error State */}
        {error && (
          <div
            role="alert"
            className="rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] p-4 text-xs text-[var(--status-critical)] flex items-start gap-2.5"
          >
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="flex-1">
              <strong className="font-semibold">{error.categoryTitle}:</strong>
              <p className="mt-1 leading-relaxed text-[var(--foreground)]">{error.message}</p>
              {error.requiresRegistration && (
                <Link
                  href="/auth/register"
                  className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-3 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] transition-colors"
                >
                  <span>Create Free Account</span>
                </Link>
              )}
              {file && !isScanning && error.isRetryable && (
                <button
                  type="button"
                  onClick={(e) => handleSubmit(e)}
                  className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-3 py-1.5 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer"
                >
                  <RefreshCw className="h-3.5 w-3.5 text-[var(--primary-orange)]" aria-hidden="true" />
                  <span>Retry Analysis</span>
                </button>
              )}
            </div>
            <button
              type="button"
              onClick={() => setError(null)}
              aria-label="Dismiss error"
              className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] cursor-pointer"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        )}

        {/* Scanning In-Flight Status Indicator */}
        {isScanning && (
          <div className="rounded-xl border border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan-subtle)] p-4 text-xs text-[var(--foreground)] space-y-2">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-[var(--accent-cyan)]" aria-hidden="true" />
                <strong className="font-semibold">{scanStep || 'Analyzing threat vectors...'}</strong>
              </div>
              <button
                type="button"
                onClick={handleCancelScan}
                className="rounded-lg border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] hover:opacity-90 px-2.5 py-1 text-[11px] font-medium text-[var(--status-critical)] transition-opacity cursor-pointer"
              >
                Cancel
              </button>
            </div>
            <div className="w-full bg-[var(--surface)] rounded-full h-1.5 overflow-hidden border border-[var(--border-subtle)]">
              <div className="bg-[var(--accent-cyan)] h-1.5 rounded-full animate-pulse w-3/4" />
            </div>
            <p className="text-[11px] text-[var(--foreground-secondary)]">
              Extracted content is isolated in safe analysis memory. URLs are not automatically navigated.
            </p>
          </div>
        )}

        {/* Submit Actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2 text-[11px] text-[var(--muted-foreground)]">
            <Shield className="h-3.5 w-3.5 text-[var(--accent-cyan)]" aria-hidden="true" />
            <span>Server-side sandboxed triage &middot; Zero permanent raw file storage</span>
          </div>

          <div className="flex items-center gap-2">
            {file && (
              <button
                type="button"
                onClick={handleClearFile}
                disabled={isScanning}
                className="rounded-xl border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-interactive)] px-4 py-2 text-xs font-semibold text-[var(--foreground)] transition-colors cursor-pointer disabled:opacity-50"
              >
                Clear
              </button>
            )}
            {isScanning ? (
              <button
                type="button"
                onClick={handleCancelScan}
                className="inline-flex items-center gap-2 rounded-xl border border-[var(--status-critical-border)] bg-[var(--status-critical-bg)] hover:opacity-90 px-4 py-2.5 text-xs font-bold text-[var(--status-critical)] transition-opacity cursor-pointer"
              >
                <X className="h-4 w-4" aria-hidden="true" />
                <span>Cancel Scan</span>
              </button>
            ) : (
              <button
                type="submit"
                disabled={!file || isScanning || isQuotaBlocked}
                className="inline-flex items-center gap-2 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--primary-deep-orange)] px-5 py-2.5 text-xs font-bold text-[var(--primary-foreground)] shadow-sm transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                <span>{isQuotaBlocked ? 'Credits Exhausted' : 'Analyze Threat Vectors'}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>
        </div>
      </form>
    </div>
  );
}
