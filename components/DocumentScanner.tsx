'use client';

import React, { useState, useRef, DragEvent, ChangeEvent } from 'react';
import {
  UploadCloud,
  FileText,
  Image as ImageIcon,
  X,
  AlertCircle,
  Loader2,
  CheckCircle2,
  Lock,
  Eye,
  FileCheck,
  ShieldAlert,
  HelpCircle,
  RefreshCw,
  Sparkles,
  ArrowRight,
  Shield,
  Layers,
} from 'lucide-react';
import { DocumentScanResult } from '@/lib/document-scanner';

interface DocumentScannerProps {
  onScanComplete: (result: DocumentScanResult) => void;
  isScanning: boolean;
  setIsScanning: (scanning: boolean) => void;
}

const MAX_SIZE_MB = 10;
const MAX_BYTES = MAX_SIZE_MB * 1024 * 1024;
const ACCEPTED_TYPES = ['application/pdf', 'image/png', 'image/jpeg', 'image/webp'];

export default function DocumentScanner({
  onScanComplete,
  isScanning,
  setIsScanning,
}: DocumentScannerProps) {
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [contextNote, setContextNote] = useState('');
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
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

    // Size validation
    if (selectedFile.size > MAX_BYTES) {
      setError(`File size (${(selectedFile.size / (1024 * 1024)).toFixed(1)}MB) exceeds the 10MB limit.`);
      return;
    }

    // Format validation
    const fileType = selectedFile.type.toLowerCase();
    const isExtensionMatch = /\.(pdf|png|jpe?g|webp)$/i.test(selectedFile.name);
    if (!ACCEPTED_TYPES.includes(fileType) && !isExtensionMatch) {
      setError('Unsupported file type. Please upload a PDF document or a PNG, JPEG, or WebP image.');
      return;
    }

    setFile(selectedFile);

    // Create image preview if image
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

    setScanStep('Step 1/3: Validating file signature & SHA-256 fingerprint...');

    try {
      const formData = new FormData();
      formData.append('file', file);
      if (contextNote.trim()) {
        formData.append('context', contextNote.trim());
      }

      setScanStep(
        file.type === 'application/pdf'
          ? 'Step 2/3: Parsing PDF text streams & extracting structure...'
          : 'Step 2/3: Uploading screenshot & preparing visual OCR...'
      );

      const response = await fetch('/api/scan-document', {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      });

      setScanStep('Step 3/3: Awaiting Featherless AI multimodal inspection (this may take 15-30s)...');

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error || `Upload failed with status ${response.status}`);
      }

      if (!data?.result) {
        throw new Error('Analysis response did not contain a valid report.');
      }

      onScanComplete(data.result);
    } catch (err: any) {
      console.error('Document scan error:', err);
      if (err?.name === 'AbortError') {
        if (isAbortedByUserRef.current) {
          setError('Analysis was cancelled by the user. You can restart or retry when ready.');
        } else {
          setError('The document analysis was aborted or timed out awaiting upstream visual OCR. Click "Retry Analysis" to safely re-attempt; prior preprocessing is cached.');
        }
      } else {
        setError(err?.message || 'An unexpected error occurred during document analysis.');
      }
    } finally {
      setIsScanning(false);
      setScanStep('');
      abortControllerRef.current = null;
    }
  };

  // Preset demo generator for quick evaluation
  const handleLoadSample = (sampleType: 'invoice' | 'phish_sms' | 'clean_receipt') => {
    handleClearFile();
    let textContent = '';
    let fileName = '';
    let mime = 'application/pdf';

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
    <div className="rounded-2xl border border-white/5 bg-[#0d1322] p-5 sm:p-7 shadow-xl">
      {/* Header and Guidelines */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/5 pb-5">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <UploadCloud className="h-5 w-5 text-cyan-400" />
            <span>Upload Document or Screenshot</span>
          </h3>
          <p className="mt-1 text-xs text-slate-400 max-w-xl">
            Analyze suspicious email screenshots, payment demands, fake invoices, and customer support impersonations. All uploads are processed strictly as untrusted evidence.
          </p>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-white/5 self-start sm:self-auto">
          <Lock className="h-3.5 w-3.5 text-cyan-400" />
          <span>Max 10MB &middot; PDF, PNG, JPG, WebP</span>
        </div>
      </div>

      {/* Preset Demo Samples Bar */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-medium text-slate-400 flex items-center gap-1">
          <Sparkles className="h-3 w-3 text-cyan-400" />
          <span>Try a test document:</span>
        </span>
        <button
          type="button"
          onClick={() => handleLoadSample('invoice')}
          disabled={isScanning}
          className="rounded-lg border border-amber-500/30 bg-amber-950/20 px-2.5 py-1 text-[11px] font-medium text-amber-300 hover:bg-amber-900/30 transition-colors cursor-pointer"
        >
          Fake Geek Squad Invoice (PDF)
        </button>
        <button
          type="button"
          onClick={() => handleLoadSample('phish_sms')}
          disabled={isScanning}
          className="rounded-lg border border-red-500/30 bg-red-950/20 px-2.5 py-1 text-[11px] font-medium text-red-300 hover:bg-red-900/30 transition-colors cursor-pointer"
        >
          Account Lock Phish (PDF)
        </button>
        <button
          type="button"
          onClick={() => handleLoadSample('clean_receipt')}
          disabled={isScanning}
          className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 px-2.5 py-1 text-[11px] font-medium text-emerald-300 hover:bg-emerald-900/30 transition-colors cursor-pointer"
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
          className={`relative rounded-2xl border-2 border-dashed p-6 sm:p-8 text-center transition-all ${
            dragActive
              ? 'border-cyan-400 bg-cyan-950/20 ring-4 ring-cyan-500/20'
              : file
              ? 'border-white/10 bg-[#090d18]'
              : 'border-white/10 bg-[#090d18]/60 hover:border-cyan-500/40 hover:bg-cyan-950/10 cursor-pointer'
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
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 shadow-inner">
                <UploadCloud className="h-7 w-7" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">
                  Drag and drop your document or screenshot here
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  Or <span className="text-cyan-400 underline underline-offset-2">browse your computer</span> to select
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-[11px] text-slate-400">
                <span className="rounded bg-slate-900 px-2 py-0.5 border border-white/5">PDF</span>
                <span className="rounded bg-slate-900 px-2 py-0.5 border border-white/5">PNG</span>
                <span className="rounded bg-slate-900 px-2 py-0.5 border border-white/5">JPG / JPEG</span>
                <span className="rounded bg-slate-900 px-2 py-0.5 border border-white/5">WebP</span>
                <span>(Up to 10MB)</span>
              </div>
            </div>
          ) : (
            <div className="flex flex-col sm:flex-row items-center gap-4 text-left">
              {/* Preview or Document Icon */}
              {previewUrl ? (
                <div className="relative h-24 w-24 sm:h-28 sm:w-28 shrink-0 overflow-hidden rounded-xl border border-white/10 bg-black/40">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={previewUrl}
                    alt="Uploaded preview"
                    className="h-full w-full object-cover"
                  />
                  <div className="absolute bottom-1 right-1 rounded bg-black/70 px-1 py-0.5 text-[9px] font-mono text-cyan-300">
                    Image
                  </div>
                </div>
              ) : (
                <div className="flex h-24 w-24 sm:h-28 sm:w-28 shrink-0 items-center justify-center rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-cyan-400">
                  <FileText className="h-10 w-10" />
                </div>
              )}

              {/* File Details */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-cyan-950/80 border border-cyan-500/30 px-2 py-0.5 text-[10px] font-mono font-bold text-cyan-300 uppercase">
                    {file.type === 'application/pdf' ? 'PDF Document' : 'Screenshot'}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    {formatFileSize(file.size)}
                  </span>
                </div>
                <h4 className="mt-1 text-sm font-bold text-white truncate max-w-md">
                  {file.name}
                </h4>
                <p className="mt-1 text-xs text-slate-400 flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Ready for secure analysis &amp; IOC extraction</span>
                </p>
              </div>

              {/* Remove Button */}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleClearFile();
                }}
                disabled={isScanning}
                className="rounded-xl border border-white/10 bg-slate-900/80 hover:bg-red-950/40 hover:border-red-500/30 p-2.5 text-slate-400 hover:text-red-400 transition-colors cursor-pointer"
                title="Remove file and select another"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {/* Optional Context Field */}
        <div>
          <label htmlFor="context-notes" className="block text-xs font-semibold text-slate-300 mb-1.5">
            Additional Context or Source <span className="text-slate-400 font-normal">(Optional)</span>
          </label>
          <input
            id="context-notes"
            type="text"
            value={contextNote}
            onChange={(e) => setContextNote(e.target.value)}
            disabled={isScanning}
            placeholder="e.g., Received via WhatsApp claiming to be our supplier changing bank details..."
            className="w-full rounded-xl border border-white/10 bg-[#090d18] px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        {/* Error State */}
        {error && (
          <div
            role="alert"
            className="rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-xs text-red-300 flex items-start gap-2.5"
          >
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
            <div className="flex-1">
              <strong className="text-red-200">Document scan status:</strong>
              <p className="mt-1 leading-relaxed">{error}</p>
              {file && !isScanning && (
                <button
                  type="button"
                  onClick={(e) => handleSubmit(e)}
                  className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/60 hover:bg-cyan-900/60 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:text-white transition-colors cursor-pointer"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  <span>Retry Analysis</span>
                </button>
              )}
            </div>
            <button
              type="button"
              onClick={() => setError(null)}
              className="text-red-400 hover:text-white"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* Scanning In-Flight Status Indicator */}
        {isScanning && (
          <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-4 text-xs text-cyan-200 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                <strong className="font-semibold">{scanStep || 'Analyzing threat vectors...'}</strong>
              </div>
              <button
                type="button"
                onClick={handleCancelScan}
                className="rounded-lg border border-red-500/30 bg-red-950/40 hover:bg-red-900/50 px-2.5 py-1 text-[11px] font-medium text-red-300 hover:text-white transition-colors cursor-pointer"
              >
                Cancel
              </button>
            </div>
            <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
              <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-1.5 rounded-full animate-pulse w-3/4" />
            </div>
            <p className="text-[11px] text-slate-400">
              Extracted content is isolated in safe analysis memory. URLs are not automatically navigated.
            </p>
          </div>
        )}

        {/* Submit Actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <Shield className="h-3.5 w-3.5 text-cyan-400" />
            <span>Server-side sandboxed triage &middot; Zero permanent raw file storage</span>
          </div>

          <div className="flex items-center gap-2">
            {file && (
              <button
                type="button"
                onClick={handleClearFile}
                disabled={isScanning}
                className="rounded-xl border border-white/10 bg-slate-900/60 hover:bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
              >
                Clear
              </button>
            )}
            {isScanning ? (
              <button
                type="button"
                onClick={handleCancelScan}
                className="inline-flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-950/50 hover:bg-red-900/60 px-4 py-2.5 text-xs font-bold text-red-300 hover:text-white transition-colors cursor-pointer"
              >
                <X className="h-4 w-4" />
                <span>Cancel Scan</span>
              </button>
            ) : (
              <button
                type="submit"
                disabled={!file || isScanning}
                className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 px-5 py-2.5 text-xs font-bold text-white shadow-lg shadow-cyan-600/30 hover:shadow-cyan-500/50 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ShieldAlert className="h-4 w-4" />
                <span>Analyze Threat Vectors</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>
      </form>
    </div>
  );
}
