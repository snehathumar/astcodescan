import React, { useState } from 'react';
import { Check, Download, X } from 'lucide-react';
import type { AuditReport } from '../utils/codeAnalyzer';
import {
  buildSecureCodingPythonAuditor,
  buildSecureCodingReadmeMarkdown,
  generateAuditMarkdownReport,
} from '../utils/codeAnalyzer';
import { downloadTextFile } from '../utils/downloadFile';

interface ExportKitModalProps {
  isOpen: boolean;
  onClose: () => void;
  latestReport: AuditReport;
  activeSampleTitle: string;
}

export const ExportKitModal: React.FC<ExportKitModalProps> = ({
  isOpen,
  onClose,
  latestReport,
  activeSampleTitle,
}) => {
  const [downloadedId, setDownloadedId] = useState<string | null>(null);

  if (!isOpen) {
    return null;
  }

  const triggerDownload = (id: string, filename: string, content: string, mime?: string) => {
    downloadTextFile(filename, content, mime);
    setDownloadedId(id);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="export-kit-title"
    >
      <div className="w-full max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 pb-4">
          <div>
            <p className="text-xs font-medium text-sky-700">
              Secure Coding Review · Export Artifacts
            </p>
            <h2 id="export-kit-title" className="mt-1 text-xl font-bold text-slate-900">
              Export Security Audit Kit
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close export modal"
            className="rounded-lg p-2 text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <p className="mt-4 text-sm leading-relaxed text-slate-600">
          Download ready-to-use audit artifacts, including your live audit findings (
          {latestReport.summary.totalFindings} detected) and standalone Python static analyzer.
        </p>

        <div className="mt-5 rounded-lg border border-slate-200 bg-slate-50/70 p-4 space-y-2.5">
          <button
            type="button"
            onClick={() =>
              triggerDownload(
                'p2-readme',
                'README.md',
                buildSecureCodingReadmeMarkdown(),
                'text/markdown;charset=utf-8'
              )
            }
            className="flex w-full items-center justify-between rounded-lg border border-slate-200 bg-white px-3.5 py-2.5 text-xs font-medium text-slate-800 transition-colors hover:border-sky-300 hover:text-sky-700"
          >
            <span>Download README.md (Documentation)</span>
            {downloadedId === 'p2-readme' ? (
              <Check className="h-4 w-4 text-emerald-600" aria-hidden="true" />
            ) : (
              <Download className="h-4 w-4 text-slate-400" aria-hidden="true" />
            )}
          </button>

          <button
            type="button"
            onClick={() =>
              triggerDownload(
                'p2-report',
                'secure_coding_audit_report.md',
                generateAuditMarkdownReport(latestReport, activeSampleTitle),
                'text/markdown;charset=utf-8'
              )
            }
            className="flex w-full items-center justify-between rounded-lg border border-slate-200 bg-white px-3.5 py-2.5 text-xs font-medium text-slate-800 transition-colors hover:border-sky-300 hover:text-sky-700"
          >
            <span>Download Live Audit Report (.md)</span>
            {downloadedId === 'p2-report' ? (
              <Check className="h-4 w-4 text-emerald-600" aria-hidden="true" />
            ) : (
              <Download className="h-4 w-4 text-slate-400" aria-hidden="true" />
            )}
          </button>

          <button
            type="button"
            onClick={() =>
              triggerDownload(
                'p2-py',
                'secure_code_auditor.py',
                buildSecureCodingPythonAuditor(),
                'text/x-python;charset=utf-8'
              )
            }
            className="flex w-full items-center justify-between rounded-lg border border-slate-200 bg-white px-3.5 py-2.5 text-xs font-medium text-slate-800 transition-colors hover:border-sky-300 hover:text-sky-700"
          >
            <span>Download Standalone CLI Script (secure_code_auditor.py)</span>
            {downloadedId === 'p2-py' ? (
              <Check className="h-4 w-4 text-emerald-600" aria-hidden="true" />
            ) : (
              <Download className="h-4 w-4 text-slate-400" aria-hidden="true" />
            )}
          </button>
        </div>

        <div className="mt-5 flex items-center justify-between border-t border-slate-200 pt-4">
          <p className="text-xs text-slate-500">
            Includes Markdown audit report, docs &amp; Python CLI
          </p>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-slate-800 whitespace-nowrap"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
