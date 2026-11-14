import React from 'react';
import { History, Trash2 } from 'lucide-react';

export interface HistoryItem {
  id: string;
  kind: 'url-scan' | 'email-scan' | 'code-audit' | 'quiz-attempt';
  title: string;
  summary: string;
  severityOrScore: string;
  createdAt: string;
}

interface HistoryPanelProps {
  entries: HistoryItem[];
  onDelete: (id: string) => void;
}

export const HistoryPanel: React.FC<HistoryPanelProps> = ({ entries, onDelete }) => {
  const auditEntries = entries.filter((e) => e.kind === 'code-audit');

  return (
    <section
      id="audit-history"
      aria-labelledby="saved-history-heading"
      className="mt-10 rounded-xl border border-slate-200 bg-white p-5"
    >
      <div className="flex items-center justify-between gap-4 border-b border-slate-200 pb-3.5">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-slate-500" aria-hidden="true" />
          <h2 id="saved-history-heading" className="text-base font-bold text-slate-900">
            Persisted Security Audit Log ({auditEntries.length})
          </h2>
        </div>
        <p className="text-xs text-slate-500">Stored server-side across sessions</p>
      </div>

      {auditEntries.length === 0 ? (
        <p className="mt-4 text-xs text-slate-500">
          No persisted code audits yet. Run an AST security audit, upload a file, or scan a
          workspace file to save results automatically.
        </p>
      ) : (
        <div className="mt-3 divide-y divide-slate-200">
          {auditEntries.slice(0, 10).map((entry) => (
            <div
              key={entry.id}
              className="flex flex-wrap items-center justify-between gap-3 py-3 text-xs"
            >
              <div className="min-w-0 flex-1">
                <p className="text-slate-500">
                  AST Code Audit · {new Date(entry.createdAt).toLocaleString()}
                </p>
                <p className="mt-0.5 truncate font-mono font-semibold text-slate-900">
                  {entry.title}
                </p>
                <p className="mt-0.5 text-slate-600">{entry.summary}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="font-mono font-semibold text-slate-800 tabular-nums">
                  {entry.severityOrScore}
                </span>
                <button
                  type="button"
                  onClick={() => onDelete(entry.id)}
                  aria-label={`Delete audit log ${entry.title}`}
                  className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-red-700"
                >
                  <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
};
