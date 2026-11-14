import React from 'react';
import { Download } from 'lucide-react';

export type CodeReviewNavSection = 'inspect' | 'edit' | 'diff' | 'history';

interface TopBarProps {
  activeSection: CodeReviewNavSection;
  onNavigate: (section: CodeReviewNavSection) => void;
  onOpenExportModal: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeSection,
  onNavigate,
  onOpenExportModal,
}) => {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-8 px-4 py-3.5 sm:px-6 lg:px-8">
        {/* Zone 1: Single text element wordmark */}
        <button
          type="button"
          onClick={() => onNavigate('inspect')}
          className="text-left text-base font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-600"
        >
          SecureCode AST
        </button>

        {/* Zone 2: 4 concise single-line text navigation links */}
        <nav aria-label="Primary navigation" className="hidden md:flex items-center gap-6 text-sm font-medium">
          <button
            type="button"
            onClick={() => onNavigate('inspect')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'inspect'
                ? 'border-sky-600 text-slate-900'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            AST Analyzer
          </button>
          <button
            type="button"
            onClick={() => onNavigate('edit')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'edit'
                ? 'border-sky-600 text-slate-900'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            Custom Editor
          </button>
          <button
            type="button"
            onClick={() => onNavigate('diff')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'diff'
                ? 'border-sky-600 text-slate-900'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            Remediation Diff
          </button>
          <button
            type="button"
            onClick={() => onNavigate('history')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'history'
                ? 'border-sky-600 text-slate-900'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            Audit History
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onOpenExportModal}
            className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-slate-800 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-600"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Export Project Kit</span>
          </button>
        </div>
      </div>
    </header>
  );
};
