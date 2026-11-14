import { useCallback, useEffect, useState } from 'react';
import { ExportKitModal } from './components/ExportKitModal';
import { HistoryPanel, type HistoryItem } from './components/HistoryPanel';
import { SecureCodeProject } from './components/SecureCodeProject';
import { TopBar, type CodeReviewNavSection } from './components/TopBar';
import { SECURE_CODE_SAMPLES } from './data/secureCodeSamples';
import { analyzeSourceCode, type AuditReport } from './utils/codeAnalyzer';

export default function App() {
  const [activeSection, setActiveSection] = useState<CodeReviewNavSection>('inspect');
  const [viewMode, setViewMode] = useState<'inspect' | 'edit' | 'diff'>('inspect');
  const [exportModalOpen, setExportModalOpen] = useState(false);

  const initialSample = SECURE_CODE_SAMPLES[0];
  const [latestReport, setLatestReport] = useState<AuditReport>(() =>
    analyzeSourceCode(initialSample.vulnerableCode, initialSample.language)
  );
  const [latestSampleTitle, setLatestSampleTitle] = useState<string>(initialSample.title);
  const [historyEntries, setHistoryEntries] = useState<HistoryItem[]>([]);

  const loadHistory = useCallback(async () => {
    try {
      const resp = await fetch('/api/history');
      if (resp.ok) {
        const data = (await resp.json()) as { entries: HistoryItem[] };
        setHistoryEntries(Array.isArray(data.entries) ? data.entries : []);
      }
    } catch {
      // Ignore if offline
    }
  }, []);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const handleDeleteHistory = async (id: string) => {
    try {
      const resp = await fetch(`/api/history/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (resp.ok) {
        setHistoryEntries((prev) => prev.filter((item) => item.id !== id));
      }
    } catch {
      // Ignore network errors
    }
  };

  const handleNavigate = (section: CodeReviewNavSection) => {
    setActiveSection(section);
    if (section === 'history') {
      document.getElementById('audit-history')?.scrollIntoView({ behavior: 'smooth' });
      return;
    }
    setViewMode(section);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      <TopBar
        activeSection={activeSection}
        onNavigate={handleNavigate}
        onOpenExportModal={() => setExportModalOpen(true)}
      />

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
        <SecureCodeProject
          controlledViewMode={viewMode}
          onViewModeChange={(mode) => {
            setViewMode(mode);
            setActiveSection(mode);
          }}
          onReportChange={(report, title) => {
            setLatestReport(report);
            setLatestSampleTitle(title);
          }}
          onHistoryUpdated={() => void loadHistory()}
        />

        <HistoryPanel entries={historyEntries} onDelete={(id) => void handleDeleteHistory(id)} />
      </main>

      <footer className="border-t border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-2 px-4 py-5 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
          <p>SecureCode AST · Static Application Security Review</p>
          <p className="font-mono">Python 3 AST · Babel JS/TS AST · OWASP Top 10</p>
        </div>
      </footer>

      <ExportKitModal
        isOpen={exportModalOpen}
        onClose={() => setExportModalOpen(false)}
        latestReport={latestReport}
        activeSampleTitle={latestSampleTitle}
      />
    </div>
  );
}
