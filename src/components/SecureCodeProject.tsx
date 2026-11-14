import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertOctagon,
  CheckCircle2,
  Code2,
  Download,
  FolderSearch,
  Loader2,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import {
  SECURE_CODE_SAMPLES,
  type CodeLanguage,
  type CodeSample,
} from '../data/secureCodeSamples';
import {
  analyzeSourceCode,
  buildSecureCodingPythonAuditor,
  generateAuditMarkdownReport,
  type AuditReport,
  type SecurityFinding,
  type Severity,
} from '../utils/codeAnalyzer';
import { downloadTextFile } from '../utils/downloadFile';

interface SecureCodeProjectProps {
  onReportChange: (report: AuditReport, title: string) => void;
  onHistoryUpdated: () => void;
  controlledViewMode?: ViewMode;
  onViewModeChange?: (mode: ViewMode) => void;
}

interface WorkspaceFileOption {
  path: string;
  language: CodeLanguage;
}

interface BackendAuditReport extends AuditReport {
  engine?: string;
  parseError?: string | null;
}

type ViewMode = 'inspect' | 'edit' | 'diff';
type SeverityFilter = 'All' | Severity;

export const SecureCodeProject: React.FC<SecureCodeProjectProps> = ({
  onReportChange,
  onHistoryUpdated,
  controlledViewMode,
  onViewModeChange,
}) => {
  const initialSample = SECURE_CODE_SAMPLES[0];

  const [selectedSampleId, setSelectedSampleId] = useState<string>(initialSample.id);
  const [activeTitle, setActiveTitle] = useState<string>(initialSample.title);
  const [language, setLanguage] = useState<CodeLanguage>(initialSample.language);
  const [codeInput, setCodeInput] = useState<string>(initialSample.vulnerableCode);
  const [auditedCode, setAuditedCode] = useState<string>(initialSample.vulnerableCode);
  const [report, setReport] = useState<BackendAuditReport>(() => ({
    ...analyzeSourceCode(initialSample.vulnerableCode, initialSample.language),
    engine: 'Python 3 Native AST Auditor',
    parseError: null,
  }));
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const [internalViewMode, setInternalViewMode] = useState<ViewMode>('inspect');
  const viewMode = controlledViewMode ?? internalViewMode;
  const setViewMode = (mode: ViewMode) => {
    setInternalViewMode(mode);
    onViewModeChange?.(mode);
  };
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('All');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const [workspaceFiles, setWorkspaceFiles] = useState<WorkspaceFileOption[]>([]);
  const [selectedWorkspacePath, setSelectedWorkspacePath] = useState<string>('');

  const activeSample: CodeSample = useMemo(
    () => SECURE_CODE_SAMPLES.find((s) => s.id === selectedSampleId) ?? SECURE_CODE_SAMPLES[0],
    [selectedSampleId]
  );

  // Run initial real AST scan on mount + load workspace file allowlist
  useEffect(() => {
    let active = true;
    const init = async () => {
      try {
        const [scanResp, filesResp] = await Promise.all([
          fetch('/api/code-review/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              code: initialSample.vulnerableCode,
              language: initialSample.language,
              title: initialSample.title,
              saveHistory: false,
            }),
          }),
          fetch('/api/code-review/workspace-files'),
        ]);
        if (active && scanResp.ok) {
          const data = (await scanResp.json()) as BackendAuditReport;
          setReport(data);
          onReportChange(data, initialSample.title);
        }
        if (active && filesResp.ok) {
          const fileData = (await filesResp.json()) as { files: WorkspaceFileOption[] };
          setWorkspaceFiles(fileData.files ?? []);
          if (fileData.files?.length > 0) {
            setSelectedWorkspacePath(fileData.files[0].path);
          }
        }
      } catch {
        // Keep initial report if backend is unreachable
      }
    };
    void init();
    return () => {
      active = false;
    };
  }, []);

  const executeServerAstScan = async (
    targetCode: string,
    targetLanguage: CodeLanguage,
    targetTitle: string,
    saveHistory = true
  ) => {
    if (!targetCode.trim()) {
      setScanError('Source code cannot be empty.');
      return;
    }
    setScanning(true);
    setScanError(null);
    try {
      const resp = await fetch('/api/code-review/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: targetCode,
          language: targetLanguage,
          title: targetTitle,
          saveHistory,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setScanError(data.error || 'Failed to run AST security audit.');
      } else {
        const nextReport = data as BackendAuditReport;
        setAuditedCode(targetCode);
        setReport(nextReport);
        setSelectedFindingId(nextReport.findings[0]?.id ?? null);
        setSeverityFilter('All');
        setViewMode('inspect');
        onReportChange(nextReport, targetTitle);
        if (saveHistory) {
          onHistoryUpdated();
        }
      }
    } catch {
      setScanError('Network error while contacting backend AST scanner.');
    } finally {
      setScanning(false);
    }
  };

  const handleSelectSample = (sample: CodeSample) => {
    setSelectedSampleId(sample.id);
    setActiveTitle(sample.title);
    setLanguage(sample.language);
    setCodeInput(sample.vulnerableCode);
    void executeServerAstScan(sample.vulnerableCode, sample.language, sample.title, false);
  };

  const handleRunAudit = () => {
    void executeServerAstScan(codeInput, language, activeTitle, true);
  };

  const handleApplyCleanFixToEditor = () => {
    setCodeInput(activeSample.remediatedCode);
    setLanguage(activeSample.language);
    const title = `${activeSample.title} (Remediated)`;
    setActiveTitle(title);
    void executeServerAstScan(activeSample.remediatedCode, activeSample.language, title, true);
  };

  const handleSourceFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const lower = file.name.toLowerCase();
    const detectedLang: CodeLanguage = lower.endsWith('.py')
      ? 'python'
      : lower.endsWith('.php')
        ? 'php'
        : 'javascript';
    setLanguage(detectedLang);
    setCodeInput(text);
    setActiveTitle(`Uploaded: ${file.name}`);
    e.target.value = '';
    await executeServerAstScan(text, detectedLang, `Uploaded: ${file.name}`, true);
  };

  const handleScanWorkspaceFile = async () => {
    if (!selectedWorkspacePath) return;
    setScanning(true);
    setScanError(null);
    try {
      const resp = await fetch('/api/code-review/scan-workspace', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: selectedWorkspacePath }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setScanError(data.error || 'Failed to scan workspace file.');
      } else {
        const nextReport = data.report as BackendAuditReport;
        setLanguage(nextReport.language);
        setCodeInput(data.code);
        setAuditedCode(data.code);
        setActiveTitle(`Workspace: ${data.path}`);
        setReport(nextReport);
        setSelectedFindingId(nextReport.findings[0]?.id ?? null);
        setSeverityFilter('All');
        setViewMode('inspect');
        onReportChange(nextReport, `Workspace: ${data.path}`);
        onHistoryUpdated();
      }
    } catch {
      setScanError('Network error while scanning workspace file.');
    } finally {
      setScanning(false);
    }
  };

  const filteredFindings = useMemo(() => {
    if (severityFilter === 'All') {
      return report.findings;
    }
    return report.findings.filter((f) => f.severity === severityFilter);
  }, [report.findings, severityFilter]);

  const activeFinding: SecurityFinding | null = useMemo(() => {
    if (filteredFindings.length === 0) {
      return null;
    }
    return filteredFindings.find((f) => f.id === selectedFindingId) ?? filteredFindings[0];
  }, [filteredFindings, selectedFindingId]);

  const findingsByLine = useMemo(() => {
    const map = new Map<number, SecurityFinding[]>();
    for (const f of report.findings) {
      const list = map.get(f.line) ?? [];
      list.push(f);
      map.set(f.line, list);
    }
    return map;
  }, [report.findings]);

  const severityTextClass = (sev: Severity) => {
    if (sev === 'Critical') return 'text-red-700';
    if (sev === 'High') return 'text-amber-700';
    if (sev === 'Medium') return 'text-sky-700';
    return 'text-slate-600';
  };

  const severityRowBg = (sev: Severity) => {
    if (sev === 'Critical') return 'bg-red-500/15';
    if (sev === 'High') return 'bg-amber-500/15';
    return 'bg-sky-500/15';
  };

  const inspectedLines = useMemo(() => auditedCode.split(/\r?\n/), [auditedCode]);

  return (
    <section aria-labelledby="secure-code-heading" className="space-y-6">
      {/* Project Header */}
      <div className="flex flex-col gap-4 border-b border-slate-200 pb-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold text-sky-700">
            AST Security Workbench · {report.engine ?? 'AST Security Engine'}
          </p>
          <h1
            id="secure-code-heading"
            className="mt-1.5 text-3xl font-bold tracking-tight text-slate-900 text-balance"
          >
            Secure Coding Review &amp; AST Static Analyzer
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 transition-colors hover:bg-slate-50 whitespace-nowrap">
            <Upload className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Upload Source File</span>
            <input
              type="file"
              accept=".py,.js,.ts,.tsx,.jsx,.php"
              onChange={handleSourceFileUpload}
              className="sr-only"
            />
          </label>
          <button
            type="button"
            onClick={() =>
              downloadTextFile(
                'secure_coding_audit_report.md',
                generateAuditMarkdownReport(report, activeTitle),
                'text/markdown;charset=utf-8'
              )
            }
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 transition-colors hover:bg-slate-50 whitespace-nowrap"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Export Audit Report (.md)</span>
          </button>
          <button
            type="button"
            onClick={() =>
              downloadTextFile(
                'secure_code_auditor.py',
                buildSecureCodingPythonAuditor(),
                'text/x-python;charset=utf-8'
              )
            }
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 transition-colors hover:bg-slate-50 whitespace-nowrap"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Download Python Auditor</span>
          </button>
        </div>
      </div>

      {/* Real Workspace Self-Audit Bar */}
      {workspaceFiles.length > 0 && (
        <div className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-800">
            <FolderSearch className="h-4 w-4 text-sky-700 shrink-0" aria-hidden="true" />
            <span>Audit Live Project Source File (Real Workspace Scan):</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="workspace-file-select" className="sr-only">
              Select workspace source file
            </label>
            <select
              id="workspace-file-select"
              value={selectedWorkspacePath}
              onChange={(e) => setSelectedWorkspacePath(e.target.value)}
              className="max-w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-800"
            >
              {workspaceFiles.map((f) => (
                <option key={f.path} value={f.path}>
                  {f.path}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => void handleScanWorkspaceFile()}
              disabled={scanning}
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap"
            >
              <span>Scan File</span>
            </button>
          </div>
        </div>
      )}

      {/* Target Sample Application Strip */}
      <div>
        <p className="mb-2.5 text-xs font-semibold text-slate-600">
          Or Select Vulnerable Benchmark Sample
        </p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {SECURE_CODE_SAMPLES.map((sample) => {
            const isSelected = sample.id === selectedSampleId && activeTitle === sample.title;
            return (
              <button
                key={sample.id}
                type="button"
                onClick={() => handleSelectSample(sample)}
                className={`rounded-xl border p-3.5 text-left transition-colors ${
                  isSelected
                    ? 'border-sky-600 bg-white ring-1 ring-sky-600'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <p className="text-xs font-medium text-slate-500">{sample.framework}</p>
                <p className="mt-1 text-sm font-semibold text-slate-900">{sample.title}</p>
              </button>
            );
          })}
        </div>
      </div>

      {scanError && (
        <div
          role="alert"
          className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs font-medium text-red-800"
        >
          {scanError}
        </div>
      )}

      {report.parseError && (
        <div
          role="status"
          className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs font-medium text-amber-900"
        >
          AST Parse Warning: {report.parseError}
        </div>
      )}

      {/* 4-Column Tabular Posture Strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <p className="text-xs font-medium text-slate-500">Total Findings</p>
          <p className="mt-1 font-mono text-2xl font-bold text-slate-900 tabular-nums">
            {report.summary.totalFindings}
          </p>
          <p className="mt-0.5 text-xs text-slate-500 tabular-nums">
            {report.summary.linesScanned} lines scanned
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <p className="text-xs font-medium text-slate-500">Critical Severity</p>
          <p className="mt-1 font-mono text-2xl font-bold text-red-700 tabular-nums">
            {report.summary.critical}
          </p>
          <p className="mt-0.5 text-xs text-slate-500">Immediate exploit risk</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <p className="text-xs font-medium text-slate-500">High &amp; Medium</p>
          <p className="mt-1 font-mono text-2xl font-bold text-amber-700 tabular-nums">
            {report.summary.high + report.summary.medium}
          </p>
          <p className="mt-0.5 text-xs text-slate-500 tabular-nums">
            {report.summary.high} High · {report.summary.medium} Medium
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <p className="text-xs font-medium text-slate-500">Audit Posture</p>
          <p
            className={`mt-1 text-lg font-bold ${
              report.summary.totalFindings === 0
                ? 'text-emerald-700'
                : report.summary.critical > 0
                  ? 'text-red-700'
                  : 'text-amber-700'
            }`}
          >
            {report.summary.postureLabel}
          </p>
          <p className="mt-1 text-xs text-slate-500 truncate">{activeTitle}</p>
        </div>
      </div>

      {/* Main Split Workbench */}
      <div className="grid gap-6 lg:grid-cols-12">
        {/* Left: Code Viewer / Editor / Diff */}
        <div className="min-w-0 lg:col-span-7">
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
            {/* Code Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-slate-50 px-4 py-3">
              <div
                role="tablist"
                aria-label="Code workbench mode"
                className="inline-flex max-w-full overflow-x-auto rounded-lg border border-slate-200 bg-white p-0.5"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={viewMode === 'inspect'}
                  onClick={() => setViewMode('inspect')}
                  className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                    viewMode === 'inspect'
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Inspect Lines
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={viewMode === 'edit'}
                  onClick={() => setViewMode('edit')}
                  className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                    viewMode === 'edit'
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Edit / Custom Code
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={viewMode === 'diff'}
                  onClick={() => setViewMode('diff')}
                  className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                    viewMode === 'diff'
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Compare Secure Fix
                </button>
              </div>

              <div className="flex items-center gap-2">
                <label htmlFor="audit-lang-select" className="sr-only">
                  Programming Language
                </label>
                <select
                  id="audit-lang-select"
                  value={language}
                  onChange={(e) => setLanguage(e.target.value as CodeLanguage)}
                  className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
                >
                  <option value="python">Python (AST)</option>
                  <option value="javascript">JS / TS (Babel AST)</option>
                  <option value="php">PHP</option>
                </select>
                <button
                  type="button"
                  onClick={handleRunAudit}
                  disabled={scanning}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-sky-700 px-3.5 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-sky-800 disabled:opacity-50 whitespace-nowrap"
                >
                  {scanning ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  ) : (
                    <Play className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  <span>{scanning ? 'Auditing...' : 'Run Security Audit'}</span>
                </button>
              </div>
            </div>

            {/* Mode 1: Inspect Annotated Lines */}
            {viewMode === 'inspect' && (
              <div className="max-h-[540px] overflow-auto bg-slate-950 p-4 font-mono text-xs text-slate-100">
                {inspectedLines.map((lineText, idx) => {
                  const lineNo = idx + 1;
                  const lineFindings = findingsByLine.get(lineNo) ?? [];
                  const topFinding = lineFindings[0];
                  const isFocused = Boolean(
                    activeFinding && lineFindings.some((f) => f.id === activeFinding.id)
                  );

                  return (
                    <div
                      key={`${lineNo}-${lineText.slice(0, 12)}`}
                      className={`group flex items-start gap-3 rounded px-2 py-0.5 ${
                        topFinding ? severityRowBg(topFinding.severity) : ''
                      } ${isFocused ? 'ring-1 ring-sky-400' : ''}`}
                    >
                      <span className="w-7 shrink-0 select-none text-right text-slate-500 tabular-nums">
                        {lineNo}
                      </span>
                      {topFinding ? (
                        <button
                          type="button"
                          onClick={() => setSelectedFindingId(topFinding.id)}
                          className="flex-1 text-left whitespace-pre-wrap break-all text-slate-100 hover:underline"
                        >
                          {lineText || ' '}
                          <span className="ml-3 font-sans text-[11px] font-semibold text-amber-300">
                            [{topFinding.severity.toUpperCase()} · {topFinding.cwe}]
                          </span>
                        </button>
                      ) : (
                        <span className="flex-1 whitespace-pre-wrap break-all text-slate-200">
                          {lineText || ' '}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Mode 2: Editable Custom Code */}
            {viewMode === 'edit' && (
              <div className="p-4">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <label
                    htmlFor="custom-code-editor"
                    className="text-xs font-semibold text-slate-700"
                  >
                    Source Code Buffer (paste or edit code, then click Run Security Audit)
                  </label>
                  <button
                    type="button"
                    onClick={() => handleSelectSample(activeSample)}
                    className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-slate-900"
                  >
                    <RotateCcw className="h-3 w-3" aria-hidden="true" />
                    <span>Reset Sample</span>
                  </button>
                </div>
                <textarea
                  id="custom-code-editor"
                  value={codeInput}
                  onChange={(e) => {
                    setCodeInput(e.target.value);
                    setActiveTitle('Custom Source Audit');
                  }}
                  rows={18}
                  spellCheck={false}
                  className="w-full rounded-lg border border-slate-300 bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </div>
            )}

            {/* Mode 3: Compare Secure Fix */}
            {viewMode === 'diff' && (
              <div className="p-4 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-xs text-slate-600">
                    Comparing vulnerable baseline against hardened implementation for{' '}
                    <span className="font-semibold text-slate-900">{activeSample.title}</span>.
                  </p>
                  <button
                    type="button"
                    onClick={handleApplyCleanFixToEditor}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-emerald-800 whitespace-nowrap"
                  >
                    <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Verify Remediated Code in Scanner</span>
                  </button>
                </div>
                <div className="grid gap-3 md:grid-cols-2">
                  <div className="min-w-0">
                    <p className="mb-1.5 text-xs font-semibold text-red-700">
                      Vulnerable Code
                    </p>
                    <pre className="max-h-[420px] overflow-auto rounded-lg border border-red-200 bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-slate-100">
                      <code>{activeSample.vulnerableCode}</code>
                    </pre>
                  </div>
                  <div className="min-w-0">
                    <p className="mb-1.5 text-xs font-semibold text-emerald-700">
                      Remediated Secure Code
                    </p>
                    <pre className="max-h-[420px] overflow-auto rounded-lg border border-emerald-200 bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-slate-100">
                      <code>{activeSample.remediatedCode}</code>
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Findings List & Remediation Inspector */}
        <aside className="min-w-0 space-y-4 lg:col-span-5">
          {/* Findings Queue */}
          <div className="rounded-xl border border-slate-200 bg-white p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-3">
              <div className="flex items-center gap-2">
                <Code2 className="h-4 w-4 text-slate-500" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-900">
                  Security Findings ({filteredFindings.length})
                </h3>
              </div>

              <div className="inline-flex rounded-lg border border-slate-200 bg-slate-50 p-0.5">
                {(['All', 'Critical', 'High', 'Medium'] as SeverityFilter[]).map((sev) => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSeverityFilter(sev)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
                      severityFilter === sev
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {filteredFindings.length === 0 ? (
              <div className="mt-4 rounded-lg border border-emerald-200 bg-emerald-50/60 p-4">
                <div className="flex items-center gap-2 text-sm font-semibold text-emerald-900">
                  <CheckCircle2 className="h-4 w-4 text-emerald-700" aria-hidden="true" />
                  <span>
                    {report.summary.totalFindings === 0
                      ? 'Clean Baseline — No Vulnerabilities Detected'
                      : `No ${severityFilter} severity findings`}
                  </span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-emerald-800">
                  {report.summary.totalFindings === 0
                    ? 'The scanned source code passed all AST & OWASP Top 10 static checks.'
                    : 'Switch the severity filter to All to review findings in other tiers.'}
                </p>
              </div>
            ) : (
              <div className="mt-3 max-h-60 space-y-2 overflow-y-auto pr-1">
                {filteredFindings.map((finding) => {
                  const isActive = activeFinding?.id === finding.id;
                  return (
                    <button
                      key={finding.id}
                      type="button"
                      onClick={() => setSelectedFindingId(finding.id)}
                      className={`w-full rounded-lg border p-3 text-left transition-colors ${
                        isActive
                          ? 'border-sky-600 bg-sky-50/50'
                          : 'border-slate-200 bg-white hover:border-slate-300'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className={`font-semibold ${severityTextClass(finding.severity)}`}>
                          {finding.severity} · {finding.cwe}
                        </span>
                        <span className="font-mono text-slate-500 tabular-nums">
                          Line {finding.line}
                        </span>
                      </div>
                      <p className="mt-1 text-sm font-semibold text-slate-900">{finding.title}</p>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Selected Finding Remediation Details */}
          {activeFinding && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4">
              <div className="flex items-start justify-between gap-3 border-b border-slate-200 pb-3">
                <div>
                  <p className="text-xs font-medium text-slate-500">
                    {activeFinding.ruleId} · {activeFinding.cwe} · {activeFinding.owasp}
                  </p>
                  <h4 className="mt-1 text-base font-bold text-slate-900">
                    {activeFinding.title}
                  </h4>
                </div>
                <span
                  className={`inline-flex items-center gap-1 text-xs font-bold whitespace-nowrap ${severityTextClass(
                    activeFinding.severity
                  )}`}
                >
                  {activeFinding.severity === 'Critical' ? (
                    <AlertOctagon className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  <span>{activeFinding.severity}</span>
                </span>
              </div>

              <div>
                <p className="text-xs font-semibold text-slate-500">
                  Flagged Line {activeFinding.line}
                </p>
                <pre className="mt-1 overflow-x-auto rounded-lg border border-slate-200 bg-slate-950 px-3 py-2 font-mono text-xs text-red-300">
                  <code>{activeFinding.snippet}</code>
                </pre>
              </div>

              <div>
                <p className="text-xs font-semibold text-slate-900">Vulnerability Impact</p>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">
                  {activeFinding.explanation}
                </p>
              </div>

              <div>
                <p className="text-xs font-semibold text-slate-900">Recommended Remediation</p>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">
                  {activeFinding.remediation}
                </p>
                <pre className="mt-2 overflow-x-auto rounded-lg border border-emerald-200 bg-emerald-50/60 px-3 py-2 font-mono text-xs text-emerald-950">
                  <code>{activeFinding.secureExample}</code>
                </pre>
              </div>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
};
