import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import {
  listWorkspaceSourceFiles,
  readAllowedWorkspaceFile,
  runRealAstSecurityScan,
} from './server/astCodeScanner.ts';
import {
  addHistoryEntry,
  deleteHistoryEntry,
  listHistoryEntries,
} from './server/historyStore.ts';
import {
  analyzeLiveUrl,
  analyzeRawEmailHeaders,
} from './server/phishingLiveAnalyzer.ts';
import type { CodeLanguage } from './src/data/secureCodeSamples.ts';

const PORT = Number(process.env.PORT) || 3000;
const ALLOWED_LANGUAGES = new Set<CodeLanguage>(['python', 'javascript', 'php']);

async function startServer() {
  const app = express();

  // Top-level request deserialization mounted BEFORE all route handlers
  app.use(express.json({ limit: '512kb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'securecode-ast-analyzer' });
  });

  // Project 1: Real Live URL, DNS & TLS Phishing Inspector
  app.post('/api/phishing/inspect-url', async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const urlInput = typeof body.url === 'string' ? body.url.trim() : '';

    if (!urlInput) {
      return res.status(400).json({ error: 'Please provide a URL to inspect.' });
    }
    if (urlInput.length > 2048) {
      return res.status(400).json({ error: 'URL exceeds maximum allowed length (2048 chars).' });
    }

    try {
      const result = await analyzeLiveUrl(urlInput);
      await addHistoryEntry({
        kind: 'url-scan',
        title: result.hostname,
        summary: `${result.verdict} · Risk ${result.riskScore}/100 · ${result.resolvedIps[0] ?? 'No DNS'}`,
        severityOrScore: `${result.riskScore}/100`,
      });
      return res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to inspect URL.';
      return res.status(400).json({ error: message });
    }
  });

  // Project 1: Real RFC-5322 Raw Email Header & Live SPF/DMARC Forensics
  app.post('/api/phishing/inspect-email', async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const rawEmail = typeof body.rawEmail === 'string' ? body.rawEmail : '';

    if (!rawEmail.trim()) {
      return res.status(400).json({ error: 'Please paste raw email headers or .eml content.' });
    }
    if (rawEmail.length > 250_000) {
      return res.status(400).json({ error: 'Email payload exceeds 250 KB limit.' });
    }

    try {
      const result = await analyzeRawEmailHeaders(rawEmail);
      await addHistoryEntry({
        kind: 'email-scan',
        title: result.fromAddress || result.subject,
        summary: `${result.verdict} · SPF:${result.authResults.spf} DKIM:${result.authResults.dkim} DMARC:${result.authResults.dmarc}`,
        severityOrScore: `${result.riskScore}/100`,
      });
      return res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to parse email headers.';
      return res.status(400).json({ error: message });
    }
  });

  // Project 2: Real AST Static Security Code Scanner (JS/TS AST + Python AST + PHP)
  app.post('/api/code-review/scan', async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const code = typeof body.code === 'string' ? body.code : '';
    const rawLang = typeof body.language === 'string' ? body.language : 'python';
    const title = typeof body.title === 'string' && body.title.trim() ? body.title.trim() : 'Custom Source Audit';
    const saveHistory = body.saveHistory !== false;

    if (!ALLOWED_LANGUAGES.has(rawLang as CodeLanguage)) {
      return res.status(400).json({ error: 'Unsupported language. Choose python, javascript, or php.' });
    }
    if (!code.trim()) {
      return res.status(400).json({ error: 'Source code cannot be empty.' });
    }
    if (code.length > 250_000) {
      return res.status(400).json({ error: 'Source code exceeds 250 KB limit.' });
    }

    try {
      const report = await runRealAstSecurityScan(code, rawLang as CodeLanguage);
      if (saveHistory) {
        await addHistoryEntry({
          kind: 'code-audit',
          title,
          summary: `${report.engine} · ${report.summary.totalFindings} findings (${report.summary.postureLabel})`,
          severityOrScore: `${report.summary.totalFindings} findings`,
        });
      }
      return res.json(report);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Static scan failed.';
      return res.status(500).json({ error: message });
    }
  });

  // Project 2: Real Workspace File Listing & Self-Audit
  app.get('/api/code-review/workspace-files', async (_req, res) => {
    try {
      const files = await listWorkspaceSourceFiles();
      return res.json({ files });
    } catch {
      return res.status(500).json({ error: 'Failed to list workspace files.' });
    }
  });

  app.post('/api/code-review/scan-workspace', async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const relPath = typeof body.path === 'string' ? body.path.trim() : '';
    if (!relPath) {
      return res.status(400).json({ error: 'Workspace file path is required.' });
    }

    const loaded = await readAllowedWorkspaceFile(relPath);
    if (!loaded) {
      return res.status(404).json({ error: 'Requested file is not in the workspace allowlist.' });
    }

    const report = await runRealAstSecurityScan(loaded.code, loaded.language);
    await addHistoryEntry({
      kind: 'code-audit',
      title: `Workspace: ${relPath}`,
      summary: `${report.engine} · ${report.summary.totalFindings} findings (${report.summary.postureLabel})`,
      severityOrScore: `${report.summary.totalFindings} findings`,
    });
    return res.json({ path: relPath, code: loaded.code, report });
  });

  // Persistent Audit & Quiz History
  app.get('/api/history', async (_req, res) => {
    const entries = await listHistoryEntries();
    return res.json({ entries });
  });

  app.post('/api/history', async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const kind = body.kind;
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const summary = typeof body.summary === 'string' ? body.summary.trim() : '';
    const severityOrScore = typeof body.severityOrScore === 'string' ? body.severityOrScore.trim() : '';

    if (
      (kind !== 'url-scan' && kind !== 'email-scan' && kind !== 'code-audit' && kind !== 'quiz-attempt') ||
      !title ||
      !summary
    ) {
      return res.status(400).json({ error: 'Invalid history entry payload.' });
    }

    const created = await addHistoryEntry({ kind, title, summary, severityOrScore });
    return res.status(201).json({ entry: created });
  });

  app.delete('/api/history/:id', async (req, res) => {
    const removed = await deleteHistoryEntry(req.params.id);
    if (!removed) {
      return res.status(404).json({ error: 'History entry not found.' });
    }
    return res.json({ ok: true });
  });

  if (process.env.NODE_ENV === 'production') {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SecureCode AST Analyzer listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
