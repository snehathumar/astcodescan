import fs from 'node:fs/promises';
import path from 'node:path';

export interface HistoryEntry {
  id: string;
  kind: 'url-scan' | 'email-scan' | 'code-audit' | 'quiz-attempt';
  title: string;
  summary: string;
  severityOrScore: string;
  createdAt: string;
}

const DATA_DIR = path.resolve(process.cwd(), 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'workbench-history.json');
const MAX_ENTRIES = 40;

async function ensureStore(): Promise<HistoryEntry[]> {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const raw = await fs.readFile(HISTORY_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export async function listHistoryEntries(): Promise<HistoryEntry[]> {
  const entries = await ensureStore();
  return entries.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function addHistoryEntry(
  entry: Omit<HistoryEntry, 'id' | 'createdAt'>
): Promise<HistoryEntry> {
  const existing = await ensureStore();
  const created: HistoryEntry = {
    ...entry,
    id: `hist_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    createdAt: new Date().toISOString(),
  };
  const next = [created, ...existing].slice(0, MAX_ENTRIES);
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(HISTORY_FILE, JSON.stringify(next, null, 2), 'utf-8');
  return created;
}

export async function deleteHistoryEntry(id: string): Promise<boolean> {
  const existing = await ensureStore();
  const next = existing.filter((item) => item.id !== id);
  if (next.length === existing.length) {
    return false;
  }
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(HISTORY_FILE, JSON.stringify(next, null, 2), 'utf-8');
  return true;
}
