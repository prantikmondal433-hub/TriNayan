import { ScanRequest, ScanResponse, ReportRequest } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function scanUrl(url: string): Promise<ScanResponse> {
  const body: ScanRequest = { url };
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Scan failed (${res.status}): ${err}`);
  }
  return res.json();
}

export async function submitReport(report: ReportRequest): Promise<void> {
  const res = await fetch(`${API_BASE}/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(report),
  });
  if (!res.ok) {
    throw new Error(`Report failed (${res.status})`);
  }
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`, { method: "GET" });
    return res.ok;
  } catch {
    return false;
  }
}

// ── History (localStorage) ───────────────────────────────────────────────────

export interface HistoryEntry {
  url: string;
  risk: number;
  verdict: string;
  scanned_at: string;
}

const HISTORY_KEY = "trustlens_history";
const MAX_HISTORY = 20;

export function getHistory(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

export function addToHistory(entry: HistoryEntry): void {
  if (typeof window === "undefined") return;
  const history = getHistory();
  const filtered = history.filter((h) => h.url !== entry.url);
  filtered.unshift(entry);
  localStorage.setItem(
    HISTORY_KEY,
    JSON.stringify(filtered.slice(0, MAX_HISTORY))
  );
}

export function clearHistory(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(HISTORY_KEY);
}
