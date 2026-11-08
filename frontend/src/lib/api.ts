import { ScanRequest, ScanResponse, ReportRequest } from "./types";
import { MOCK_SCAN_RESPONSE, MOCK_SAFE_RESPONSE } from "./mock-data";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function scanUrl(url: string): Promise<{ data: ScanResponse; isLive: boolean }> {
  const body: ScanRequest = { url };
  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout ? AbortSignal.timeout(18000) : undefined,
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`API returned ${res.status}: ${errText}`);
    }
    const data: ScanResponse = await res.json();
    return { data, isLive: true };
  } catch (err) {
    console.warn("Real API call failed, falling back to realistic simulation:", err);
    // Simulation fallback so hackathon demo never fails even if backend is offline
    await new Promise((r) => setTimeout(r, 1200));
    const isSuspicious =
      url.includes("sbi") ||
      url.includes("login") ||
      url.includes("verify") ||
      url.includes("secure") ||
      url.includes("xyz");

    const fallbackData: ScanResponse = isSuspicious
      ? { ...MOCK_SCAN_RESPONSE, url }
      : { ...MOCK_SAFE_RESPONSE, url };

    return { data: fallbackData, isLive: false };
  }
}

export async function submitReport(report: ReportRequest): Promise<{ success: boolean; isLive: boolean }> {
  try {
    const res = await fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report),
      signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined,
    });
    if (!res.ok) {
      throw new Error(`Report failed (${res.status})`);
    }
    return { success: true, isLive: true };
  } catch (err) {
    console.warn("Report endpoint not yet available, simulated success:", err);
    await new Promise((r) => setTimeout(r, 800));
    return { success: true, isLive: false };
  }
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`, {
      method: "GET",
      signal: AbortSignal.timeout ? AbortSignal.timeout(3000) : undefined,
    });
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
const MAX_HISTORY = 10;

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
  const filtered = history.filter((h) => h.url.toLowerCase() !== entry.url.toLowerCase());
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
