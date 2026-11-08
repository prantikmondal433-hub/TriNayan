// Shared contract from backend/app/schemas.py

export type Severity = "low" | "medium" | "high" | "critical";
export type Verdict = "Safe" | "Suspicious" | "Dangerous";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
}

export interface ModuleResult {
  module: string;
  score: number;       // 0–100, higher = worse
  confidence: number;  // 0–1
  findings: Finding[];
  error: string | null;
}

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  url: string;
  risk: number;         // 0–100
  verdict: Verdict;
  reasons: string[];    // top 3–5 plain-language reasons
  recommended_action: string;
  modules: {
    threat: ModuleResult;
    websec: ModuleResult;
    cert: ModuleResult;
    community: ModuleResult;
  };
  scan_id?: string;
  scanned_at?: string;
}

export interface ReportRequest {
  url: string;
  category: string;
  comment: string;
}
