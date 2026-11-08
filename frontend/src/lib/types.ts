// Shared contract from backend/app/schemas.py

export type Severity = "low" | "medium" | "high" | "critical";
export type ModuleName = "threat" | "websec" | "cert" | "community";
export type Verdict = "Safe" | "Suspicious" | "Dangerous";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
}

export interface ModuleResult {
  module: ModuleName | string;
  score: number;       // 0–100, higher = worse
  confidence: number;  // 0–1
  findings: Finding[];
  error: string | null;
}

export interface Reason {
  module?: ModuleName | string;
  id?: string;
  severity?: Severity;
  title: string;
}

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  url: string;
  risk: number;         // 0–100
  verdict: Verdict;
  reasons: (string | Reason)[];    // supports both string and Reason objects
  recommended_action: string;
  modules: {
    threat: ModuleResult;
    websec: ModuleResult;
    cert: ModuleResult;
    community: ModuleResult;
    [key: string]: ModuleResult;
  };
  scan_id?: string;
  scanned_at?: string;
}

export interface ReportRequest {
  url: string;
  category: string;
  comment: string;
}
