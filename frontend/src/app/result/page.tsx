"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield, ArrowLeft, AlertTriangle, CheckCircle,
  ChevronDown, ChevronUp, ExternalLink, Flag
} from "lucide-react";
import { ScanResponse, ModuleResult, Verdict } from "@/lib/types";
import { CertPanel } from "@/components/CertPanel";
import { MOCK_SCAN_RESPONSE, MOCK_SAFE_RESPONSE } from "@/lib/mock-data";
import { verdictColor, severityColor, severityIcon, moduleLabel } from "@/lib/utils";

// ── Risk Gauge ───────────────────────────────────────────────────────────────
function RiskGauge({ risk, verdict }: { risk: number; verdict: Verdict }) {
  const color = verdictColor(verdict);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (risk / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="#1e293b" strokeWidth="12" />
          <circle
            cx="60" cy="60" r="54" fill="none"
            stroke={color.ring} strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 1s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-black text-white">{risk}</span>
          <span className="text-xs text-slate-400">/ 100</span>
        </div>
      </div>
      <span className={`text-lg font-bold px-4 py-1 rounded-full ${color.bg} ${color.text} border ${color.border}`}>
        {verdict}
      </span>
    </div>
  );
}

// ── Module Card ──────────────────────────────────────────────────────────────
function ModuleCard({ result }: { result: ModuleResult }) {
  const [open, setOpen] = useState(result.score >= 50);

  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-700/40 transition-colors"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span className="text-white font-semibold text-sm">{moduleLabel(result.module)}</span>
          {result.error && <span className="text-xs text-yellow-400">⚠ error</span>}
        </div>
        <div className="flex items-center gap-3">
          <div className="w-24 h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${result.score}%`,
                backgroundColor: result.score >= 70 ? "#ef4444" : result.score >= 40 ? "#eab308" : "#22c55e",
              }}
            />
          </div>
          <span className="text-xs text-slate-400 w-8 text-right">{result.score}</span>
          {open ? <ChevronUp size={14} className="text-slate-400" /> : <ChevronDown size={14} className="text-slate-400" />}
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-3 border-t border-slate-700">
          {result.error && (
            <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-300 text-xs">
              Module error: {result.error}
            </div>
          )}
          {result.findings.length === 0 ? (
            <p className="mt-3 text-slate-400 text-sm flex items-center gap-2">
              <CheckCircle size={14} className="text-green-400" /> No issues found
            </p>
          ) : (
            result.findings.map((f) => (
              <div key={f.id} className={`mt-3 rounded-lg p-4 ${severityColor(f.severity)}`}>
                <div className="flex items-start gap-2">
                  <span className="text-sm mt-0.5">{severityIcon(f.severity)}</span>
                  <div>
                    <p className="font-semibold text-sm">{f.title}</p>
                    <p className="text-xs opacity-80 mt-1 leading-relaxed">{f.detail}</p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Result Page ─────────────────────────────────────────────────────────
function ResultContent() {
  const params = useSearchParams();
  const router = useRouter();
  const rawUrl = params.get("url") ?? "";
  const useMock = params.get("mock") === "1";

  const [result, setResult] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!rawUrl) { router.replace("/"); return; }

    // Use mock data until real API is ready (H16-24)
    const timer = setTimeout(() => {
      if (useMock || rawUrl.includes("sbi-login")) {
        setResult(MOCK_SCAN_RESPONSE);
      } else {
        setResult(MOCK_SAFE_RESPONSE);
      }
      setLoading(false);
    }, 1800); // simulate network

    return () => clearTimeout(timer);
  }, [rawUrl, useMock, router]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center gap-6">
        <div className="relative w-20 h-20">
          <div className="absolute inset-0 rounded-full border-4 border-blue-500/30 border-t-blue-500 animate-spin" />
          <Shield className="absolute inset-0 m-auto text-blue-400" size={28} />
        </div>
        <div className="text-center">
          <p className="text-white font-semibold">Scanning…</p>
          <p className="text-slate-400 text-sm mt-1 max-w-xs break-all">{rawUrl}</p>
        </div>
        {/* Skeleton */}
        <div className="w-full max-w-2xl px-4 space-y-3 mt-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-14 bg-slate-800 rounded-xl animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (err || !result) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center space-y-4">
          <AlertTriangle size={40} className="mx-auto text-yellow-400" />
          <p className="text-white font-semibold">Scan failed</p>
          <p className="text-slate-400 text-sm">{err || "Unknown error"}</p>
          <Link href="/" className="inline-block mt-4 text-blue-400 underline">← Try again</Link>
        </div>
      </div>
    );
  }

  const color = verdictColor(result.verdict);

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Nav */}
      <nav className="flex items-center gap-3 px-6 py-4 border-b border-slate-800 sticky top-0 bg-slate-950/90 backdrop-blur z-10">
        <Shield className="text-blue-400" size={20} />
        <span className="font-bold text-white">TrustLens</span>
        <Link href="/" className="ml-auto flex items-center gap-1.5 text-slate-400 hover:text-white text-sm transition-colors">
          <ArrowLeft size={14} /> New scan
        </Link>
      </nav>

      <div className="max-w-3xl mx-auto px-4 py-10 space-y-8">

        {/* Verdict header */}
        <div className={`rounded-2xl border p-6 ${color.bg} ${color.border}`}>
          <div className="flex flex-col sm:flex-row items-center gap-6">
            <RiskGauge risk={result.risk} verdict={result.verdict} />
            <div className="flex-1 text-center sm:text-left">
              <p className="text-xs text-slate-400 mb-1 break-all">{result.url}</p>
              <h1 className={`text-2xl font-black mb-3 ${color.text}`}>
                {result.verdict === "Safe" ? "✅ This site looks safe" :
                  result.verdict === "Suspicious" ? "⚠️ Proceed with caution" :
                    "🚨 This site is dangerous"}
              </h1>
              <p className="text-slate-300 text-sm leading-relaxed">{result.recommended_action}</p>
            </div>
          </div>
        </div>

        {/* Top reasons */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
          <h2 className="text-white font-semibold mb-3 flex items-center gap-2">
            <AlertTriangle size={15} className="text-yellow-400" /> Why this verdict
          </h2>
          <ul className="space-y-2">
            {result.reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="text-slate-500 mt-0.5 font-mono text-xs w-4">{i + 1}.</span>
                {r}
              </li>
            ))}
          </ul>
        </div>

        {/* Module breakdown */}
        <div>
          <h2 className="text-white font-semibold mb-3">Detailed Analysis</h2>
          <div className="space-y-3">
            <ModuleCard result={result.modules.threat} />
            <ModuleCard result={result.modules.websec} />
            {/* Certificate gets its own rich panel */}
            <CertPanel findings={result.modules.cert.findings} score={result.modules.cert.score} />
            <ModuleCard result={result.modules.community} />
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-wrap gap-3">
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2.5 bg-slate-800 border border-slate-700 text-slate-300 rounded-lg text-sm hover:bg-slate-700 transition-colors"
          >
            <ExternalLink size={14} /> Open site
          </a>
          <Link
            href={`/report?url=${encodeURIComponent(result.url)}`}
            className="flex items-center gap-2 px-4 py-2.5 bg-red-900/40 border border-red-700/50 text-red-300 rounded-lg text-sm hover:bg-red-900/60 transition-colors"
          >
            <Flag size={14} /> Report this site
          </Link>
          <Link
            href="/"
            className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500 transition-colors"
          >
            <Shield size={14} /> Scan another URL
          </Link>
        </div>

        <p className="text-xs text-slate-600 text-center">
          Scanned at {result.scanned_at ? new Date(result.scanned_at).toLocaleString() : "—"} ·
          Results are risk signals, not legal proof
        </p>
      </div>
    </main>
  );
}

export default function ResultPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="animate-spin w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full" />
      </div>
    }>
      <ResultContent />
    </Suspense>
  );
}
