"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  ArrowLeft,
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Flag,
  Server,
  Zap,
} from "lucide-react";
import { ScanResponse, ModuleResult, Verdict } from "@/lib/types";
import { scanUrl, addToHistory } from "@/lib/api";
import {
  verdictColor,
  severityColor,
  severityIcon,
  moduleLabel,
  getReasonTitle,
} from "@/lib/utils";
import { CertPanel } from "@/components/CertPanel";
import { useLanguage } from "@/context/LanguageContext";
import { LanguageSelector } from "@/components/LanguageSelector";

// ── Circular Risk Gauge ───────────────────────────────────────────────────────
function RiskGauge({
  risk,
  verdict,
  verdictText,
}: {
  risk: number;
  verdict: Verdict;
  verdictText: string;
}) {
  const color = verdictColor(verdict);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (Math.min(100, Math.max(0, risk)) / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-3 shrink-0">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="#1e293b" strokeWidth="12" />
          <circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke={color.ring}
            strokeWidth="12"
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
      <span
        className={`text-sm font-bold px-4 py-1 rounded-full ${color.bg} ${color.text} border ${color.border}`}
      >
        {verdictText}
      </span>
    </div>
  );
}

// ── Collapsible Module Card ──────────────────────────────────────────────────
function ModuleCard({ result, title }: { result?: ModuleResult; title?: string }) {
  const modResult: ModuleResult = result || {
    module: "unknown",
    score: 0,
    confidence: 1,
    findings: [],
    error: null,
  };

  const [open, setOpen] = useState(modResult.score >= 40 || modResult.findings.length > 0);

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-800/60 transition-colors text-left"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span className="text-slate-100 font-semibold text-sm">
            {title || moduleLabel(modResult.module)}
          </span>
          {modResult.error && (
            <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-0.5 rounded border border-yellow-500/20">
              Notice
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="w-24 h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${Math.min(100, Math.max(0, modResult.score))}%`,
                backgroundColor:
                  modResult.score >= 70
                    ? "#ef4444"
                    : modResult.score >= 40
                    ? "#eab308"
                    : "#22c55e",
              }}
            />
          </div>
          <span className="text-xs font-mono text-slate-300 w-8 text-right">
            {modResult.score}
          </span>
          {open ? (
            <ChevronUp size={16} className="text-slate-400" />
          ) : (
            <ChevronDown size={16} className="text-slate-400" />
          )}
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-2.5 border-t border-slate-800 pt-3">
          {modResult.error && (
            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-300 text-xs">
              Notice: {modResult.error}
            </div>
          )}
          {modResult.findings.length === 0 ? (
            <p className="text-slate-400 text-xs flex items-center gap-2 py-1">
              <CheckCircle size={14} className="text-green-400" /> No security risks identified
            </p>
          ) : (
            modResult.findings.map((f, i) => (
              <div
                key={f.id || i}
                className={`rounded-lg p-3 text-xs ${severityColor(f.severity)}`}
              >
                <div className="flex items-start gap-2">
                  <span className="text-sm shrink-0">{severityIcon(f.severity)}</span>
                  <div className="space-y-1">
                    <p className="font-semibold text-slate-100">{f.title}</p>
                    {f.detail && (
                      <p className="text-slate-300 opacity-90 leading-relaxed">
                        {f.detail}
                      </p>
                    )}
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

// ── Main Page Content ────────────────────────────────────────────────────────
function ResultContent() {
  const params = useSearchParams();
  const router = useRouter();
  const rawUrl = params.get("url") ?? "";
  const { t, tVerdict } = useLanguage();

  const [result, setResult] = useState<ScanResponse | null>(null);
  const [isLive, setIsLive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!rawUrl) {
      router.replace("/");
      return;
    }

    let isMounted = true;
    setLoading(true);
    setErr("");

    scanUrl(rawUrl)
      .then(({ data, isLive: liveStatus }) => {
        if (!isMounted) return;
        setResult(data);
        setIsLive(liveStatus);
        setLoading(false);

        addToHistory({
          url: data.url,
          risk: data.risk,
          verdict: data.verdict,
          scanned_at: data.scanned_at || new Date().toISOString(),
        });
      })
      .catch((error) => {
        if (!isMounted) return;
        setErr(error.message || "Failed to scan URL");
        setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [rawUrl, router]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center gap-6 px-4">
        <div className="relative w-20 h-20">
          <div className="absolute inset-0 rounded-full border-4 border-blue-500/30 border-t-blue-500 animate-spin" />
          <Shield className="absolute inset-0 m-auto text-blue-400" size={28} />
        </div>
        <div className="text-center">
          <p className="text-white font-semibold text-lg">Analyzing website trust...</p>
          <p className="text-slate-400 text-sm mt-1 max-w-md break-all font-mono">
            {rawUrl}
          </p>
          <p className="text-slate-500 text-xs mt-3">
            Examining SSL certificates, CT logs, brand signals, and security headers
          </p>
        </div>
        <div className="w-full max-w-2xl px-4 space-y-3 mt-6">
          <div className="h-28 bg-slate-900 rounded-2xl animate-pulse" />
          <div className="h-16 bg-slate-900 rounded-xl animate-pulse" />
          <div className="h-16 bg-slate-900 rounded-xl animate-pulse" />
        </div>
      </div>
    );
  }

  if (err || !result) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4">
        <div className="text-center space-y-4 max-w-md">
          <AlertTriangle size={48} className="mx-auto text-yellow-400" />
          <p className="text-white font-bold text-xl">Scan Unsuccessful</p>
          <p className="text-slate-400 text-sm">{err || "An unexpected error occurred."}</p>
          <Link
            href="/"
            className="inline-block mt-4 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg text-sm"
          >
            ← Try another scan
          </Link>
        </div>
      </div>
    );
  }

  const color = verdictColor(result.verdict);
  const certModule = result.modules?.cert || {
    module: "cert",
    score: 0,
    confidence: 1,
    findings: [],
    error: null,
  };

  const headline =
    result.verdict === "Safe"
      ? t("safeHeadline")
      : result.verdict === "Suspicious"
      ? t("suspiciousHeadline")
      : t("dangerousHeadline");

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      {/* Top Navigation */}
      <nav className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/95 sticky top-0 z-20 backdrop-blur">
        <div className="flex items-center gap-3">
          <Shield className="text-blue-400" size={22} />
          <span className="font-bold text-white text-lg tracking-tight">TrustLens</span>

          {/* Live / Simulated Connectivity Badge */}
          <div className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
            {isLive ? (
              <>
                <Zap size={12} className="text-green-400 fill-green-400" />
                <span className="text-green-300 font-medium hidden sm:inline">
                  {t("liveConnected")}
                </span>
              </>
            ) : (
              <>
                <Server size={12} className="text-yellow-400" />
                <span className="text-yellow-300 font-medium hidden sm:inline">
                  {t("demoMode")}
                </span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          <LanguageSelector />
          <Link
            href="/"
            className="flex items-center gap-1.5 text-slate-300 hover:text-white text-xs sm:text-sm transition-colors"
          >
            <ArrowLeft size={14} /> {t("newScan")}
          </Link>
        </div>
      </nav>

      <div className="max-w-3xl mx-auto px-4 py-8 space-y-6">
        {/* Verdict Hero Card */}
        <div className={`rounded-2xl border p-6 sm:p-7 ${color.bg} ${color.border} shadow-lg`}>
          <div className="flex flex-col sm:flex-row items-center gap-6">
            <RiskGauge
              risk={result.risk}
              verdict={result.verdict}
              verdictText={tVerdict(result.verdict)}
            />
            <div className="flex-1 text-center sm:text-left space-y-2">
              <p className="text-xs font-mono text-slate-400 break-all">{result.url}</p>
              <h1 className={`text-2xl sm:text-3xl font-extrabold ${color.text}`}>
                {headline}
              </h1>
              <p className="text-slate-300 text-sm leading-relaxed">
                {result.recommended_action}
              </p>
            </div>
          </div>
        </div>

        {/* Top Plain-Language Reasons */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h2 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
            <AlertTriangle size={15} className="text-yellow-400" /> {t("whyVerdict")}
          </h2>
          {result.reasons && result.reasons.length > 0 ? (
            <ul className="space-y-2">
              {result.reasons.map((r, i) => (
                <li key={i} className="flex items-start gap-2.5 text-xs sm:text-sm text-slate-300">
                  <span className="text-slate-500 font-mono text-xs w-4 mt-0.5">{i + 1}.</span>
                  <span>{getReasonTitle(r)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-slate-400 text-xs">No critical risk triggers flagged for this site.</p>
          )}
        </div>

        {/* Detailed Module Breakdown */}
        <div className="space-y-3">
          <h2 className="text-white font-semibold text-sm">{t("detailedInspection")}</h2>
          {result.modules?.threat && (
            <ModuleCard result={result.modules.threat} title={t("threatModule")} />
          )}
          {result.modules?.websec && (
            <ModuleCard result={result.modules.websec} title={t("websecModule")} />
          )}
          {/* Certificate Deep Inspection Panel */}
          <CertPanel
            findings={certModule.findings || []}
            score={certModule.score || 0}
          />
          {result.modules?.community && (
            <ModuleCard result={result.modules.community} title={t("communityModule")} />
          )}
        </div>

        {/* Action Controls Bar */}
        <div className="flex flex-wrap items-center gap-3 pt-3">
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-lg text-xs sm:text-sm transition-colors"
          >
            <ExternalLink size={14} /> {t("openSite")}
          </a>
          <Link
            href={`/report?url=${encodeURIComponent(result.url)}`}
            className="flex items-center gap-2 px-4 py-2 bg-red-950/60 hover:bg-red-900/60 border border-red-800/60 text-red-300 rounded-lg text-xs sm:text-sm transition-colors"
          >
            <Flag size={14} /> {t("reportSite")}
          </Link>
          <Link
            href="/"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg text-xs sm:text-sm transition-colors ml-auto"
          >
            <Shield size={14} /> {t("scanAnother")}
          </Link>
        </div>

        <p className="text-xs text-slate-600 text-center pt-2">
          Scanned at {result.scanned_at ? new Date(result.scanned_at).toLocaleString() : "Just now"} ·
          Results represent probabilistic risk signals · Passive scanning only
        </p>
      </div>
    </main>
  );
}

export default function ResultPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-slate-950 flex items-center justify-center">
          <div className="animate-spin w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full" />
        </div>
      }
    >
      <ResultContent />
    </Suspense>
  );
}
