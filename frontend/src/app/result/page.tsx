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

// ── Risk Gauge ───────────────────────────────────────────────────────────────
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
    <div className="flex flex-col items-center gap-3">
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
        className={`text-lg font-bold px-4 py-1 rounded-full ${color.bg} ${color.text} border ${color.border}`}
      >
        {verdictText}
      </span>
    </div>
  );
}

// ── Generic Module Card ──────────────────────────────────────────────────────
function ModuleCard({ result, title }: { result?: ModuleResult; title?: string }) {
  const modResult: ModuleResult = result || {
    module: "unknown",
    score: 0,
    confidence: 1,
    findings: [],
    error: null,
  };

  const [open, setOpen] = useState(modResult.score >= 40);

  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-700/40 transition-colors"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span className="text-white font-semibold text-sm">
            {title || moduleLabel(modResult.module)}
          </span>
          {modResult.error && (
            <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-0.5 rounded border border-yellow-500/20">
              ⚠ notice
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="w-24 h-2 bg-slate-700 rounded-full overflow-hidden">
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
          <span className="text-xs text-slate-400 w-8 text-right font-mono">
            {modResult.score}
          </span>
          {open ? (
            <ChevronUp size={14} className="text-slate-400" />
          ) : (
            <ChevronDown size={14} className="text-slate-400" />
          )}
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-3 border-t border-slate-700">
          {modResult.error && (
            <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-300 text-xs">
              Notice: {modResult.error}
            </div>
          )}
          {modResult.findings.length === 0 ? (
            <p className="mt-3 text-slate-400 text-sm flex items-center gap-2">
              <CheckCircle size={14} className="text-green-400" /> No security risks identified
            </p>
          ) : (
            modResult.findings.map((f, i) => (
              <div
                key={f.id || i}
                className={`mt-3 rounded-lg p-4 ${severityColor(f.severity)}`}
              >
                <div className="flex items-start gap-2">
                  <span className="text-sm mt-0.5">{severityIcon(f.severity)}</span>
                  <div>
                    <p className="font-semibold text-sm">{f.title}</p>
                    {f.detail && (
                      <p className="text-xs opacity-80 mt-1 leading-relaxed">
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

// ── Main Result Page Component ───────────────────────────────────────────────
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

        // Store into localStorage history
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
        {/* Skeleton UI */}
        <div className="w-full max-w-2xl px-4 space-y-3 mt-6">
          <div className="h-28 bg-slate-800/80 rounded-2xl animate-pulse" />
          <div className="h-16 bg-slate-800/60 rounded-xl animate-pulse" />
          <div className="h-16 bg-slate-800/60 rounded-xl animate-pulse" />
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
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Top Navigation */}
      <nav className="flex items-center gap-3 px-6 py-4 border-b border-slate-800 sticky top-0 bg-slate-950/90 backdrop-blur z-10">
        <Shield className="text-blue-400" size={20} />
        <span className="font-bold text-white tracking-tight">TrustLens</span>

        {/* Live / Simulated Pill */}
        <div className="ml-2 sm:ml-4 flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700">
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

        <div className="ml-auto flex items-center gap-3">
          <LanguageSelector />
          <Link
            href="/"
            className="flex items-center gap-1.5 text-slate-400 hover:text-white text-sm transition-colors"
          >
            <ArrowLeft size={14} /> {t("newScan")}
          </Link>
        </div>
      </nav>

      <div className="max-w-3xl mx-auto px-4 py-10 space-y-8">
        {/* Verdict Hero Card */}
        <div className={`rounded-2xl border p-6 sm:p-8 ${color.bg} ${color.border}`}>
          <div className="flex flex-col sm:flex-row items-center gap-6 sm:gap-8">
            <RiskGauge
              risk={result.risk}
              verdict={result.verdict}
              verdictText={tVerdict(result.verdict)}
            />
            <div className="flex-1 text-center sm:text-left">
              <p className="text-xs font-mono text-slate-400 mb-2 break-all">{result.url}</p>
              <h1 className={`text-2xl sm:text-3xl font-black mb-3 ${color.text}`}>
                {headline}
              </h1>
              <p className="text-slate-300 text-sm leading-relaxed">
                {result.recommended_action}
              </p>
            </div>
          </div>
        </div>

        {/* Top plain-language reasons */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
          <h2 className="text-white font-semibold mb-3 flex items-center gap-2">
            <AlertTriangle size={15} className="text-yellow-400" /> {t("whyVerdict")}
          </h2>
          {result.reasons && result.reasons.length > 0 ? (
            <ul className="space-y-2">
              {result.reasons.map((r, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-slate-300">
                  <span className="text-slate-500 font-mono text-xs w-4 mt-0.5">{i + 1}.</span>
                  <span>{getReasonTitle(r)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-slate-400 text-sm">No critical risk triggers flagged for this site.</p>
          )}
        </div>

        {/* Detailed Module Breakdown */}
        <div>
          <h2 className="text-white font-semibold text-lg mb-4">{t("detailedInspection")}</h2>
          <div className="space-y-4">
            {result.modules?.threat && (
              <ModuleCard result={result.modules.threat} title={t("threatModule")} />
            )}
            {result.modules?.websec && (
              <ModuleCard result={result.modules.websec} title={t("websecModule")} />
            )}
            {/* Certificate gets dedicated deep chain panel */}
            <CertPanel
              findings={certModule.findings || []}
              score={certModule.score || 0}
            />
            {result.modules?.community && (
              <ModuleCard result={result.modules.community} title={t("communityModule")} />
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap gap-3 pt-2">
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2.5 bg-slate-800 border border-slate-700 text-slate-300 rounded-lg text-sm hover:bg-slate-700 transition-colors"
          >
            <ExternalLink size={14} /> {t("openSite")}
          </a>
          <Link
            href={`/report?url=${encodeURIComponent(result.url)}`}
            className="flex items-center gap-2 px-4 py-2.5 bg-red-900/40 border border-red-700/50 text-red-300 rounded-lg text-sm hover:bg-red-900/60 transition-colors"
          >
            <Flag size={14} /> {t("reportSite")}
          </Link>
          <Link
            href="/"
            className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500 transition-colors"
          >
            <Shield size={14} /> {t("scanAnother")}
          </Link>
        </div>

        <p className="text-xs text-slate-600 text-center">
          Scanned at {result.scanned_at ? new Date(result.scanned_at).toLocaleString() : "Just now"} ·
          Results are probabilistic risk signals, not legal or CA proof.
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
