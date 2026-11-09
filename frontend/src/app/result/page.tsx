"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import {
  Globe,
  ExternalLink,
  Flag,
  RotateCcw,
  AlertTriangle,
  CheckCircle,
  Copy,
  Check,
  Zap,
  Server,
} from "lucide-react";
import { ScanResponse, ModuleResult, Verdict } from "@/lib/types";
import { scanUrl, addToHistory } from "@/lib/api";
import {
  verdictColor,
  severityColor,
  severityIcon,
  getReasonTitle,
} from "@/lib/utils";
import { CertPanel } from "@/components/CertPanel";
import { useLanguage } from "@/context/LanguageContext";
import { LanguageSelector } from "@/components/LanguageSelector";
import { SplashLoader } from "@/components/SplashLoader";

// ── Circular Risk Gauge (0-100 Animated on Mount) ───────────────────────────
function AnimatedRiskGauge({
  targetRisk,
  verdict,
  verdictText,
}: {
  targetRisk: number;
  verdict: Verdict;
  verdictText: string;
}) {
  const [animatedRisk, setAnimatedRisk] = useState(0);

  useEffect(() => {
    // Animate from 0 to target score on mount
    const timer = setTimeout(() => {
      setAnimatedRisk(Math.min(100, Math.max(0, targetRisk)));
    }, 60);
    return () => clearTimeout(timer);
  }, [targetRisk]);

  const color = verdictColor(verdict);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (animatedRisk / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-3 shrink-0">
      <div
        className="relative w-36 h-36 sm:w-44 sm:h-44"
        role="progressbar"
        aria-valuenow={targetRisk}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Risk score: ${targetRisk} out of 100, status: ${verdictText}`}
      >
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          {/* Background Track */}
          <circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke="#131B38"
            strokeWidth="10"
          />
          {/* Animated Arc */}
          <circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke={color.ring}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{
              transition: "stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)",
              filter: `drop-shadow(0 0 12px ${color.ring}77)`,
            }}
          />
        </svg>

        {/* Center Score */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-4xl sm:text-5xl font-black text-[var(--tn-text)] tracking-tight">
            {targetRisk}
          </span>
          <span className="text-xs text-[var(--tn-text-secondary)] font-mono mt-0.5">/ 100</span>
        </div>
      </div>

      {/* Verdict Pill Badge */}
      <span
        className={`text-xs sm:text-sm font-bold px-5 py-1 rounded-full border shadow-sm tracking-wide ${color.bg} ${color.border} ${color.text}`}
      >
        {verdictText} ({targetRisk}) →
      </span>
    </div>
  );
}

// ── Generic Category Inspection Card ─────────────────────────────────────────
function CategoryCard({
  icon,
  title,
  subtitle,
  result,
}: {
  icon: string;
  title: string;
  subtitle: string;
  result?: ModuleResult;
}) {
  const { t } = useLanguage();
  const [expanded, setExpanded] = useState(false);

  const modResult: ModuleResult | null = result || null;
  const score = modResult?.score ?? 0;
  const findings = modResult?.findings ?? [];

  const isSafe = score <= 30;
  const isDanger = score >= 70;

  return (
    <article className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-5 sm:p-6 shadow-xl flex flex-col justify-between transition-all hover:border-white hover:shadow-2xl hover:shadow-blue-500/10">
      <div>
        {/* Header Pill & Sub-Score Bar + Status Chip */}
        <div className="flex items-center justify-between gap-3 mb-3">
          <div className="border border-white/70 rounded-full px-3.5 py-1 text-[var(--tn-text)] font-bold text-xs sm:text-sm flex items-center gap-2 bg-[var(--tn-bg)]/80 shadow-inner">
            <span aria-hidden="true">{icon}</span>
            <h2>{title}</h2>
          </div>

          <div className="flex items-center gap-2.5">
            <div
              className="w-16 sm:w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden"
              role="progressbar"
              aria-valuenow={score}
              aria-valuemin={0}
              aria-valuemax={100}
            >
              <div
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{
                  width: `${Math.min(100, Math.max(0, score))}%`,
                  backgroundColor: isDanger ? "var(--tn-danger)" : !isSafe ? "var(--tn-warning)" : "var(--tn-safe)",
                }}
              />
            </div>
            <span
              className={`text-xs font-bold font-mono px-2 py-0.5 rounded-full ${
                isDanger
                  ? "bg-red-500/20 text-red-300 border border-red-500/40"
                  : !isSafe
                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                  : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
              }`}
            >
              {score}
            </span>
          </div>
        </div>

        {/* Subtitle */}
        <p className="text-[var(--tn-text-secondary)] text-xs leading-relaxed mb-4">{subtitle}</p>

        {/* Findings container */}
        <div className="space-y-2 mb-3">
          {!modResult ? (
            <p className="text-xs text-[var(--tn-text-muted)] italic p-3 bg-white/5 rounded-xl border border-white/10">
              {t("noData")}
            </p>
          ) : modResult.error ? (
            <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-300 text-xs">
              Notice: {modResult.error}
            </div>
          ) : findings.length === 0 ? (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/25 rounded-xl text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle size={15} className="shrink-0 text-emerald-400" aria-hidden="true" />
              <span>No risk flags or suspicious anomalies detected.</span>
            </div>
          ) : (
            (expanded ? findings : findings.slice(0, 2)).map((f, i) => (
              <div key={f.id || i} className={`rounded-xl p-3 text-xs ${severityColor(f.severity)}`}>
                <div className="flex items-start gap-2">
                  <span className="text-sm shrink-0" aria-hidden="true">{severityIcon(f.severity)}</span>
                  <div className="space-y-0.5">
                    <p className="font-semibold text-slate-100">{f.title}</p>
                    {f.detail && (
                      <p className="text-slate-300 opacity-90 leading-relaxed text-[11px]">{f.detail}</p>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {findings.length > 2 && (
        <button
          type="button"
          onClick={() => setExpanded((o) => !o)}
          className="text-[11px] text-blue-400 hover:text-blue-300 pt-2 flex items-center gap-1 font-medium transition-colors focus-ring rounded"
        >
          {expanded ? "Show less" : `View all (${findings.length}) findings`}
        </button>
      )}
    </article>
  );
}

// ── Result Content Component ─────────────────────────────────────────────────
function ResultContent() {
  const params = useSearchParams();
  const router = useRouter();
  const rawUrl = params.get("url") ?? "";
  const { t, tVerdict } = useLanguage();

  const [result, setResult] = useState<ScanResponse | null>(null);
  const [isLive, setIsLive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!rawUrl) {
      router.replace("/");
      return;
    }

    let isMounted = true;

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

  function handleCopyUrl() {
    if (!result?.url) return;
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  // 1. Loading State (Shows beating logo loader)
  if (loading) {
    return <SplashLoader message={t("analyzing")} subMessage={rawUrl} />;
  }

  // 2. Error State
  if (err) {
    return (
      <main className="min-h-screen bg-[var(--tn-bg)] text-[var(--tn-text)] flex flex-col font-sans">
        <header className="sticky top-0 z-40 bg-[var(--tn-bg)]/85 backdrop-blur-md border-b border-[var(--tn-border)]">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3.5 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-3 focus-ring rounded-lg group">
              <div className="relative w-8 h-9 shrink-0">
                <Image src="/logo.png" alt="TriNayan" fill sizes="36px" className="object-contain" />
              </div>
              <span className="font-extrabold text-[var(--tn-text)] text-xl tracking-tight">TriNayan</span>
            </Link>
            <LanguageSelector />
          </div>
        </header>

        <div className="flex-1 flex items-center justify-center px-4 py-12">
          <div className="text-center space-y-4 max-w-md bg-[var(--tn-surface)] border border-white/60 rounded-[var(--tn-radius-card)] p-8 shadow-2xl">
            <AlertTriangle size={48} className="mx-auto text-amber-400" />
            <h1 className="text-xl font-bold text-[var(--tn-text)]">Scan Unsuccessful</h1>
            <p className="text-xs sm:text-sm text-[var(--tn-text-secondary)]">{err}</p>
            <Link
              href="/"
              className="inline-flex items-center gap-2 mt-4 px-6 py-2.5 rounded-full bg-gradient-to-r from-blue-600 to-sky-600 text-white font-semibold text-xs sm:text-sm shadow-md focus-ring"
            >
              <RotateCcw size={14} /> {t("newScan")}
            </Link>
          </div>
        </div>
      </main>
    );
  }

  // 3. Empty State
  if (!result) {
    return (
      <main className="min-h-screen bg-[var(--tn-bg)] text-[var(--tn-text)] flex items-center justify-center p-4">
        <div className="text-center space-y-4">
          <p className="text-[var(--tn-text-secondary)]">{t("noData")}</p>
          <Link href="/" className="px-5 py-2 rounded-full border border-white/40 text-xs">
            {t("home")}
          </Link>
        </div>
      </main>
    );
  }

  const headline =
    result.verdict === "Safe"
      ? t("safeHeadline")
      : result.verdict === "Suspicious"
      ? t("suspiciousHeadline")
      : t("dangerousHeadline");

  const certModule = result.modules?.cert;

  return (
    <main className="min-h-screen bg-[var(--tn-bg)] text-[var(--tn-text)] flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* ── Top Navigation Bar (Identical to Landing) ── */}
      <header className="sticky top-0 z-40 bg-[var(--tn-bg)]/85 backdrop-blur-md border-b border-[var(--tn-border)]">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3.5 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 focus-ring rounded-lg group" aria-label="TriNayan Home">
            <div className="relative w-8 h-9 sm:w-9 sm:h-10 shrink-0">
              <Image
                src="/logo.png"
                alt="TriNayan Security Shield"
                fill
                priority
                sizes="36px"
                className="object-contain transition-transform group-hover:scale-105"
              />
            </div>
            <span className="font-extrabold text-[var(--tn-text)] text-xl sm:text-2xl tracking-tight">
              TriNayan
            </span>
          </Link>

          <div className="flex items-center gap-2.5 sm:gap-4">
            <div className="hidden lg:flex items-center gap-1.5 text-xs px-3 py-1 rounded-full bg-[var(--tn-surface)] border border-white/20">
              {isLive ? (
                <>
                  <Zap size={12} className="text-emerald-400 fill-emerald-400" />
                  <span className="text-emerald-300 font-medium">{t("liveConnected")}</span>
                </>
              ) : (
                <>
                  <Server size={12} className="text-amber-400" />
                  <span className="text-amber-300 font-medium">{t("demoMode")}</span>
                </>
              )}
            </div>

            <LanguageSelector />

            <Link
              href={`/report?url=${encodeURIComponent(result.url)}`}
              className="px-3.5 py-1.5 rounded-full border border-white/60 hover:border-white text-xs sm:text-sm font-semibold text-[var(--tn-text)] bg-white/5 hover:bg-white/10 transition-all focus-ring shadow-sm"
            >
              {t("reportPhishing")}
            </Link>

            <Link
              href="/"
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-white/40 hover:border-white text-xs text-[var(--tn-text-secondary)] hover:text-white transition-all focus-ring"
            >
              <RotateCcw size={12} />
              <span>{t("newScan")}</span>
            </Link>
          </div>
        </div>
      </header>

      {/* ── Main Score Container ── */}
      <div className="flex-1 max-w-4xl mx-auto px-4 py-8 space-y-6 w-full animate-fade-in">
        {/* Scanned URL Pill Bar with Copy + Scan Another Actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 rounded-full border border-white/60 bg-[var(--tn-surface)]">
          <div className="flex items-center gap-2 text-xs sm:text-sm font-mono text-[var(--tn-text)] truncate max-w-[260px] sm:max-w-md">
            <Globe size={14} className="text-blue-400 shrink-0" aria-hidden="true" />
            <span className="truncate">{result.url}</span>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleCopyUrl}
              className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium text-[var(--tn-text-secondary)] hover:text-white bg-white/10 hover:bg-white/15 transition-all focus-ring"
              aria-label={t("copyUrl")}
            >
              {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
              <span>{copied ? t("urlCopied") : t("copyUrl")}</span>
            </button>

            <Link
              href="/"
              className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 transition-all focus-ring"
            >
              <RotateCcw size={12} />
              <span>{t("newScan")}</span>
            </Link>
          </div>
        </div>

        {/* ── Verdict Hero Card with Animated Gauge ── */}
        <section
          aria-label="Inspection Verdict"
          className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-6 sm:p-8 shadow-2xl transition-all"
        >
          <div className="flex flex-col sm:flex-row items-center gap-6 sm:gap-10">
            {/* Animated Gauge */}
            <AnimatedRiskGauge
              targetRisk={result.risk}
              verdict={result.verdict}
              verdictText={tVerdict(result.verdict)}
            />

            {/* Verdict Summary */}
            <div className="flex-1 text-center sm:text-left space-y-3">
              <h1 className="text-2xl sm:text-3xl font-extrabold text-[var(--tn-text)] tracking-tight">
                {headline}
              </h1>
              <p className="text-[var(--tn-text-secondary)] text-xs sm:text-sm leading-relaxed max-w-xl">
                {result.recommended_action}
              </p>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2.5 pt-2">
                <a
                  href={result.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-1.5 rounded-full border border-white/40 hover:border-white bg-white/5 hover:bg-white/10 text-xs sm:text-sm font-semibold text-[var(--tn-text)] transition-all flex items-center gap-1.5 focus-ring"
                >
                  <ExternalLink size={13} aria-hidden="true" />
                  <span>{t("openSite")}</span>
                </a>

                <Link
                  href={`/report?url=${encodeURIComponent(result.url)}`}
                  className="px-4 py-1.5 rounded-full border border-red-500/50 hover:border-red-400 bg-red-500/10 hover:bg-red-500/20 text-xs sm:text-sm font-semibold text-red-300 transition-all flex items-center gap-1.5 focus-ring"
                >
                  <Flag size={13} aria-hidden="true" />
                  <span>{t("reportSite")}</span>
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* ── Top Plain-Language Reasons (if present) ── */}
        {result.reasons && result.reasons.length > 0 && result.verdict !== "Safe" && (
          <section className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-5 sm:p-6 shadow-md space-y-3">
            <h2 className="text-[var(--tn-text)] font-bold text-sm sm:text-base flex items-center gap-2">
              <AlertTriangle size={16} className="text-amber-400" aria-hidden="true" />
              <span>{t("whyVerdict")} ({result.reasons.length})</span>
            </h2>

            <ul className="space-y-2 pt-1" role="list">
              {result.reasons.map((r, i) => (
                <li
                  key={i}
                  className="flex items-start gap-2.5 text-xs sm:text-sm text-[var(--tn-text-secondary)] p-2.5 rounded-xl bg-[var(--tn-bg)]/60 border border-white/10"
                >
                  <span className="text-amber-400 font-mono font-bold text-xs w-5 mt-0.5 shrink-0">
                    {i + 1}.
                  </span>
                  <span className="leading-relaxed">{getReasonTitle(r)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* ── 4 Category Cards Grid (Matching Landing 3.png) ── */}
        <section aria-label="Detailed Module Findings" className="space-y-3">
          <h2 className="text-[var(--tn-text)] font-bold text-sm sm:text-base tracking-tight">
            {t("detailedInspection")}
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* 1. Threat & Lexical Analysis */}
            <CategoryCard
              icon="🎯"
              title={t("threatModule")}
              subtitle={t("threatDesc")}
              result={result.modules?.threat}
            />

            {/* 2. Certificate Trust */}
            <CertPanel
              findings={certModule?.findings || []}
              score={certModule?.score || 0}
              title={t("certModule")}
              subtitle={t("certDesc")}
              scannedUrl={result.url}
            />

            {/* 3. Security Headers & Cookies */}
            <CategoryCard
              icon="🛡️"
              title={t("websecModule")}
              subtitle={t("websecDesc")}
              result={result.modules?.websec}
            />

            {/* 4. Community Threat Intel */}
            <CategoryCard
              icon="👥"
              title={t("communityModule")}
              subtitle={t("communityDesc")}
              result={result.modules?.community}
            />
          </div>
        </section>

        {/* ── Footer Disclaimer ── */}
        <footer className="text-center text-[var(--tn-text-muted)] text-xs py-8 border-t border-[var(--tn-border)] space-y-1">
          <p>{t("footerDisclaimerResult")}</p>
          {result.scanned_at && (
            <p className="text-[11px] text-slate-500 font-mono">
              Scanned at {new Date(result.scanned_at).toLocaleString()}
            </p>
          )}
        </footer>
      </div>
    </main>
  );
}

export default function ResultPage() {
  const { t } = useLanguage();
  return (
    <Suspense fallback={<SplashLoader message={t("analyzing")} />}>
      <ResultContent />
    </Suspense>
  );
}
