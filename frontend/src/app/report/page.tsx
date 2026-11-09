"use client";

import { useState, FormEvent, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import {
  Search,
  ChevronDown,
  CheckCircle,
  AlertTriangle,
  Home,
  ShieldAlert,
  Loader2,
} from "lucide-react";
import { submitReport } from "@/lib/api";
import { useLanguage } from "@/context/LanguageContext";
import { LanguageSelector } from "@/components/LanguageSelector";

const CATEGORIES = [
  "Phishing / Credential Harvesting",
  "Brand Impersonation",
  "Fake Payment / UPI Fraud",
  "Malware Distribution",
  "Job / Recruitment Scam",
  "Insecure Certificate / MITM",
  "Other Suspicious Activity",
];

function ReportForm() {
  const params = useSearchParams();
  const prefillUrl = params.get("url") ?? "";
  const { t } = useLanguage();

  const [url, setUrl] = useState(prefillUrl);
  const [category, setCategory] = useState(CATEGORIES[0]);
  const [comment, setComment] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [urlError, setUrlError] = useState("");
  const [showToast, setShowToast] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setErrorMsg("");
    setUrlError("");

    let target = url.trim();
    if (!target) {
      setUrlError(t("fieldRequired") || "Please enter a URL to report.");
      return;
    }
    if (!/^https?:\/\//i.test(target)) {
      target = "https://" + target;
    }

    try {
      new URL(target);
    } catch {
      setUrlError(t("invalidUrl") || "Please enter a valid web address.");
      return;
    }

    setLoading(true);
    try {
      await submitReport({
        url: target,
        category,
        comment,
      });
      setSubmitted(true);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 5000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to submit report. Please try again.";
      setErrorMsg(msg);
    } finally {
      setLoading(false);
    }
  }

  if (submitted) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex flex-col items-center justify-center py-10 gap-4 text-center animate-fade-in"
      >
        <div className="w-16 h-16 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center mb-2">
          <CheckCircle size={36} className="text-[var(--tn-safe)] drop-shadow-[0_0_12px_rgba(16,185,129,0.5)]" />
        </div>
        <h2 className="text-2xl font-extrabold text-[var(--tn-text)]">{t("reportSuccess")}</h2>
        <p className="text-[var(--tn-text-secondary)] max-w-md text-xs sm:text-sm leading-relaxed">
          {t("reportSuccessDesc")}
        </p>

        <div className="flex flex-wrap gap-3 mt-6">
          <Link
            href="/"
            className="px-6 py-2.5 bg-gradient-to-r from-blue-600 via-blue-500 to-sky-600 hover:from-blue-500 hover:to-sky-500 text-white rounded-full text-xs sm:text-sm transition-all font-semibold shadow-md focus-ring"
          >
            {t("scanAnother")}
          </Link>
          <button
            type="button"
            onClick={() => {
              setSubmitted(false);
              setUrl("");
              setComment("");
              setUrlError("");
              setErrorMsg("");
            }}
            className="px-6 py-2.5 bg-white/10 text-[var(--tn-text)] rounded-full text-xs sm:text-sm hover:bg-white/15 transition-all border border-white/30 focus-ring"
          >
            Report Another Site
          </button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-5 text-left">
      {/* Toast Notification */}
      {showToast && (
        <div
          role="status"
          className="p-3 bg-emerald-500/15 border border-emerald-500/50 rounded-xl text-emerald-300 text-xs sm:text-sm flex items-center gap-2 animate-fade-in"
        >
          <CheckCircle size={16} className="shrink-0" />
          <span>Report received and queued for intelligence review.</span>
        </div>
      )}

      {errorMsg && (
        <div
          role="alert"
          className="p-3 bg-red-500/15 border border-red-500/50 rounded-xl text-red-300 text-xs sm:text-sm flex items-center gap-2 animate-fade-in"
        >
          <AlertTriangle size={16} className="shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Field 1: Suspicious URL */}
      <div>
        <label htmlFor="suspicious-url" className="block text-xs sm:text-sm text-[var(--tn-text)] mb-2 font-semibold">
          {t("urlToReport")}
        </label>
        <div className="rounded-full border border-white/60 bg-[var(--tn-surface)] px-4 py-3 flex items-center gap-2.5 focus-within:border-blue-400 focus-within:ring-2 focus-within:ring-blue-500/25 shadow-inner transition-all">
          <Search size={16} className="text-[var(--tn-text-secondary)] shrink-0" aria-hidden="true" />
          <input
            id="suspicious-url"
            type="url"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (urlError) setUrlError("");
            }}
            required
            aria-required="true"
            aria-invalid={!!urlError}
            aria-describedby={urlError ? "url-error" : undefined}
            placeholder="https://fake-login-example.com"
            className="w-full bg-transparent text-[var(--tn-text)] placeholder-[var(--tn-text-secondary)]/60 text-xs sm:text-sm font-sans outline-none font-mono"
          />
        </div>
        {urlError && (
          <p id="url-error" role="alert" className="text-red-400 text-xs mt-1.5 px-3">
            {urlError}
          </p>
        )}
      </div>

      {/* Field 2: Threat Category (Fixed Typo: Phishing / Credential Harvesting) */}
      <div>
        <label htmlFor="threat-category" className="block text-xs sm:text-sm text-[var(--tn-text)] mb-2 font-semibold">
          {t("threatCategory")}
        </label>
        <div className="rounded-full border border-white/60 bg-[var(--tn-surface)] px-4 py-3 shadow-inner relative flex items-center focus-within:border-blue-400 focus-within:ring-2 focus-within:ring-blue-500/25 transition-all">
          <select
            id="threat-category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="w-full bg-transparent text-[var(--tn-text)] text-xs sm:text-sm outline-none appearance-none pr-8 cursor-pointer font-sans"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c} className="bg-[var(--tn-surface)] text-[var(--tn-text)]">
                {c}
              </option>
            ))}
          </select>
          <ChevronDown
            size={16}
            className="text-[var(--tn-text-secondary)] absolute right-4 pointer-events-none"
            aria-hidden="true"
          />
        </div>
      </div>

      {/* Field 3: Evidence or Context (Optional) */}
      <div>
        <label htmlFor="evidence-context" className="block text-xs sm:text-sm text-[var(--tn-text)] mb-2 font-semibold">
          {t("comments")}
        </label>
        <div className="rounded-2xl border border-white/60 bg-[var(--tn-surface)] p-3.5 shadow-inner focus-within:border-blue-400 focus-within:ring-2 focus-within:ring-blue-500/25 transition-all">
          <textarea
            id="evidence-context"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            rows={3}
            placeholder="e.g., Received via SMS pretending to be an electricity bill update asking for debit card details..."
            className="w-full bg-transparent text-[var(--tn-text)] placeholder-[var(--tn-text-secondary)]/60 text-xs sm:text-sm outline-none resize-none font-sans leading-relaxed"
          />
        </div>
      </div>

      {/* Submit Button */}
      <button
        type="submit"
        disabled={loading}
        className="w-full py-3.5 rounded-full bg-gradient-to-r from-blue-700 via-blue-600 to-blue-700 hover:from-blue-600 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold text-sm sm:text-base transition-all shadow-lg shadow-blue-950/50 border border-blue-400/40 active:scale-[0.99] flex items-center justify-center gap-2 mt-6 focus-ring cursor-pointer"
      >
        {loading ? (
          <>
            <Loader2 size={18} className="animate-spin" aria-hidden="true" />
            <span>{t("submitting")}</span>
          </>
        ) : (
          <>
            <ShieldAlert size={18} aria-hidden="true" />
            <span>{t("submitReport")}</span>
          </>
        )}
      </button>

      <p className="text-[11px] text-[var(--tn-text-muted)] text-center leading-relaxed pt-2">
        Reports feed our collaborative defense network. Verified malicious reports automatically weight risk scoring across all TriNayan scanners.
      </p>
    </form>
  );
}

export default function ReportPage() {
  const { t } = useLanguage();

  return (
    <main className="min-h-screen bg-[var(--tn-bg)] text-[var(--tn-text)] flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* ── Top Navigation Bar (Image 4) ── */}
      <header className="sticky top-0 z-40 bg-[var(--tn-bg)]/85 backdrop-blur-md border-b border-[var(--tn-border)]">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3.5 flex items-center justify-between">
          {/* Left: Brand Logo & Title */}
          <Link href="/" className="flex items-center gap-3 focus-ring rounded-lg group" aria-label="TriNayan Home">
            <div className="relative w-8 h-9 sm:w-9 sm:h-10 shrink-0">
              <Image
                src="/logo.png"
                alt="TriNayan Shield Logo"
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

          {/* Right: Language Selector & Home Button with Lucide Home icon */}
          <div className="flex items-center gap-3 sm:gap-5">
            <LanguageSelector />
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full border border-white/60 hover:border-white text-xs sm:text-sm font-semibold text-[var(--tn-text)] bg-white/5 hover:bg-white/10 transition-all focus-ring shadow-sm active:scale-95"
            >
              <Home size={14} aria-hidden="true" />
              <span>{t("home")}</span>
            </Link>
          </div>
        </div>
      </header>

      {/* ── Main Report Card Container (Image 4) ── */}
      <section className="flex-1 flex flex-col items-center justify-center px-4 py-8 sm:py-14 w-full">
        <div className="w-full max-w-2xl rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-6 sm:p-10 shadow-2xl relative overflow-hidden">
          <h1 className="text-2xl sm:text-3xl font-extrabold text-[var(--tn-text)] text-center tracking-tight mb-2.5">
            {t("reportTitle")}
          </h1>
          <p className="text-[var(--tn-text-secondary)] text-xs sm:text-sm text-center max-w-lg mx-auto leading-relaxed mb-8">
            {t("reportSubtitle")}
          </p>

          <Suspense fallback={<div className="animate-pulse h-64 bg-slate-800/40 rounded-2xl" />}>
            <ReportForm />
          </Suspense>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="text-center text-[var(--tn-text-muted)] text-xs py-6 border-t border-[var(--tn-border)]">
        <p>{t("footerDisclaimer")}</p>
      </footer>
    </main>
  );
}
