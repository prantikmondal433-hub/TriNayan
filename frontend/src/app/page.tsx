"use client";

import { useState, useEffect, useRef, FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import {
  Globe,
  Search,
  AlertTriangle,
  Lock,
  Trash2,
  ArrowRight,
} from "lucide-react";
import { getHistory, clearHistory, HistoryEntry } from "@/lib/api";
import { useLanguage } from "@/context/LanguageContext";
import { LanguageSelector } from "@/components/LanguageSelector";
import { SplashLoader } from "@/components/SplashLoader";
import { verdictColor } from "@/lib/utils";
import { Verdict } from "@/lib/types";

const DEFAULT_SAMPLE_SCANS: HistoryEntry[] = [
  {
    url: "https://www.youtube.com",
    risk: 0,
    verdict: "Safe",
    scanned_at: new Date().toISOString(),
  },
  {
    url: "https://www.google.com",
    risk: 0,
    verdict: "Safe",
    scanned_at: new Date().toISOString(),
  },
  {
    url: "https://www.abcxyz.com",
    risk: 85,
    verdict: "Dangerous",
    scanned_at: new Date().toISOString(),
  },
];

export default function HomePage() {
  const router = useRouter();
  const { t, tVerdict } = useLanguage();
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [history, setHistory] = useState<HistoryEntry[]>(DEFAULT_SAMPLE_SCANS);

  // Splash screen state with sessionStorage flag & fade out
  const [showSplash, setShowSplash] = useState(true);
  const [isFadingOut, setIsFadingOut] = useState(false);

  // Scroll section ref for IntersectionObserver
  const featureSectionRef = useRef<HTMLDivElement>(null);
  const [featuresVisible, setFeaturesVisible] = useState(false);

  useEffect(() => {
    // Check if splash was already shown in this session
    try {
      if (sessionStorage.getItem("trinayan_splash_seen")) {
        queueMicrotask(() => setShowSplash(false));
        return;
      }
    } catch {
      // Ignore sessionStorage exceptions
    }

    const minTimer = setTimeout(() => {
      setIsFadingOut(true);
      setTimeout(() => {
        setShowSplash(false);
        try {
          sessionStorage.setItem("trinayan_splash_seen", "true");
        } catch {
          // Ignore
        }
      }, 400); // 400ms fade-out transition
    }, 950); // min 950ms splash display

    return () => clearTimeout(minTimer);
  }, []);

  useEffect(() => {
    // Load recent scans history
    const saved = getHistory();
    if (saved && saved.length > 0) {
      queueMicrotask(() => setHistory(saved));
    }
  }, []);

  useEffect(() => {
    // IntersectionObserver for 2x2 feature cards scroll reveal
    const observer = new IntersectionObserver(
      (entries) => {
        const [entry] = entries;
        if (entry.isIntersecting) {
          setFeaturesVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 }
    );

    if (featureSectionRef.current) {
      observer.observe(featureSectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  function handleClearHistory() {
    clearHistory();
    setHistory([]);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");

    let target = url.trim();
    if (!target) {
      setError(t("fieldRequired") || "Please enter a URL to inspect.");
      return;
    }
    if (!/^https?:\/\//i.test(target)) {
      target = "https://" + target;
    }

    try {
      new URL(target);
    } catch {
      setError(t("invalidUrl") || "Please enter a valid web address.");
      return;
    }

    router.push(`/result?url=${encodeURIComponent(target)}`);
  }

  return (
    <>
      {showSplash && <SplashLoader isFadingOut={isFadingOut} />}

      <main className="min-h-screen bg-[var(--tn-bg)] text-[var(--tn-text)] flex flex-col font-sans selection:bg-blue-600 selection:text-white">
        {/* ── Sticky Transparent Header ── */}
        <header className="sticky top-0 z-40 bg-[var(--tn-bg)]/85 backdrop-blur-md border-b border-[var(--tn-border)] transition-colors">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3.5 flex items-center justify-between">
            {/* Left: Brand Logo & Title */}
            <Link
              href="/"
              className="flex items-center gap-3 focus-ring rounded-lg group"
              aria-label="TriNayan Home"
            >
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

            {/* Right: Language Selector & Report Phishing Pill */}
            <div className="flex items-center gap-3 sm:gap-5">
              <LanguageSelector />
              <Link
                href="/report"
                className="px-4 py-1.5 rounded-full border border-white/60 hover:border-white text-xs sm:text-sm font-semibold text-[var(--tn-text)] bg-white/5 hover:bg-white/10 transition-all focus-ring shadow-sm active:scale-95"
              >
                {t("reportPhishing")}
              </Link>
            </div>
          </div>
        </header>

        {/* ── Hero Section (Image 2) ── */}
        <section className="flex-1 flex flex-col items-center px-4 pt-8 sm:pt-14 pb-12 max-w-4xl mx-auto w-full text-center">
          {/* Passive Security Pill */}
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-[var(--tn-border-medium)] bg-[var(--tn-surface)]/70 text-xs text-[var(--tn-text-secondary)] shadow-inner mb-6">
            <Lock size={13} className="text-slate-400 shrink-0" aria-hidden="true" />
            <span>{t("heroBadge")}</span>
          </div>

          {/* Supporting paragraph with consistent TriNayan brand name */}
          <p className="text-[var(--tn-text-secondary)] text-xs sm:text-sm md:text-base max-w-2xl leading-relaxed mb-6 px-2">
            {t("heroSubtitle")}
          </p>

          {/* Gradient Headline */}
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight mb-8">
            <span className="text-gradient-headline">
              {t("heroTitle1")} {t("heroTitleHighlight")}
            </span>
          </h1>

          {/* URL Search Bar */}
          <form
            onSubmit={handleSubmit}
            className="w-full max-w-2xl flex flex-col items-center"
            role="search"
            aria-label="URL Security Inspector"
          >
            <div className="w-full rounded-full border border-white/60 bg-[var(--tn-surface)] shadow-2xl px-5 py-3 sm:py-3.5 flex items-center gap-3.5 focus-within:border-blue-400 focus-within:ring-2 focus-within:ring-blue-500/25 transition-all">
              <Globe size={20} className="text-[var(--tn-text-secondary)] shrink-0" aria-hidden="true" />
              <label htmlFor="url-input" className="sr-only">
                {t("inputPlaceholder")}
              </label>
              <input
                id="url-input"
                type="text"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  if (error) setError("");
                }}
                placeholder={t("inputPlaceholder")}
                className="w-full bg-transparent text-[var(--tn-text)] placeholder-[var(--tn-text-secondary)]/70 placeholder:italic text-sm sm:text-base outline-none font-sans"
              />
            </div>

            {/* Inspect This Button */}
            <button
              type="submit"
              className="mt-5 inline-flex items-center justify-center gap-2 px-8 py-2.5 rounded-full bg-gradient-to-r from-slate-400/90 via-slate-100 to-slate-400/90 hover:from-slate-300 hover:via-white hover:to-slate-300 text-slate-950 font-bold text-sm sm:text-base transition-all shadow-md active:scale-95 focus-ring cursor-pointer"
            >
              <span>{t("inspectThis")}</span>
              <Search size={16} className="text-slate-950 shrink-0" aria-hidden="true" />
            </button>

            {error && (
              <p
                role="alert"
                className="mt-3 text-[var(--tn-danger)] text-xs sm:text-sm flex items-center gap-1.5 animate-fade-in"
              >
                <AlertTriangle size={14} className="shrink-0" />
                <span>{error}</span>
              </p>
            )}
          </form>

          {/* ── Recent Scans List (Image 2) ── */}
          <div className="w-full max-w-2xl mt-12 sm:mt-16 text-left">
            <div className="flex items-center justify-between mb-3 px-1">
              <h2 className="text-base sm:text-lg italic font-sans font-medium text-[var(--tn-text)]">
                {t("recentScans")}
              </h2>
              {history.length > 0 && (
                <button
                  type="button"
                  onClick={handleClearHistory}
                  aria-label={t("clearHistory")}
                  className="text-xs text-[var(--tn-text-secondary)] hover:text-red-400 flex items-center gap-1.5 transition-colors focus-ring rounded px-2 py-0.5"
                >
                  <Trash2 size={13} aria-hidden="true" />
                  <span>{t("clearHistory")}</span>
                </button>
              )}
            </div>

            <div className="space-y-3" role="list" aria-label="Recent scans history">
              {history.map((h, i) => {
                const color = verdictColor(h.verdict as Verdict);
                return (
                  <Link
                    key={`${h.url}-${i}`}
                    href={`/result?url=${encodeURIComponent(h.url)}`}
                    role="listitem"
                    className="flex items-center justify-between px-5 py-3 rounded-full border border-white/60 bg-[var(--tn-surface)]/80 hover:bg-[var(--tn-surface-hover)] hover:border-white transition-all shadow-sm group focus-ring"
                  >
                    <span className="text-xs sm:text-sm italic font-sans text-[var(--tn-text)] truncate max-w-[190px] sm:max-w-[380px]">
                      {h.url}
                    </span>

                    <span
                      className={`text-xs font-bold px-3 py-1 rounded-full flex items-center gap-1.5 shadow-sm transition-transform group-hover:scale-105 shrink-0 ${color.chip}`}
                    >
                      <span>
                        {tVerdict(h.verdict as Verdict)} ({h.risk})
                      </span>
                      <ArrowRight size={13} aria-hidden="true" />
                    </span>
                  </Link>
                );
              })}
            </div>
          </div>
        </section>

        {/* ── Scroll Section: 2x2 Feature Cards Grid (Image 3) ── */}
        <section
          ref={featureSectionRef}
          aria-label="Security inspection modules"
          className="w-full max-w-4xl mx-auto px-4 py-12 sm:py-16"
        >
          <div
            className={`grid grid-cols-1 md:grid-cols-2 gap-5 transition-all duration-700 ${
              featuresVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
            }`}
          >
            {/* Card 1: Threat & Lexical Analysis */}
            <article className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-6 shadow-xl relative overflow-hidden transition-all hover:-translate-y-1 hover:border-white hover:shadow-2xl hover:shadow-blue-500/10">
              <div className="border border-white/70 rounded-full px-4 py-1.5 text-[var(--tn-text)] font-bold text-sm sm:text-base flex items-center gap-2.5 w-fit mb-3.5 bg-[var(--tn-bg)]/80 shadow-inner">
                <span className="text-base" aria-hidden="true">🎯</span>
                <h2>{t("threatModule")}</h2>
              </div>
              <p className="text-[var(--tn-text-secondary)] text-xs sm:text-sm leading-relaxed">
                {t("threatDesc")}
              </p>
            </article>

            {/* Card 2: Certificate Trust */}
            <article className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-6 shadow-xl relative overflow-hidden transition-all hover:-translate-y-1 hover:border-white hover:shadow-2xl hover:shadow-blue-500/10">
              <div className="border border-white/70 rounded-full px-4 py-1.5 text-[var(--tn-text)] font-bold text-sm sm:text-base flex items-center gap-2.5 w-fit mb-3.5 bg-[var(--tn-bg)]/80 shadow-inner">
                <span className="text-base" aria-hidden="true">🔒</span>
                <h2>{t("certModule")}</h2>
              </div>
              <p className="text-[var(--tn-text-secondary)] text-xs sm:text-sm leading-relaxed">
                {t("certDesc")}
              </p>
            </article>

            {/* Card 3: Security Headers & Cookies (Fixed Title) */}
            <article className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-6 shadow-xl relative overflow-hidden transition-all hover:-translate-y-1 hover:border-white hover:shadow-2xl hover:shadow-blue-500/10">
              <div className="border border-white/70 rounded-full px-4 py-1.5 text-[var(--tn-text)] font-bold text-sm sm:text-base flex items-center gap-2.5 w-fit mb-3.5 bg-[var(--tn-bg)]/80 shadow-inner">
                <span className="text-base" aria-hidden="true">🛡️</span>
                <h2>{t("websecModule")}</h2>
              </div>
              <p className="text-[var(--tn-text-secondary)] text-xs sm:text-sm leading-relaxed">
                {t("websecDesc")}
              </p>
            </article>

            {/* Card 4: Community Threat Intel */}
            <article className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-6 shadow-xl relative overflow-hidden transition-all hover:-translate-y-1 hover:border-white hover:shadow-2xl hover:shadow-blue-500/10">
              <div className="border border-white/70 rounded-full px-4 py-1.5 text-[var(--tn-text)] font-bold text-sm sm:text-base flex items-center gap-2.5 w-fit mb-3.5 bg-[var(--tn-bg)]/80 shadow-inner">
                <span className="text-base" aria-hidden="true">👥</span>
                <h2>{t("communityModule")}</h2>
              </div>
              <p className="text-[var(--tn-text-secondary)] text-xs sm:text-sm leading-relaxed">
                {t("communityDesc")}
              </p>
            </article>
          </div>
        </section>

        {/* ── Footer Disclaimer ── */}
        <footer className="text-center text-[var(--tn-text-muted)] text-xs py-8 border-t border-[var(--tn-border)]">
          <p>{t("footerDisclaimer")}</p>
        </footer>
      </main>
    </>
  );
}
