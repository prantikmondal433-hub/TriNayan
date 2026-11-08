"use client";

import { useState, useEffect, FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  Search,
  AlertTriangle,
  Lock,
  Globe,
  Clock,
  ArrowRight,
  Trash2,
} from "lucide-react";
import { getHistory, clearHistory, HistoryEntry } from "@/lib/api";
import { verdictColor } from "@/lib/utils";
import { useLanguage } from "@/context/LanguageContext";
import { LanguageSelector } from "@/components/LanguageSelector";

export default function HomePage() {
  const router = useRouter();
  const { t, tVerdict } = useLanguage();
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  useEffect(() => {
    setHistory(getHistory());
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
      setError("Please enter a URL to scan.");
      return;
    }
    if (!/^https?:\/\//i.test(target)) {
      target = "https://" + target;
    }

    try {
      new URL(target);
    } catch {
      setError("Please enter a valid web address.");
      return;
    }

    router.push(`/result?url=${encodeURIComponent(target)}`);
  }

  const examples = [
    { label: "Legitimate (GitHub)", url: "https://github.com" },
    { label: "Fake SBI Portal (Phishing)", url: "https://sbi-login-secure.xyz" },
    { label: "Global Brand (Google)", url: "https://google.com" },
  ];

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex flex-col">
      {/* Top Navbar */}
      <nav className="flex items-center gap-3 px-6 py-4 border-b border-slate-800">
        <Shield className="text-blue-400" size={24} />
        <span className="font-bold text-white text-lg tracking-tight">TrustLens</span>

        <div className="ml-auto flex items-center gap-3 sm:gap-4 text-xs">
          {/* Language Selector */}
          <LanguageSelector />

          <Link
            href="/monitor"
            className="text-slate-400 hover:text-slate-200 transition-colors hidden sm:inline"
          >
            {t("ctSentinel")}
          </Link>
          <Link
            href="/report"
            className="text-slate-400 hover:text-slate-200 transition-colors"
          >
            {t("reportPhishing")}
          </Link>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="flex flex-col items-center justify-center flex-1 px-4 py-12 text-center max-w-4xl mx-auto w-full">
        {/* Safety Badge */}
        <div className="mb-6 flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-full px-4 py-1.5">
          <Lock size={13} className="text-blue-400" />
          <span className="text-blue-300 text-xs font-medium">
            {t("heroBadge")}
          </span>
        </div>

        <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold text-white mb-4 leading-tight tracking-tight">
          {t("heroTitle1")}{" "}
          <span className="text-blue-400">{t("heroTitleHighlight")}</span>
        </h1>
        <p className="text-slate-400 text-base sm:text-lg max-w-xl mb-10 leading-relaxed">
          {t("heroSubtitle")}
        </p>

        {/* Scan Input Form */}
        <form
          onSubmit={handleSubmit}
          className="w-full max-w-2xl"
          aria-label="URL scan form"
        >
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Globe
                size={18}
                className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
              />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder={t("inputPlaceholder")}
                aria-label="URL to scan"
                className="w-full pl-11 pr-4 py-4 rounded-xl bg-slate-800/90 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm sm:text-base shadow-lg"
              />
            </div>
            <button
              type="submit"
              className="flex items-center justify-center gap-2 px-7 py-4 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl transition-all focus:outline-none focus:ring-2 focus:ring-blue-400 shadow-lg shadow-blue-600/20 active:scale-[0.98]"
            >
              <Search size={18} />
              <span>{t("inspectBtn")}</span>
            </button>
          </div>
          {error && (
            <p className="mt-2.5 text-red-400 text-sm flex items-center justify-center gap-1.5">
              <AlertTriangle size={14} /> {error}
            </p>
          )}
        </form>

        {/* Demo Examples */}
        <div className="mt-6 flex flex-wrap items-center justify-center gap-2 text-xs">
          <span className="text-slate-500">{t("quickTests")}</span>
          {examples.map((ex) => (
            <button
              key={ex.url}
              onClick={() => setUrl(ex.url)}
              className="text-slate-400 hover:text-blue-300 bg-slate-800/60 border border-slate-700/80 px-2.5 py-1 rounded-md transition-colors"
            >
              {ex.label}
            </button>
          ))}
        </div>

        {/* Recent Scan History */}
        {history.length > 0 && (
          <div className="mt-12 w-full max-w-2xl text-left bg-slate-900/60 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Clock size={14} className="text-slate-500" /> {t("recentScans")}
              </span>
              <button
                onClick={handleClearHistory}
                className="text-xs text-slate-500 hover:text-slate-400 flex items-center gap-1"
                title="Clear history"
              >
                <Trash2 size={12} /> {t("clearHistory")}
              </button>
            </div>
            <div className="space-y-2">
              {history.map((h, i) => {
                const color = verdictColor(h.verdict as any);
                return (
                  <Link
                    key={i}
                    href={`/result?url=${encodeURIComponent(h.url)}`}
                    className="flex items-center justify-between p-2.5 rounded-lg bg-slate-800/40 hover:bg-slate-800 border border-slate-800 transition-colors group"
                  >
                    <span className="text-xs sm:text-sm text-slate-300 font-mono truncate max-w-[280px] sm:max-w-[360px]">
                      {h.url}
                    </span>
                    <div className="flex items-center gap-3">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full font-medium ${color.bg} ${color.text}`}
                      >
                        {tVerdict(h.verdict as any)} ({h.risk})
                      </span>
                      <ArrowRight
                        size={14}
                        className="text-slate-600 group-hover:text-slate-300 transition-colors"
                      />
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        )}

        {/* Feature Highlights Grid */}
        <div className="mt-16 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 w-full">
          {[
            {
              icon: "🎯",
              title: t("threatModule"),
              desc: "Brand lookalikes, homoglyphs, and lexical heuristic checks.",
            },
            {
              icon: "🔒",
              title: t("certModule"),
              desc: "CT log search, CA key reuse detection, and crypto audits.",
            },
            {
              icon: "🛡️",
              title: t("websecModule"),
              desc: "Passive header posture (HSTS, CSP) and cookie security flags.",
            },
            {
              icon: "👥",
              title: t("communityModule"),
              desc: "Collaborative crowdsourced reports and live blocklists.",
            },
          ].map((f) => (
            <div
              key={f.title}
              className="bg-slate-800/40 border border-slate-800 rounded-xl p-5 text-left hover:border-slate-700 transition-colors"
            >
              <div className="text-2xl mb-2">{f.icon}</div>
              <div className="text-white font-semibold text-sm mb-1">{f.title}</div>
              <div className="text-slate-400 text-xs leading-relaxed">{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <footer className="text-center py-4 text-slate-600 text-xs border-t border-slate-800">
        TrustLens Security · Results represent probabilistic risk signals · Passive scanning only
      </footer>
    </main>
  );
}
