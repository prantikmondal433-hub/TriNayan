"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Shield, Search, AlertTriangle, Lock, Globe } from "lucide-react";

export default function HomePage() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    let target = url.trim();
    if (!target) { setError("Please enter a URL."); return; }
    if (!/^https?:\/\//i.test(target)) target = "https://" + target;
    try { new URL(target); } catch { setError("That doesn't look like a valid URL."); return; }
    router.push(`/result?url=${encodeURIComponent(target)}`);
  }

  const examples = ["https://github.com", "https://sbi-login-secure.xyz", "https://google.com"];

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex flex-col">
      <nav className="flex items-center gap-3 px-6 py-4 border-b border-slate-800">
        <Shield className="text-blue-400" size={24} />
        <span className="font-bold text-white text-lg tracking-tight">TrustLens</span>
        <span className="ml-auto text-xs text-slate-500 hidden sm:block">AI-powered website trust analysis</span>
      </nav>

      <div className="flex flex-col items-center justify-center flex-1 px-4 py-16 text-center">
        <div className="mb-6 flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-full px-4 py-1.5">
          <Lock size={13} className="text-blue-400" />
          <span className="text-blue-300 text-xs font-medium">Passive scanning only · Your privacy is protected</span>
        </div>

        <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold text-white mb-4 leading-tight">
          Is this website{" "}<span className="text-blue-400">really safe?</span>
        </h1>
        <p className="text-slate-400 text-base sm:text-lg max-w-xl mb-10">
          TrustLens checks for phishing, weak certificates, security flaws, and community reports —
          giving you one honest, explainable verdict.
        </p>

        <form onSubmit={handleSubmit} className="w-full max-w-2xl" aria-label="URL scan form">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Globe size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter a URL to scan, e.g. https://example.com"
                aria-label="URL to scan"
                className="w-full pl-10 pr-4 py-4 rounded-xl bg-slate-800 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm sm:text-base"
              />
            </div>
            <button
              type="submit"
              className="flex items-center justify-center gap-2 px-6 py-4 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl transition-colors focus:outline-none focus:ring-2 focus:ring-blue-400"
            >
              <Search size={16} />Scan
            </button>
          </div>
          {error && (
            <p className="mt-2 text-red-400 text-sm flex items-center gap-1">
              <AlertTriangle size={13} /> {error}
            </p>
          )}
        </form>

        <div className="mt-5 flex flex-wrap justify-center gap-2">
          <span className="text-slate-500 text-xs pt-0.5">Try:</span>
          {examples.map((ex) => (
            <button key={ex} onClick={() => setUrl(ex)}
              className="text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2 transition-colors">
              {ex}
            </button>
          ))}
        </div>

        <div className="mt-20 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl w-full">
          {[
            { icon: "🎯", title: "Threat Analysis", desc: "Brand impersonation, ML phishing model, domain age" },
            { icon: "🔒", title: "Certificate Trust", desc: "CT logs, key reuse, chain validation, CA watchlist" },
            { icon: "🛡️", title: "Web Security", desc: "Headers, cookies, exposed files, SPF/DMARC" },
            { icon: "👥", title: "Community Intel", desc: "User reports, blocklist feeds, reputation scoring" },
          ].map((f) => (
            <div key={f.title} className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 text-left">
              <div className="text-2xl mb-2">{f.icon}</div>
              <div className="text-white font-semibold text-sm mb-1">{f.title}</div>
              <div className="text-slate-400 text-xs leading-relaxed">{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <footer className="text-center py-4 text-slate-600 text-xs border-t border-slate-800">
        TrustLens · Results are risk signals, not proof · Passive scanning only
      </footer>
    </main>
  );
}
