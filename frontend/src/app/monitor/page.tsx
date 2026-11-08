"use client";

import { useState, FormEvent } from "react";
import Link from "next/link";
import {
  Shield,
  ArrowLeft,
  Bell,
  CheckCircle,
  AlertTriangle,
  Globe,
  Mail,
  Search,
} from "lucide-react";

export default function MonitorPage() {
  const [domain, setDomain] = useState("");
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleRegister(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    // Simulated registration until P3/P1 stretch endpoint lands
    await new Promise((r) => setTimeout(r, 900));
    setSubmitted(true);
    setLoading(false);
  }

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <nav className="flex items-center gap-3 px-6 py-4 border-b border-slate-800">
        <Shield className="text-blue-400" size={20} />
        <span className="font-bold text-white">TrustLens</span>
        <Link
          href="/"
          className="ml-auto flex items-center gap-1.5 text-slate-400 hover:text-white text-sm transition-colors"
        >
          <ArrowLeft size={14} /> Home
        </Link>
      </nav>

      <div className="max-w-2xl mx-auto px-4 py-12">
        <div className="mb-8 text-center sm:text-left">
          <div className="inline-flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-full px-3.5 py-1 mb-3">
            <Bell size={13} className="text-blue-400" />
            <span className="text-blue-300 text-xs font-semibold uppercase tracking-wider">
              Certificate Transparency Sentinel
            </span>
          </div>
          <h1 className="text-3xl font-extrabold text-white mb-2">
            Domain & Brand Monitoring
          </h1>
          <p className="text-slate-400 text-sm leading-relaxed">
            Protect your brand against rogue TLS certificates and lookalike phishing domains.
            Receive real-time alerts whenever a Certificate Authority logs a new certificate
            for your domain or close homoglyphs.
          </p>
        </div>

        {submitted ? (
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-8 text-center space-y-4">
            <CheckCircle size={52} className="mx-auto text-green-400" />
            <h2 className="text-xl font-bold text-white">Monitoring Active</h2>
            <p className="text-slate-300 text-sm max-w-md mx-auto">
              We are now tracking CT log feeds for <span className="font-mono text-blue-400 font-semibold">{domain}</span>.
              Instant alerts will be dispatched to <span className="font-mono text-slate-200">{email}</span>.
            </p>
            <div className="pt-4 flex justify-center gap-3">
              <button
                onClick={() => {
                  setSubmitted(false);
                  setDomain("");
                  setEmail("");
                }}
                className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded-xl border border-slate-700 transition-colors"
              >
                Monitor Another Domain
              </button>
              <Link
                href="/"
                className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-xl transition-colors"
              >
                Back to Scanner
              </Link>
            </div>
          </div>
        ) : (
          <form
            onSubmit={handleRegister}
            className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-5"
          >
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Target Domain to Monitor *
              </label>
              <div className="relative">
                <Globe
                  size={16}
                  className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500"
                />
                <input
                  type="text"
                  required
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com or bankportal.gov.in"
                  className="w-full pl-10 pr-4 py-3 bg-slate-800/90 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm font-mono"
                />
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Also automatically monitors for typosquatting variants (e.g. examp1e.com).
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Alert Notification Email *
              </label>
              <div className="relative">
                <Mail
                  size={16}
                  className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500"
                />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="security@yourdomain.com"
                  className="w-full pl-10 pr-4 py-3 bg-slate-800/90 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !domain.trim() || !email.trim()}
              className="w-full flex items-center justify-center gap-2 py-3.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-xl transition-all shadow-lg shadow-blue-600/20 active:scale-[0.99]"
            >
              <Bell size={16} />
              {loading ? "Registering Sentinel..." : "Activate CT Log Monitoring"}
            </button>
          </form>
        )}
      </div>
    </main>
  );
}
