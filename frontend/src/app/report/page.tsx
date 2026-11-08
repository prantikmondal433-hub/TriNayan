"use client";

import { useState, FormEvent, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { Shield, ArrowLeft, Flag, CheckCircle } from "lucide-react";

const CATEGORIES = [
  "Phishing",
  "Malware",
  "Scam / Fraud",
  "Brand Impersonation",
  "Fake Shop",
  "Other",
];

function ReportForm() {
  const params = useSearchParams();
  const prefillUrl = params.get("url") ?? "";

  const [url, setUrl] = useState(prefillUrl);
  const [category, setCategory] = useState(CATEGORIES[0]);
  const [comment, setComment] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    // TODO H16: replace with real POST /report
    await new Promise((r) => setTimeout(r, 1000));
    setSubmitted(true);
    setLoading(false);
  }

  if (submitted) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4 text-center">
        <CheckCircle size={52} className="text-green-400" />
        <h2 className="text-white text-2xl font-bold">Report submitted!</h2>
        <p className="text-slate-400 max-w-sm text-sm">
          Thank you. Our community team will review this URL. Your report helps protect other users.
        </p>
        <div className="flex gap-3 mt-4">
          <Link href="/" className="px-5 py-2.5 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500 transition-colors font-medium">
            Scan another URL
          </Link>
          <button
            onClick={() => { setSubmitted(false); setUrl(""); setComment(""); }}
            className="px-5 py-2.5 bg-slate-700 text-slate-300 rounded-lg text-sm hover:bg-slate-600 transition-colors"
          >
            Report another
          </button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5 max-w-xl mx-auto">
      <div>
        <label className="block text-sm text-slate-300 mb-1.5 font-medium">URL to report *</label>
        <input
          type="text" value={url} onChange={(e) => setUrl(e.target.value)} required
          placeholder="https://suspicious-site.com"
          className="w-full px-4 py-3 rounded-xl bg-slate-800 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm"
        />
      </div>

      <div>
        <label className="block text-sm text-slate-300 mb-1.5 font-medium">Category *</label>
        <select
          value={category} onChange={(e) => setCategory(e.target.value)}
          className="w-full px-4 py-3 rounded-xl bg-slate-800 border border-slate-700 text-white focus:outline-none focus:ring-2 focus:ring-red-500 text-sm"
        >
          {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
        </select>
      </div>

      <div>
        <label className="block text-sm text-slate-300 mb-1.5 font-medium">Additional details</label>
        <textarea
          value={comment} onChange={(e) => setComment(e.target.value)} rows={4}
          placeholder="Describe what made this site suspicious (optional)..."
          className="w-full px-4 py-3 rounded-xl bg-slate-800 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm resize-none"
        />
      </div>

      <button
        type="submit" disabled={loading || !url.trim()}
        className="w-full flex items-center justify-center gap-2 py-3 bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors"
      >
        <Flag size={15} />
        {loading ? "Submitting…" : "Submit Report"}
      </button>

      <p className="text-xs text-slate-500 text-center">
        Reports are reviewed by our team. Only report genuinely suspicious sites.
      </p>
    </form>
  );
}

export default function ReportPage() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <nav className="flex items-center gap-3 px-6 py-4 border-b border-slate-800">
        <Shield className="text-blue-400" size={20} />
        <span className="font-bold text-white">TrustLens</span>
        <Link href="/" className="ml-auto flex items-center gap-1.5 text-slate-400 hover:text-white text-sm transition-colors">
          <ArrowLeft size={14} /> Home
        </Link>
      </nav>

      <div className="max-w-2xl mx-auto px-4 py-10">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2 mb-2">
            <Flag size={22} className="text-red-400" /> Report a Suspicious Site
          </h1>
          <p className="text-slate-400 text-sm">
            Help protect the community by reporting phishing or malicious websites.
          </p>
        </div>

        <Suspense fallback={<div className="animate-pulse h-64 bg-slate-800 rounded-xl" />}>
          <ReportForm />
        </Suspense>
      </div>
    </main>
  );
}
