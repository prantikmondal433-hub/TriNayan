"use client";

import { useState, FormEvent, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { Shield, ArrowLeft, Flag, CheckCircle, AlertTriangle } from "lucide-react";
import { submitReport } from "@/lib/api";

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

  const [url, setUrl] = useState(prefillUrl);
  const [category, setCategory] = useState(CATEGORIES[0]);
  const [comment, setComment] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setErrorMsg("");

    let target = url.trim();
    if (!target) {
      setErrorMsg("Please enter a URL to report.");
      return;
    }
    if (!/^https?:\/\//i.test(target)) {
      target = "https://" + target;
    }

    setLoading(true);
    try {
      await submitReport({
        url: target,
        category,
        comment,
      });
      setSubmitted(true);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to submit report. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  if (submitted) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4 text-center">
        <CheckCircle size={56} className="text-green-400" />
        <h2 className="text-white text-2xl font-bold">Threat Report Submitted</h2>
        <p className="text-slate-400 max-w-sm text-sm leading-relaxed">
          Thank you for protecting the community. Your report has been registered into our
          threat intelligence database for reputation-weighted verification.
        </p>
        <div className="flex gap-3 mt-4">
          <Link
            href="/"
            className="px-5 py-2.5 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500 transition-colors font-medium"
          >
            Scan another URL
          </Link>
          <button
            onClick={() => {
              setSubmitted(false);
              setUrl("");
              setComment("");
            }}
            className="px-5 py-2.5 bg-slate-800 text-slate-300 rounded-lg text-sm hover:bg-slate-700 transition-colors border border-slate-700"
          >
            Report another site
          </button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5 max-w-xl mx-auto">
      {errorMsg && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-300 text-sm flex items-center gap-2">
          <AlertTriangle size={15} />
          {errorMsg}
        </div>
      )}

      <div>
        <label className="block text-sm text-slate-300 mb-1.5 font-medium">
          Suspicious URL *
        </label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
          placeholder="https://fake-login-example.com"
          className="w-full px-4 py-3 rounded-xl bg-slate-800/90 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm font-mono"
        />
      </div>

      <div>
        <label className="block text-sm text-slate-300 mb-1.5 font-medium">
          Threat Category *
        </label>
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="w-full px-4 py-3 rounded-xl bg-slate-800/90 border border-slate-700 text-white focus:outline-none focus:ring-2 focus:ring-red-500 text-sm"
        >
          {CATEGORIES.map((c) => (
            <option key={c} value={c} className="bg-slate-900 text-white">
              {c}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className="block text-sm text-slate-300 mb-1.5 font-medium">
          Evidence or Context (Optional)
        </label>
        <textarea
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          rows={4}
          placeholder="e.g., Received via SMS pretending to be an electricity bill update asking for debit card details..."
          className="w-full px-4 py-3 rounded-xl bg-slate-800/90 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm resize-none"
        />
      </div>

      <button
        type="submit"
        disabled={loading || !url.trim()}
        className="w-full flex items-center justify-center gap-2 py-3.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all shadow-lg shadow-red-600/20 active:scale-[0.99]"
      >
        <Flag size={15} />
        {loading ? "Submitting to threat network..." : "Submit Threat Report"}
      </button>

      <p className="text-xs text-slate-500 text-center leading-relaxed">
        Reports feed our collaborative defense network. Verified malicious reports automatically
        weight risk scoring across all TrustLens extensions and scanners.
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
        <Link
          href="/"
          className="ml-auto flex items-center gap-1.5 text-slate-400 hover:text-white text-sm transition-colors"
        >
          <ArrowLeft size={14} /> Home
        </Link>
      </nav>

      <div className="max-w-2xl mx-auto px-4 py-10">
        <div className="mb-8 text-center sm:text-left">
          <h1 className="text-2xl sm:text-3xl font-bold text-white flex items-center justify-center sm:justify-start gap-2.5 mb-2">
            <Flag size={24} className="text-red-400" /> Report a Malicious Website
          </h1>
          <p className="text-slate-400 text-sm">
            Help safeguard Indian citizens and users worldwide by flagging deceptive portals,
            fake payment gateways, or credential harvesters.
          </p>
        </div>

        <Suspense
          fallback={<div className="animate-pulse h-64 bg-slate-800/60 rounded-xl" />}
        >
          <ReportForm />
        </Suspense>
      </div>
    </main>
  );
}
