"use client";

import { CheckCircle, ChevronDown, ChevronUp, Lock } from "lucide-react";
import { useState } from "react";
import { Finding } from "@/lib/types";
import { severityColor, severityIcon } from "@/lib/utils";

interface CertInfo {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  key_type: string;
  key_bits: number;
  serial: string;
  is_root: boolean;
  is_self_signed: boolean;
}

interface CertPanelProps {
  findings: Finding[];
  score: number;
  title?: string;
  subtitle?: string;
  scannedUrl?: string;
}

const DEFAULT_CHAIN: CertInfo[] = [
  {
    subject: "CN=*.google.com, O=Google LLC, C=US",
    issuer: "CN=WR2, O=Google Trust Services, C=US",
    valid_from: "2026-09-01",
    valid_to: "2027-01-20",
    key_type: "ECDSA",
    key_bits: 256,
    serial: "2a:4b:6c:8d:0e:1f:3a",
    is_root: false,
    is_self_signed: false,
  },
  {
    subject: "CN=WR2, O=Google Trust Services, C=US",
    issuer: "CN=GTS Root R4, O=Google Trust Services LLC, C=US",
    valid_from: "2020-08-11",
    valid_to: "2027-02-22",
    key_type: "RSA",
    key_bits: 2048,
    serial: "00:c4:91:2b:08:4a:cf:0c:18",
    is_root: false,
    is_self_signed: false,
  },
  {
    subject: "CN=GTS Root R4, O=Google Trust Services LLC, C=US",
    issuer: "CN=GTS Root R4, O=Google Trust Services LLC, C=US",
    valid_from: "2016-06-22",
    valid_to: "2036-06-22",
    key_type: "RSA",
    key_bits: 4096,
    serial: "82:10:cf:b0:d2:40:e3:59:44:63:e0:bb",
    is_root: true,
    is_self_signed: true,
  },
];

function CertNode({ cert, index, total }: { cert: CertInfo; index: number; total: number }) {
  const [expanded, setExpanded] = useState(index === 0);
  const isLeaf = index === 0;
  const isRoot = index === total - 1;
  const isWeak = cert.key_bits < 2048 && cert.key_type === "RSA";

  const label = isLeaf ? "🍃 Leaf Certificate" : isRoot ? "🌳 Root Authority" : "🔗 Intermediate CA";

  return (
    <div className="relative">
      {!isRoot && (
        <div className="absolute left-4 top-full w-0.5 h-3 bg-white/20 z-10" aria-hidden="true" />
      )}

      <div
        className={`border rounded-xl overflow-hidden bg-[var(--tn-bg)]/80 ${
          isWeak
            ? "border-red-500/50"
            : isLeaf
            ? "border-blue-500/50"
            : "border-white/20"
        }`}
      >
        <button
          type="button"
          onClick={() => setExpanded((o) => !o)}
          aria-expanded={expanded}
          className="w-full flex items-center justify-between px-3.5 py-2.5 hover:bg-white/5 transition-colors text-left focus-ring"
        >
          <div className="flex items-center gap-2 overflow-hidden">
            <span className="text-[11px] font-semibold text-[var(--tn-text)] shrink-0">{label}</span>
            <span className="text-[11px] text-[var(--tn-text-secondary)] font-mono truncate">
              {cert.subject.replace("CN=", "")}
            </span>
            {isWeak && (
              <span className="text-[10px] text-red-400 bg-red-500/15 border border-red-500/30 px-1.5 py-0.5 rounded-full shrink-0">
                Weak key
              </span>
            )}
          </div>
          {expanded ? (
            <ChevronUp size={14} className="text-slate-400 shrink-0 ml-2" />
          ) : (
            <ChevronDown size={14} className="text-slate-400 shrink-0 ml-2" />
          )}
        </button>

        {expanded && (
          <div className="px-3.5 pb-3 border-t border-white/10 pt-2.5 grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-[11px]">
            <div>
              <span className="text-[var(--tn-text-muted)] font-medium">Subject</span>
              <p className="text-[var(--tn-text)] font-mono mt-0.5 break-all">{cert.subject}</p>
            </div>
            <div>
              <span className="text-[var(--tn-text-muted)] font-medium">Issuer</span>
              <p className="text-[var(--tn-text)] font-mono mt-0.5 break-all">{cert.issuer}</p>
            </div>
            <div>
              <span className="text-[var(--tn-text-muted)] font-medium">Valid from</span>
              <p className="text-[var(--tn-text-secondary)] mt-0.5">{cert.valid_from}</p>
            </div>
            <div>
              <span className="text-[var(--tn-text-muted)] font-medium">Valid to</span>
              <p className="text-[var(--tn-text-secondary)] mt-0.5">{cert.valid_to}</p>
            </div>
            <div>
              <span className="text-[var(--tn-text-muted)] font-medium">Cryptographic Key</span>
              <p className={`mt-0.5 font-semibold ${isWeak ? "text-red-400" : "text-emerald-400"}`}>
                {cert.key_type}-{cert.key_bits} {isWeak ? "⚠ Weak (<2048)" : "✓ Strong"}
              </p>
            </div>
            <div>
              <span className="text-[var(--tn-text-muted)] font-medium">Self-Signed Root</span>
              <p className="text-[var(--tn-text-secondary)] mt-0.5">{cert.is_self_signed ? "Yes" : "No"}</p>
            </div>
            <div className="sm:col-span-2">
              <span className="text-[var(--tn-text-muted)] font-medium">Serial Number</span>
              <p className="text-[var(--tn-text-secondary)] font-mono mt-0.5 text-[10px] break-all">{cert.serial}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function CertPanel({
  findings,
  score,
  title = "Certificate Trust",
  subtitle = "CT log search, CA key reuse detection, and crypto audits.",
  scannedUrl,
}: CertPanelProps) {
  const [showChain, setShowChain] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState(false);

  // Customize mock chain leaf hostname if URL provided
  let chain = DEFAULT_CHAIN;
  if (scannedUrl) {
    try {
      const parsed = new URL(scannedUrl);
      const host = parsed.hostname || "example.com";
      chain = [
        {
          ...DEFAULT_CHAIN[0],
          subject: `CN=${host}`,
        },
        DEFAULT_CHAIN[1],
        DEFAULT_CHAIN[2],
      ];
    } catch {
      // keep default
    }
  }

  const isSafe = score <= 30;
  const isDanger = score >= 70;

  return (
    <article className="rounded-[var(--tn-radius-card)] border border-white/60 bg-[var(--tn-surface)] p-5 sm:p-6 shadow-xl flex flex-col justify-between transition-all hover:border-white hover:shadow-2xl hover:shadow-blue-500/10">
      <div>
        {/* Header Pill & Sub-Score Bar + Status Chip */}
        <div className="flex items-center justify-between gap-3 mb-3">
          <div className="border border-white/70 rounded-full px-3.5 py-1 text-[var(--tn-text)] font-bold text-xs sm:text-sm flex items-center gap-2 bg-[var(--tn-bg)]/80 shadow-inner">
            <span aria-hidden="true">🔒</span>
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

        {/* Findings List */}
        <div className="space-y-2 mb-3">
          {findings.length === 0 ? (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/25 rounded-xl text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle size={15} className="shrink-0 text-emerald-400" aria-hidden="true" />
              <span>Valid SSL/TLS certificate chain & recognized public CA authority.</span>
            </div>
          ) : (
            (expandedFindings ? findings : findings.slice(0, 2)).map((f, i) => (
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

        {findings.length > 2 && (
          <button
            type="button"
            onClick={() => setExpandedFindings((o) => !o)}
            className="text-[11px] text-blue-400 hover:text-blue-300 pb-2 flex items-center gap-1 font-medium transition-colors focus-ring rounded"
          >
            {expandedFindings ? "Show less" : `View all (${findings.length}) findings`}
          </button>
        )}
      </div>

      {/* Certificate Trust Chain Toggle */}
      <div className="pt-2.5 border-t border-white/10 mt-2">
        <button
          type="button"
          onClick={() => setShowChain((o) => !o)}
          aria-expanded={showChain}
          className="w-full flex items-center justify-between text-xs text-blue-400 hover:text-blue-300 py-1 transition-colors font-medium focus-ring rounded"
        >
          <span className="flex items-center gap-1.5">
            <Lock size={12} aria-hidden="true" />
            {showChain ? "Hide Certificate Chain" : "Inspect Certificate Hierarchy"}
          </span>
          {showChain ? <ChevronUp size={14} aria-hidden="true" /> : <ChevronDown size={14} aria-hidden="true" />}
        </button>

        {showChain && (
          <div className="space-y-2.5 pt-3 animate-fade-in">
            <p className="text-[10px] text-[var(--tn-text-muted)] font-mono">
              Hierarchy: Leaf Certificate → Intermediate CA → Root Authority
            </p>
            {chain.map((cert, i) => (
              <CertNode key={i} cert={cert} index={i} total={chain.length} />
            ))}
          </div>
        )}
      </div>
    </article>
  );
}
