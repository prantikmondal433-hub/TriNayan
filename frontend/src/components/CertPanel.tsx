"use client";

import { Shield, AlertTriangle, CheckCircle, ChevronDown, ChevronUp } from "lucide-react";
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
}

const MOCK_CHAIN: CertInfo[] = [
  {
    subject: "CN=sbi-login-secure-verify.com",
    issuer: "CN=R10, O=Let's Encrypt, C=US",
    valid_from: "2026-11-05",
    valid_to: "2027-02-03",
    key_type: "RSA",
    key_bits: 2048,
    serial: "04:a1:b2:c3:d4:e5",
    is_root: false,
    is_self_signed: false,
  },
  {
    subject: "CN=R10, O=Let's Encrypt, C=US",
    issuer: "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
    valid_from: "2023-03-13",
    valid_to: "2026-03-12",
    key_type: "RSA",
    key_bits: 2048,
    serial: "00:91:2b:08:4a:cf:0c:18:a7:53",
    is_root: false,
    is_self_signed: false,
  },
  {
    subject: "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
    issuer: "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
    valid_from: "2015-06-04",
    valid_to: "2035-06-04",
    key_type: "RSA",
    key_bits: 4096,
    serial: "82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00",
    is_root: true,
    is_self_signed: true,
  },
];

function CertNode({ cert, index, total }: { cert: CertInfo; index: number; total: number }) {
  const [expanded, setExpanded] = useState(index === 0);
  const isLeaf = index === 0;
  const isRoot = index === total - 1;
  const isWeak = cert.key_bits < 2048;

  const label = isLeaf ? "🍃 Leaf Certificate" : isRoot ? "🌳 Root CA" : "🔗 Intermediate CA";

  return (
    <div className="relative">
      {!isRoot && (
        <div className="absolute left-5 top-full w-0.5 h-3 bg-slate-700 z-10" />
      )}

      <div className={`border rounded-xl overflow-hidden bg-slate-900/60 ${isWeak ? "border-red-500/50" : isLeaf ? "border-blue-500/40" : "border-slate-800"}`}>
        <button
          onClick={() => setExpanded((o) => !o)}
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-800/50 transition-colors text-left"
        >
          <div className="flex items-center gap-2.5">
            <span className="text-xs font-semibold text-slate-200">{label}</span>
            <span className="text-xs text-slate-400 font-mono truncate max-w-[220px]">
              {cert.subject.replace("CN=", "")}
            </span>
            {isWeak && (
              <span className="text-[10px] text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded-full">
                Weak key
              </span>
            )}
          </div>
          {expanded ? <ChevronUp size={14} className="text-slate-400 shrink-0" /> : <ChevronDown size={14} className="text-slate-400 shrink-0" />}
        </button>

        {expanded && (
          <div className="px-4 pb-4 border-t border-slate-800 pt-3 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
            <div>
              <span className="text-slate-500 font-medium">Subject</span>
              <p className="text-slate-200 font-mono mt-0.5 break-all">{cert.subject}</p>
            </div>
            <div>
              <span className="text-slate-500 font-medium">Issuer</span>
              <p className="text-slate-200 font-mono mt-0.5 break-all">{cert.issuer}</p>
            </div>
            <div>
              <span className="text-slate-500 font-medium">Valid from</span>
              <p className="text-slate-300 mt-0.5">{cert.valid_from}</p>
            </div>
            <div>
              <span className="text-slate-500 font-medium">Valid to</span>
              <p className="text-slate-300 mt-0.5">{cert.valid_to}</p>
            </div>
            <div>
              <span className="text-slate-500 font-medium">Cryptographic Key</span>
              <p className={`mt-0.5 font-semibold ${isWeak ? "text-red-400" : "text-green-400"}`}>
                {cert.key_type}-{cert.key_bits} {isWeak ? "⚠ Weak (<2048)" : "✓ Strong"}
              </p>
            </div>
            <div>
              <span className="text-slate-500 font-medium">Self-Signed Root</span>
              <p className="text-slate-300 mt-0.5">{cert.is_self_signed ? "Yes" : "No"}</p>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-500 font-medium">Serial Number</span>
              <p className="text-slate-400 font-mono mt-0.5 text-[11px] break-all">{cert.serial}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function CertPanel({ findings, score }: CertPanelProps) {
  const [showChain, setShowChain] = useState(true);
  const criticalFindings = findings.filter((f) => f.severity === "critical" || f.severity === "high");

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      {/* Header */}
      <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Shield size={16} className="text-blue-400" />
          <span className="text-slate-100 font-semibold text-sm">Certificate Trust & Cryptography</span>
          {criticalFindings.length > 0 ? (
            <AlertTriangle size={14} className="text-red-400" />
          ) : (
            <CheckCircle size={14} className="text-green-400" />
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="w-24 h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${Math.min(100, Math.max(0, score))}%`,
                backgroundColor: score >= 70 ? "#ef4444" : score >= 40 ? "#eab308" : "#22c55e",
              }}
            />
          </div>
          <span className="text-xs font-mono text-slate-300 w-8 text-right">{score}</span>
        </div>
      </div>

      {/* Cert findings list */}
      {findings.length > 0 && (
        <div className="px-5 py-3.5 border-b border-slate-800 space-y-2">
          <p className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
            Flagged Certificate Findings
          </p>
          {findings.map((f, i) => (
            <div key={f.id || i} className={`rounded-lg p-3 text-xs ${severityColor(f.severity)}`}>
              <div className="flex items-start gap-2">
                <span className="text-sm shrink-0">{severityIcon(f.severity)}</span>
                <div className="space-y-0.5">
                  <p className="font-semibold text-slate-100">{f.title}</p>
                  {f.detail && (
                    <p className="text-slate-300 opacity-90 leading-relaxed text-[11px]">
                      {f.detail}
                    </p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Chain Visualizer */}
      <div className="px-5 py-4">
        <button
          onClick={() => setShowChain((o) => !o)}
          className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 mb-3 transition-colors font-medium"
        >
          {showChain ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          {showChain ? "Hide" : "Inspect"} Certificate Trust Chain
        </button>

        {showChain && (
          <div className="space-y-3 pt-1">
            <p className="text-[11px] text-slate-500 font-mono">
              Chain Hierarchy: Leaf Certificate → Intermediate CA → Root Authority
            </p>
            {MOCK_CHAIN.map((cert, i) => (
              <CertNode key={i} cert={cert} index={i} total={MOCK_CHAIN.length} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
