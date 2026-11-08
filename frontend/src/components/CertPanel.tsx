// Certificate chain visualizer component
// Shows: Leaf → Intermediate → Root with key details

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

// Simulated cert chain until real data arrives (H16-24)
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
      {/* Connector line */}
      {!isRoot && (
        <div className="absolute left-5 top-full w-0.5 h-4 bg-slate-600 z-10" />
      )}

      <div className={`border rounded-xl overflow-hidden ${isWeak ? "border-red-500/50" : isLeaf ? "border-blue-500/30" : "border-slate-700"}`}>
        <button
          onClick={() => setExpanded((o) => !o)}
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-700/40 transition-colors text-left"
        >
          <div className="flex items-center gap-3">
            <span className="text-sm">{label}</span>
            <span className="text-xs text-slate-400 font-mono truncate max-w-[200px]">
              {cert.subject.replace("CN=", "")}
            </span>
            {isWeak && (
              <span className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded-full">
                Weak key
              </span>
            )}
          </div>
          {expanded ? <ChevronUp size={14} className="text-slate-400 shrink-0" /> : <ChevronDown size={14} className="text-slate-400 shrink-0" />}
        </button>

        {expanded && (
          <div className="px-4 pb-4 border-t border-slate-700 pt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
            <div>
              <span className="text-slate-500">Subject</span>
              <p className="text-slate-200 font-mono mt-0.5 break-all">{cert.subject}</p>
            </div>
            <div>
              <span className="text-slate-500">Issuer</span>
              <p className="text-slate-200 font-mono mt-0.5 break-all">{cert.issuer}</p>
            </div>
            <div>
              <span className="text-slate-500">Valid from</span>
              <p className="text-slate-200 mt-0.5">{cert.valid_from}</p>
            </div>
            <div>
              <span className="text-slate-500">Valid to</span>
              <p className="text-slate-200 mt-0.5">{cert.valid_to}</p>
            </div>
            <div>
              <span className="text-slate-500">Key</span>
              <p className={`mt-0.5 font-semibold ${isWeak ? "text-red-400" : "text-green-400"}`}>
                {cert.key_type}-{cert.key_bits} {isWeak ? "⚠ Too weak" : "✓ OK"}
              </p>
            </div>
            <div>
              <span className="text-slate-500">Self-signed</span>
              <p className="text-slate-200 mt-0.5">{cert.is_self_signed ? "Yes" : "No"}</p>
            </div>
            <div className="col-span-2">
              <span className="text-slate-500">Serial</span>
              <p className="text-slate-400 font-mono mt-0.5 text-xs">{cert.serial}</p>
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
    <div className="bg-slate-800/60 border border-slate-700 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-blue-400" />
          <span className="text-white font-semibold text-sm">Certificate Trust</span>
          {criticalFindings.length > 0 ? (
            <AlertTriangle size={14} className="text-red-400" />
          ) : (
            <CheckCircle size={14} className="text-green-400" />
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="w-24 h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full"
              style={{
                width: `${score}%`,
                backgroundColor: score >= 70 ? "#ef4444" : score >= 40 ? "#eab308" : "#22c55e",
              }}
            />
          </div>
          <span className="text-xs text-slate-400 w-8">{score}</span>
        </div>
      </div>

      {/* Cert findings */}
      {findings.length > 0 && (
        <div className="px-5 py-4 border-b border-slate-700 space-y-2">
          <p className="text-xs text-slate-500 font-medium uppercase tracking-wide mb-3">Issues found</p>
          {findings.map((f) => (
            <div key={f.id} className={`rounded-lg p-3 ${severityColor(f.severity)}`}>
              <div className="flex items-start gap-2">
                <span className="text-sm mt-0.5">{severityIcon(f.severity)}</span>
                <div>
                  <p className="font-semibold text-sm">{f.title}</p>
                  <p className="text-xs opacity-80 mt-0.5 leading-relaxed">{f.detail}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Chain visualizer */}
      <div className="px-5 py-4">
        <button
          onClick={() => setShowChain((o) => !o)}
          className="flex items-center gap-2 text-xs text-slate-400 hover:text-white mb-4 transition-colors"
        >
          {showChain ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          {showChain ? "Hide" : "Show"} certificate chain
        </button>

        {showChain && (
          <div className="space-y-4">
            <p className="text-xs text-slate-500 font-medium uppercase tracking-wide">
              Chain: Leaf → Intermediate → Root
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
