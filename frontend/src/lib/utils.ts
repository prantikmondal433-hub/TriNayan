import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { Verdict, Reason } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function verdictColor(verdict: Verdict) {
  return (
    {
      Safe: {
        bg: "bg-[var(--tn-safe-bg)]",
        border: "border-[var(--tn-safe-border)]",
        text: "text-emerald-400",
        ring: "#10B981",
        chip: "bg-[var(--tn-safe)] text-white",
      },
      Suspicious: {
        bg: "bg-[var(--tn-warning-bg)]",
        border: "border-[var(--tn-warning-border)]",
        text: "text-amber-400",
        ring: "#F59E0B",
        chip: "bg-[var(--tn-warning)] text-slate-950 font-bold",
      },
      Dangerous: {
        bg: "bg-[var(--tn-danger-bg)]",
        border: "border-[var(--tn-danger-border)]",
        text: "text-red-400",
        ring: "#EF4444",
        chip: "bg-[var(--tn-danger)] text-white",
      },
    }[verdict] || {
      bg: "bg-slate-800/40",
      border: "border-[var(--tn-border)]",
      text: "text-[var(--tn-text-secondary)]",
      ring: "#64748B",
      chip: "bg-slate-700 text-white",
    }
  );
}

export function severityColor(severity: string) {
  return (
    {
      critical: "bg-red-500/15 text-red-300 border border-red-500/40",
      high: "bg-orange-500/15 text-orange-300 border border-orange-500/40",
      medium: "bg-amber-500/15 text-amber-300 border border-amber-500/40",
      low: "bg-blue-500/15 text-blue-300 border border-blue-500/40",
    }[severity] ?? "bg-slate-800/50 text-slate-300 border border-slate-700/50"
  );
}

export function severityIcon(severity: string): string {
  return (
    { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" }[severity] ?? "⚪"
  );
}

export function moduleLabel(key: string): string {
  return (
    {
      threat: "Threat & Lexical Analysis",
      websec: "Security Headers & Cookies",
      cert: "Certificate Trust",
      community: "Community Threat Intel",
    }[key] ?? key
  );
}

export function getReasonTitle(r: string | Reason): string {
  if (typeof r === "string") return r;
  return r.title || String(r);
}
