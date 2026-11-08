import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { Verdict } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function verdictColor(verdict: Verdict) {
  return {
    Safe: {
      bg: "bg-green-500/10",
      border: "border-green-500",
      text: "text-green-400",
      ring: "#22c55e",
    },
    Suspicious: {
      bg: "bg-yellow-500/10",
      border: "border-yellow-500",
      text: "text-yellow-400",
      ring: "#eab308",
    },
    Dangerous: {
      bg: "bg-red-500/10",
      border: "border-red-500",
      text: "text-red-400",
      ring: "#ef4444",
    },
  }[verdict];
}

export function severityColor(severity: string) {
  return {
    critical: "bg-red-500/20 text-red-300 border border-red-500/40",
    high: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
    medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
    low: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
  }[severity] ?? "bg-slate-500/20 text-slate-300";
}

export function severityIcon(severity: string): string {
  return (
    { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" }[severity] ?? "⚪"
  );
}

export function moduleLabel(key: string): string {
  return (
    { threat: "Threat Analysis", websec: "Web Security", cert: "Certificate", community: "Community Intel" }[key] ??
    key
  );
}
