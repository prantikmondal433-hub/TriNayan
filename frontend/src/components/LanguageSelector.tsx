"use client";

import { useLanguage } from "@/context/LanguageContext";
import { SupportedLang } from "@/lib/i18n";
import { Globe } from "lucide-react";

export function LanguageSelector() {
  const { lang, setLang } = useLanguage();

  const options: { id: SupportedLang; label: string }[] = [
    { id: "en", label: "EN" },
    { id: "hi", label: "हिन्दी" },
    { id: "bn", label: "বাংলা" },
  ];

  return (
    <div className="inline-flex items-center gap-1 bg-slate-900 border border-slate-700/80 rounded-full p-0.5 text-xs">
      <div className="pl-2 pr-1 text-slate-500">
        <Globe size={12} />
      </div>
      {options.map((opt) => (
        <button
          key={opt.id}
          onClick={() => setLang(opt.id)}
          className={`px-2 py-0.5 rounded-full font-medium transition-all ${
            lang === opt.id
              ? "bg-blue-600 text-white shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}
