"use client";

import { useLanguage } from "@/context/LanguageContext";
import { SupportedLang } from "@/lib/i18n";

export function LanguageSelector() {
  const { lang, setLang } = useLanguage();

  const options: { id: SupportedLang; label: string; ariaLabel: string }[] = [
    { id: "en", label: "EN", ariaLabel: "Switch language to English" },
    { id: "hi", label: "हिन्दी", ariaLabel: "Switch language to Hindi" },
    { id: "bn", label: "বাংলা", ariaLabel: "Switch language to Bengali" },
  ];

  return (
    <nav aria-label="Language selection" className="inline-flex items-center gap-1 text-xs">
      {options.map((opt) => {
        const isActive = lang === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            onClick={() => setLang(opt.id)}
            aria-pressed={isActive}
            aria-label={opt.ariaLabel}
            className={`px-2 py-0.5 rounded-full text-xs font-semibold transition-all focus-ring ${
              isActive
                ? "text-[var(--tn-text)] bg-white/15 border border-white/40 shadow-sm"
                : "text-[var(--tn-text-secondary)] hover:text-white hover:bg-white/5 border border-transparent"
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </nav>
  );
}
