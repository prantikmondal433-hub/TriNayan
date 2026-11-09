"use client";

import React, { createContext, useContext, useState, useEffect } from "react";
import { SupportedLang, TRANSLATIONS, TranslationKey } from "@/lib/i18n";
import { Verdict } from "@/lib/types";

interface LanguageContextType {
  lang: SupportedLang;
  setLang: (lang: SupportedLang) => void;
  t: (key: TranslationKey) => string;
  tVerdict: (v: Verdict) => string;
}

const LanguageContext = createContext<LanguageContextType>({
  lang: "en",
  setLang: () => {},
  t: (k) => TRANSLATIONS.en[k] || k,
  tVerdict: (v) => v,
});

const LANG_STORAGE_KEY = "trinayan_user_lang";

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<SupportedLang>("en");

  useEffect(() => {
    try {
      const stored = localStorage.getItem(LANG_STORAGE_KEY) as SupportedLang;
      if (stored && (stored === "en" || stored === "hi" || stored === "bn")) {
        queueMicrotask(() => setLangState(stored));
      }
    } catch {
      // Ignore localStorage issues
    }
  }, []);

  function setLang(newLang: SupportedLang) {
    setLangState(newLang);
    try {
      localStorage.setItem(LANG_STORAGE_KEY, newLang);
    } catch {
      // Ignore
    }
  }

  function t(key: TranslationKey): string {
    const dict = (TRANSLATIONS[lang] || TRANSLATIONS.en) as Record<TranslationKey, string>;
    return dict[key] || TRANSLATIONS.en[key] || key;
  }

  function tVerdict(verdict: Verdict): string {
    if (verdict === "Safe") return t("verdictSafe");
    if (verdict === "Suspicious") return t("verdictSuspicious");
    if (verdict === "Dangerous") return t("verdictDangerous");
    return verdict;
  }

  return (
    <LanguageContext.Provider value={{ lang, setLang, t, tVerdict }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  return useContext(LanguageContext);
}
