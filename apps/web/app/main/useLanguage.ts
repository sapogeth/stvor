/**
 * useLanguage — React hook for language management
 *
 * Features:
 *   - Persists selection in localStorage ('stvor-lang')
 *   - Default language: 'en'
 *   - No page reload on switch
 *   - Returns current i18n strings + setter
 *
 * Usage:
 *   const { lang, setLang, t } = useLanguage();
 */

'use client';

import { useCallback, useEffect, useState } from 'react';
import { i18n, type I18nStrings, type Language } from './i18n';

const STORAGE_KEY = 'stvor-lang';
const DEFAULT_LANG: Language = 'en';

function isValidLanguage(value: string | null): value is Language {
  return value === 'en' || value === 'kz' || value === 'ot';
}

export function useLanguage() {
  const [lang, setLangState] = useState<Language>(DEFAULT_LANG);
  const [hydrated, setHydrated] = useState(false);

  // Hydrate from localStorage on mount (client-only)
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (isValidLanguage(stored)) {
        setLangState(stored);
      }
    } catch {
      // localStorage may be unavailable (SSR, private browsing edge-cases)
    }
    setHydrated(true);
  }, []);

  const setLang = useCallback((newLang: Language) => {
    setLangState(newLang);
    try {
      localStorage.setItem(STORAGE_KEY, newLang);
    } catch {
      // silent fail
    }
  }, []);

  const t: I18nStrings = i18n[lang];

  return { lang, setLang, t, hydrated };
}
