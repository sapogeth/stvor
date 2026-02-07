/**
 * LanguageSwitcher — Compact language toggle (EN / KZ / OT)
 *
 * Renders three buttons. Active language is highlighted with emerald accent.
 * No page reload on switch. Designed for dark theme.
 */

'use client';

import { languageLabels, type Language } from './i18n';

const LANGUAGES: Language[] = ['en', 'kz', 'ot'];

interface LanguageSwitcherProps {
  current: Language;
  onChange: (lang: Language) => void;
}

export function LanguageSwitcher({ current, onChange }: LanguageSwitcherProps) {
  return (
    <div className="flex items-center gap-1 rounded-lg bg-white/5 p-1">
      {LANGUAGES.map((lang) => (
        <button
          key={lang}
          onClick={() => onChange(lang)}
          className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all duration-200 ${
            current === lang
              ? 'bg-emerald-500/20 text-emerald-400 shadow-sm'
              : 'text-zinc-500 hover:text-zinc-300 hover:bg-white/5'
          }`}
          aria-label={`Switch to ${lang.toUpperCase()}`}
          aria-current={current === lang ? 'true' : undefined}
        >
          {languageLabels[lang]}
        </button>
      ))}
    </div>
  );
}
