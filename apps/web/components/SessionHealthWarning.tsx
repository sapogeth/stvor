/**
 * Session Health Warning Banner
 * Displays warnings about rekey requirements and session limits
 */

'use client';

import type { SessionHealth } from '@/lib/session-security';

interface SessionHealthWarningProps {
  health: SessionHealth;
  onStartNewSession?: () => void;
}

export function SessionHealthWarning({
  health,
  onStartNewSession,
}: SessionHealthWarningProps) {
  if (health.status === 'healthy') return null;

  const bgColor =
    health.status === 'critical'
      ? 'bg-red-100 dark:bg-red-900/30 border-red-400 dark:border-red-700'
      : 'bg-yellow-100 dark:bg-yellow-900/30 border-yellow-400 dark:border-yellow-700';

  const textColor =
    health.status === 'critical'
      ? 'text-red-800 dark:text-red-200'
      : 'text-yellow-800 dark:text-yellow-200';

  const icon = health.status === 'critical' ? '🛑' : '⚠️';

  return (
    <div className={`${bgColor} border rounded-lg p-4 mb-4`}>
      <div className="flex items-start gap-3">
        <span className="text-2xl">{icon}</span>
        <div className="flex-1">
          <h3 className={`font-semibold ${textColor} mb-2`}>
            {health.status === 'critical' ? 'Session Expired' : 'Session Warning'}
          </h3>
          <ul className={`text-sm ${textColor} space-y-1`}>
            {health.warnings.map((warning, i) => (
              <li key={i}>• {warning}</li>
            ))}
          </ul>
          {health.status === 'critical' && (
            <div className="mt-3">
              <button
                onClick={onStartNewSession}
                className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors text-sm font-medium"
              >
                Start New Session
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
