'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { SecurityHub } from './components/SecurityHub';
import { KeystoreExplainer } from './components/KeystoreExplainer';
import { RatchetExplainer } from './components/RatchetExplainer';
import { HandshakeExplainer } from './components/HandshakeExplainer';
import { ChatVisualization } from './components/ChatVisualization';
import { ChevronLeft, Home } from 'lucide-react';

type ExplainerType = 'handshake' | 'ratchet' | 'keystore' | 'signatures' | 'relay' | 'group-chat' | null;

export default function SecurityCenterPage() {
  const [activeExplainer, setActiveExplainer] = useState<ExplainerType>(null);
  const [showChatViz, setShowChatViz] = useState(false);
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
    // Optional: Check if user is logged in
    const stored = typeof window !== 'undefined' ? localStorage.getItem('ilyazh_username') : null;
    if (!stored && typeof window !== 'undefined') {
      // Don't redirect, just show message
      console.log('Not authenticated, showing public security center');
    }
  }, []);

  return (
    <main className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      {/* Header */}
      <header className="border-b border-gray-200 dark:border-gray-700 bg-white/80 dark:bg-gray-800/80 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100 transition-colors">
            <Home className="w-5 h-5" />
            <span className="text-sm">На главную</span>
          </Link>

          <h1 className="text-2xl font-bold">🔒 Центр Безопасности</h1>

          <div className="w-20" /> {/* Spacer for centering */}
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Main content */}
        {!activeExplainer && !showChatViz ? (
          <>
            {/* Security Hub */}
            <SecurityHub onSelectComponent={(componentId) => {
              setActiveExplainer(componentId as ExplainerType);
            }} />

            {/* Chat Visualization Section */}
            <div className="mt-16 pt-12 border-t border-gray-200 dark:border-gray-700">
              <div className="space-y-6">
                <div>
                  <h2 className="text-3xl font-bold mb-2">Полная Демонстрация</h2>
                  <p className="text-gray-600 dark:text-gray-400">
                    Посмотри, как все компоненты работают вместе в реальном чате
                  </p>
                </div>

                <button
                  onClick={() => setShowChatViz(true)}
                  className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-lg font-semibold hover:shadow-lg transition-all hover:scale-105"
                >
                  <span className="text-lg">▶</span>
                  Запустить визуализацию чата
                </button>
              </div>
            </div>

            {/* Educational section */}
            <div className="mt-12 grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm border border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-3">📚 Быстрая справка</h3>
                <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
                  <li>• <strong>Hybrid</strong>: Классический + Пост-квантовый ключ обмен</li>
                  <li>• <strong>Forward Secrecy</strong>: Каждое сообщение — новый ключ</li>
                  <li>• <strong>E2E Encryption</strong>: Сервер не видит содержимое</li>
                  <li>• <strong>Mandated Rekey</strong>: Новые ключи каждые 1М сообщений/24ч</li>
                </ul>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm border border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-semibold mb-3">🛡️ Защита от чего?</h3>
                <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
                  <li>✓ Классических компьютеров (нет приватного ключа на сервере)</li>
                  <li>✓ Квантовых компьютеров (ML-KEM-768 стойкий)</li>
                  <li>✓ Перехвата в сети (end-to-end encryption)</li>
                  <li>✓ Компрометации одного сообщения (forward secrecy)</li>
                </ul>
              </div>
            </div>
          </>
        ) : showChatViz ? (
          <div className="space-y-6">
            <button
              onClick={() => setShowChatViz(false)}
              className="flex items-center gap-2 text-blue-600 hover:text-blue-700 font-semibold mb-4"
            >
              <ChevronLeft className="w-4 h-4" />
              Назад к компонентам
            </button>

            <ChatVisualization />
          </div>
        ) : (
          <div className="space-y-6">
            <button
              onClick={() => setActiveExplainer(null)}
              className="flex items-center gap-2 text-blue-600 hover:text-blue-700 font-semibold mb-4"
            >
              <ChevronLeft className="w-4 h-4" />
              Назад к компонентам
            </button>

            {/* Explainers will be rendered as modals below */}
          </div>
        )}

        {/* Explainer modals */}
        {activeExplainer === 'keystore' && <KeystoreExplainer onClose={() => setActiveExplainer(null)} />}
        {activeExplainer === 'ratchet' && <RatchetExplainer onClose={() => setActiveExplainer(null)} />}
        {activeExplainer === 'handshake' && <HandshakeExplainer onClose={() => setActiveExplainer(null)} />}

        {/* Placeholder for other explainers */}
        {activeExplainer && !['keystore', 'ratchet', 'handshake'].includes(activeExplainer) && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg p-8 max-w-2xl w-full">
              <h2 className="text-2xl font-bold mb-4 capitalize">
                {activeExplainer === 'signatures' && '✍️ Двойные Подписи'}
                {activeExplainer === 'relay' && '🚀 Relay Server'}
                {activeExplainer === 'group-chat' && '👥 Групповые Чаты'}
              </h2>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                Детальная визуализация этого компонента еще в разработке. Скоро будет доступна!
              </p>
              <button
                onClick={() => setActiveExplainer(null)}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Закрыть
              </button>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
