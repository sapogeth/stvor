'use client';

import { useEffect, useState } from 'react';

export default function ResetDBPage() {
  const [status, setStatus] = useState('🔄 Сброс базы данных...');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        // Clear localStorage (including migration flag)
        localStorage.clear();
        setStatus('✅ Очистка localStorage...');
        await new Promise(r => setTimeout(r, 500));

        // Delete databases
        const deleteDB = (name: string) => new Promise<void>((resolve) => {
          const req = indexedDB.deleteDatabase(name);
          req.onsuccess = () => resolve();
          req.onerror = () => resolve();
          req.onblocked = () => resolve();
        });

        setStatus('🗑️ Удаление базы ключей...');
        await deleteDB('ilyazh-keystore');
        await deleteDB('ilyazh_keystore');
        await new Promise(r => setTimeout(r, 300));

        setStatus('🗑️ Удаление базы сообщений...');
        await deleteDB('stvor-messages');
        await new Promise(r => setTimeout(r, 300));

        setStatus('✅ База данных полностью очищена! Перенаправление...');
        setLoading(false);

        setTimeout(() => {
          window.location.href = '/';
        }, 1500);
      } catch (err) {
        setStatus(`❌ Ошибка: ${err instanceof Error ? err.message : String(err)}`);
        setLoading(false);
      }
    })();
  }, []);

  return (
    <main className="min-h-screen flex items-center justify-center bg-black text-white p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl shadow-2xl p-8 max-w-md w-full text-center">
        <div className="flex items-center justify-center mb-6">
          <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
            <span className="text-white font-bold text-3xl">S</span>
          </div>
        </div>

        <h1 className="text-3xl font-bold mb-2 tracking-wider">STVOR</h1>
        <h2 className="text-xl font-semibold text-gray-300 mb-6">
          Сброс Базы Данных
        </h2>

        {loading && (
          <div className="mb-6">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-green-500"></div>
          </div>
        )}

        <div className="mb-6 p-4 bg-gray-950 border border-gray-800 rounded-lg">
          <p className="text-lg text-gray-300">{status}</p>
        </div>

        {!loading && (
          <a
            href="/"
            className="inline-block py-3 px-6 bg-green-500 hover:bg-green-600 text-white font-semibold rounded-lg transition-colors"
          >
            Вернуться на главную
          </a>
        )}

        <div className="mt-6 p-4 bg-gray-950 rounded-lg border border-gray-800">
          <p className="text-xs text-gray-400">
            Очищено: localStorage, ключи шифрования, история сообщений
          </p>
        </div>
      </div>
    </main>
  );
}
