/**
 * React Hook для криптографических операций через Web Worker
 *
 * Использует Worker для выполнения тяжелых операций в отдельном потоке,
 * оставляя Main Thread свободным для отрисовки UI.
 *
 * Пример использования:
 * ```tsx
 * function MyComponent() {
 *   const { generateIdentity, loading } = useCryptoWorker();
 *
 *   const handleInit = async () => {
 *     const identity = await generateIdentity();
 *     // ...
 *   };
 *
 *   return (
 *     <button onClick={handleInit} disabled={loading}>
 *       {loading ? 'Initializing...' : 'Initialize Crypto'}
 *     </button>
 *   );
 * }
 * ```
 */

import { useEffect, useState, useCallback } from 'react';
import { getCryptoWorkerManager, terminateCryptoWorker } from './crypto-worker-manager';

export interface UseCryptoWorkerResult {
  generateIdentity: () => Promise<any>;
  generateMLKEMKeyPair: () => Promise<any>;
  loading: boolean;
  error: Error | null;
}

export function useCryptoWorker(): UseCryptoWorkerResult {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  // Инициализируем Worker при монтировании компонента
  useEffect(() => {
    const manager = getCryptoWorkerManager();
    manager
      .initialize()
      .then(() => {
        setLoading(false);
        console.log('[useCryptoWorker] ✓ Worker ready');
      })
      .catch((err) => {
        console.error('[useCryptoWorker] Failed to initialize worker:', err);
        setError(err);
        setLoading(false);
      });

    // Очищаем Worker при размонтировании
    return () => {
      // Не завершаем Worker сразу, так как он может переиспользоваться
      // terminateCryptoWorker();
    };
  }, []);

  const generateIdentity = useCallback(async () => {
    const manager = getCryptoWorkerManager();
    try {
      setLoading(true);
      const result = await manager.generateIdentity();
      setLoading(false);
      return result;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      setLoading(false);
      throw error;
    }
  }, []);

  const generateMLKEMKeyPair = useCallback(async () => {
    const manager = getCryptoWorkerManager();
    try {
      setLoading(true);
      const result = await manager.generateMLKEMKeyPair();
      setLoading(false);
      return result;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      setLoading(false);
      throw error;
    }
  }, []);

  return {
    generateIdentity,
    generateMLKEMKeyPair,
    loading,
    error,
  };
}
