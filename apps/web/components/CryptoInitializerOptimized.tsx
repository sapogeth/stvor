/**
 * Оптимизированный CryptoInitializer с поддержкой Web Workers
 *
 * АРХИТЕКТУРА:
 * 1. Main Thread: отрисовка UI, обработка пользовательских событий
 * 2. Worker Thread: инициализация PQ, генерация ключей
 * 3. Result: Main Thread остается отзывчивым во время крипто-инициализации
 *
 * УЛУЧШЕНИЯ:
 * - useEffect с пустым массивом зависимостей => инициализация один раз
 * - Динамический импорт в useEffect => избегаем блокировки Main Thread
 * - Web Worker для тяжелых операций => UI не лагает
 * - Ленивая загрузка PQ => быстрое открытие главной страницы
 */

'use client';

import { useEffect, useState } from 'react';

export interface CryptoInitializerOptions {
  /**
   * Инициализировать ли PQ при загрузке (false = ленивая загрузка)
   * @default false
   */
  lazyLoadPQ?: boolean;

  /**
   * Использовать ли Web Worker для инициализации
   * @default true (рекомендуется)
   */
  useWorker?: boolean;

  /**
   * Callback при успешной инициализации
   */
  onReady?: () => void;

  /**
   * Callback при ошибке инициализации
   */
  onError?: (error: Error) => void;
}

export function CryptoInitializerOptimized(options: CryptoInitializerOptions = {}) {
  const {
    lazyLoadPQ = true,
    useWorker = true,
    onReady,
    onError,
  } = options;

  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // CRITICAL: useEffect с пустым массивом зависимостей
  // Гарантирует инициализацию ОДИН раз при монтировании
  useEffect(() => {
    let mounted = true;

    const initializeCrypto = async () => {
      try {
        console.log('[CryptoInitializer] Starting optimization-focused initialization...');

        // ========================================================================
        // ФАЗА 1: Классическая криптография (быстро, Main Thread OK)
        // ========================================================================
        console.log('[CryptoInitializer] Phase 1: Classical crypto (X25519/AES)...');

        // Динамический импорт для избежания bundling проблем
        const { initCryptoOnce } = await import('@/lib/crypto/init');
        await initCryptoOnce();

        if (!mounted) return;

        console.log('[CryptoInitializer] ✓ Phase 1 complete');

        // ========================================================================
        // ФАЗА 2: PQ инициализация (тяжело, выносим в Worker если возможно)
        // ========================================================================

        if (!lazyLoadPQ) {
          // Опционально: инициализируем PQ сразу в Worker
          if (useWorker && typeof Worker !== 'undefined') {
            console.log('[CryptoInitializer] Phase 2: PQ in Worker...');
            const { getCryptoWorkerManager } = await import('@/lib/workers/crypto-worker-manager');
            const manager = getCryptoWorkerManager();
            await manager.initialize();
            console.log('[CryptoInitializer] ✓ Phase 2 (Worker) complete');
          } else {
            // Fallback: инициализируем PQ в Main Thread
            // (не рекомендуется, может вызвать лаги)
            console.log('[CryptoInitializer] Phase 2: PQ in Main Thread (slower)...');
            const { initPQBrowser } = await import('@ilyazh/crypto');
            await initPQBrowser();
            console.log('[CryptoInitializer] ✓ Phase 2 (Main) complete');
          }
        } else {
          // Ленивая загрузка: инициализируем PQ только при необходимости
          console.log('[CryptoInitializer] Phase 2: PQ deferred (lazy load)');
          console.log('[CryptoInitializer] PQ will be initialized when user enters chat');
        }

        if (!mounted) return;

        console.log('[CryptoInitializer] ✓ Crypto initialization complete');
        setReady(true);
        onReady?.();
      } catch (err) {
        if (!mounted) return;

        const message = err instanceof Error ? err.message : String(err);
        console.error('[CryptoInitializer] ✗ Crypto initialization failed:', message);

        setError(message);
        onError?.(err instanceof Error ? err : new Error(message));

        // Не выбрасываем ошибку - приложение может продолжить работу
        // с деградированной функциональностью
      }
    };

    initializeCrypto();

    // Cleanup при размонтировании
    return () => {
      mounted = false;
    };
  }, []); // CRITICAL: пустой массив зависимостей

  // Компонент не отрисовывает UI (только побочные эффекты)
  if (error) {
    console.error('[CryptoInitializer] Error:', error);
    // Не показываем ошибку здесь - пусть error boundary обработает
  }

  return null;
}

/**
 * Экспортируем также старый компонент для обратной совместимости
 */
export const CryptoInitializer = CryptoInitializerOptimized;
