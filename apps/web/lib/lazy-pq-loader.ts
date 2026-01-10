/**
 * Ленивая загрузка WASM-модулей для PQ-криптографии
 *
 * Вместо загрузки всех PQ-модулей при старте приложения,
 * загружаем их только когда пользователь действительно начинает чат.
 *
 * Стратегия:
 * 1. При открытии главной страницы: НЕ инициализируем PQ
 * 2. При входе в чат: инициализируем PQ (отдельный поток)
 * 3. При выходе из чата: кэшируем PQ (не перезагружаем каждый раз)
 */

type PQInitState = 'not-loaded' | 'loading' | 'ready' | 'error';

class LazyPQLoader {
  private state: PQInitState = 'not-loaded';
  private loadPromise: Promise<void> | null = null;
  private error: Error | null = null;

  /**
   * Инициализирует PQ-модули ленивым образом
   * Гарантирует, что инициализация происходит только один раз
   */
  async ensurePQReady(): Promise<void> {
    // Если уже готов, возвращаем сразу
    if (this.state === 'ready') {
      return;
    }

    // Если идет загрузка, ждем завершения
    if (this.state === 'loading') {
      return this.loadPromise!;
    }

    // Если была ошибка, можно попробовать еще раз
    if (this.state === 'error') {
      console.log('[LazyPQLoader] Retrying PQ initialization after previous error');
      this.state = 'loading';
      this.loadPromise = this.initializePQ();
      return this.loadPromise;
    }

    // Инициализируем в первый раз
    this.state = 'loading';
    this.loadPromise = this.initializePQ();
    return this.loadPromise;
  }

  /**
   * Выполняет реальную инициализацию PQ
   * Это тяжелая операция, выполняется в Web Worker если возможно
   */
  private async initializePQ(): Promise<void> {
    try {
      console.log('[LazyPQLoader] Starting PQ initialization...');
      const startTime = performance.now();

      // Динамически импортируем модуль крипто
      const crypto = await import('@ilyazh/crypto');

      // Инициализируем PQ в браузере (WASM загружается и компилируется)
      // Это самая медленная операция, поэтому она находится в отдельном потоке
      await crypto.initPQBrowser();

      const duration = performance.now() - startTime;
      console.log(`[LazyPQLoader] ✓ PQ ready in ${duration.toFixed(0)}ms`);

      this.state = 'ready';
    } catch (err) {
      this.state = 'error';
      this.error = err instanceof Error ? err : new Error(String(err));
      console.error('[LazyPQLoader] ✗ PQ initialization failed:', this.error);
      throw this.error;
    }
  }

  /**
   * Возвращает текущее состояние
   */
  getState(): PQInitState {
    return this.state;
  }

  /**
   * Возвращает ошибку инициализации (если есть)
   */
  getError(): Error | null {
    return this.error;
  }

  /**
   * Проверяет готовность PQ без ожидания
   */
  isReady(): boolean {
    return this.state === 'ready';
  }
}

// Глобальный экземпляр
const globalPQLoader = new LazyPQLoader();

/**
 * Возвращает глобальный загрузчик PQ
 */
export function getPQLoader(): LazyPQLoader {
  return globalPQLoader;
}

/**
 * Убеждается, что PQ готов к использованию
 * Вызывать перед использованием PQ-операций (handshake, key generation)
 */
export async function ensurePQReady(): Promise<void> {
  return getPQLoader().ensurePQReady();
}

/**
 * React Hook для проверки и инициализации PQ с прогресс-индикатором
 */
export function useLazyPQ() {
  const [state, setState] = useState<PQInitState>('not-loaded');
  const [error, setError] = useState<Error | null>(null);

  const initialize = async () => {
    try {
      setState('loading');
      await ensurePQReady();
      setState('ready');
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      setState('error');
      throw error;
    }
  };

  return { state, error, initialize };
}
