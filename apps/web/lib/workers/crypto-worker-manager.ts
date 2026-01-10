/**
 * Wrapper для Web Worker криптографии
 *
 * Управляет жизненным циклом Worker'а и обеспечивает простой API
 * для Main Thread компонентов в React.
 */

type PendingRequest = {
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
};

const WORKER_TIMEOUT = 60000; // 60 секунд

export class CryptoWorkerManager {
  private worker: Worker | null = null;
  private pendingRequests = new Map<string, PendingRequest>();
  private requestCounter = 0;
  private initPromise: Promise<void> | null = null;

  /**
   * Инициализирует Web Worker
   */
  async initialize(): Promise<void> {
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      try {
        // Динамически импортируем Worker (поддержка Next.js + webpack)
        if (typeof window === 'undefined') {
          throw new Error('Worker can only be used in browser');
        }

        // Используем worker-loader для создания Worker'а
        const WorkerConstructor = await import(
          'worker-loader!./crypto.worker.ts'
        ).then((m) => m.default);

        this.worker = new WorkerConstructor();

        // Обработчик сообщений от Worker'а
        const worker = this.worker!;
        worker.onmessage = (event) => {
          const response = event.data;
          const requestId = Object.keys(this.pendingRequests).find((id) => {
            const pending = this.pendingRequests.get(id);
            return pending !== undefined;
          });

          if (!requestId) {
            console.warn('[CryptoWorker] Received message with no pending request');
            return;
          }

          const pending = this.pendingRequests.get(requestId);
          if (!pending) return;

          clearTimeout(pending.timeout);
          this.pendingRequests.delete(requestId);

          if (response.success) {
            pending.resolve(response.result);
          } else {
            pending.reject(new Error(response.error));
          }
        };

        worker.onerror = (error) => {
          console.error('[CryptoWorker] Worker error:', error);
          // Реинициализируем Worker при ошибке
          this.worker = null;
          this.initPromise = null;
        };

        // Отправляем команду инициализации
        await this.sendRequest({ type: 'initialize' });
        console.log('[CryptoWorker] ✓ Worker initialized');
      } catch (err) {
        console.error('[CryptoWorker] Failed to initialize:', err);
        throw err;
      }
    })();

    return this.initPromise;
  }

  /**
   * Отправляет запрос в Worker и ждет ответа
   */
  private sendRequest(request: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.worker) {
        reject(new Error('Worker not initialized'));
        return;
      }

      const requestId = String(++this.requestCounter);
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error(`Worker request timeout after ${WORKER_TIMEOUT}ms`));
      }, WORKER_TIMEOUT);

      const pending: PendingRequest = { resolve, reject, timeout };
      this.pendingRequests.set(requestId, pending);

      this.worker!.postMessage({ ...request, _id: requestId });
    });
  }

  /**
   * Генерирует долгосрочную пару ключей (Ed25519 + ML-DSA-65)
   */
  async generateIdentity() {
    await this.initialize();
    return this.sendRequest({ type: 'generateIdentity' });
  }

  /**
   * Генерирует ML-KEM ключевую пару
   */
  async generateMLKEMKeyPair() {
    await this.initialize();
    return this.sendRequest({ type: 'generateMLKEMKeyPair' });
  }

  /**
   * Завершает работу Worker'а
   */
  terminate(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
      this.initPromise = null;
      this.pendingRequests.clear();
    }
  }
}

// Глобальный экземпляр для переиспользования
let globalWorkerManager: CryptoWorkerManager | null = null;

/**
 * Получает глобальный экземпляр Worker Manager'а
 */
export function getCryptoWorkerManager(): CryptoWorkerManager {
  if (!globalWorkerManager) {
    globalWorkerManager = new CryptoWorkerManager();
  }
  return globalWorkerManager;
}

/**
 * Очищает глобальный Worker Manager
 */
export function terminateCryptoWorker(): void {
  if (globalWorkerManager) {
    globalWorkerManager.terminate();
    globalWorkerManager = null;
  }
}
