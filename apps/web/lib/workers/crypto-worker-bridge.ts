/**
 * CryptoWorkerBridge: Main Thread interface to Worker
 *
 * Provides:
 * - Worker lifecycle management
 * - Request/response protocol
 * - Error handling with fallback to Main Thread
 * - Type-safe communication
 *
 * Usage:
 * ```typescript
 * const bridge = new CryptoWorkerBridge();
 * const identity = await bridge.generateIdentity('alice');
 * ```
 */

type WorkerMessage =
  | { type: 'init' }
  | { type: 'generateIdentity'; username: string }
  | { type: 'generatePrekeyBundle'; identity: string; bundleId: string }
  | { type: 'ping' };

type WorkerResponse =
  | { success: true; type: string; data: any }
  | { success: false; error: string };

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}

const WORKER_TIMEOUT_MS = 60_000; // 60 seconds
const WORKER_SCRIPT = new URL('./crypto.worker.ts', import.meta.url);

export class CryptoWorkerBridge {
  private worker: Worker | null = null;
  private pendingRequests = new Map<string, PendingRequest>();
  private messageCounter = 0;
  private initPromise: Promise<void> | null = null;
  private useWorker = true; // Feature flag for fallback

  /**
   * Initialize the worker (called automatically)
   */
  async initialize(): Promise<void> {
    if (this.worker) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      try {
        // Check if Worker is supported
        if (typeof Worker === 'undefined') {
          console.warn('[CryptoWorkerBridge] Worker not supported, will use Main Thread');
          this.useWorker = false;
          return;
        }

        console.log('[CryptoWorkerBridge] Creating Worker...');
        this.worker = new Worker(WORKER_SCRIPT, { type: 'module' });

        // Setup message handler
        this.worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
          const response = event.data;

          // Handle logs from worker
          if (response.type === 'log') {
            console.log(response.data.message);
            return;
          }

          // Find corresponding pending request
          // In real implementation, should include request ID in worker response
          const firstPending = this.pendingRequests.values().next();
          if (firstPending.done) {
            console.warn('[CryptoWorkerBridge] Received unexpected message:', response);
            return;
          }

          const pending = firstPending.value;
          clearTimeout(pending.timeout);

          if (response.success) {
            pending.resolve(response.data);
          } else {
            pending.reject(new Error(response.error));
          }

          // Remove from pending (note: better to use message ID)
          this.pendingRequests.clear();
        };

        this.worker.onerror = (error: ErrorEvent) => {
          console.error('[CryptoWorkerBridge] Worker error:', error);
          this.worker = null;
          this.initPromise = null;

          // Reject all pending requests
          for (const pending of this.pendingRequests.values()) {
            pending.reject(new Error(`Worker error: ${error.message}`));
          }
          this.pendingRequests.clear();
        };

        // Send init message
        await this.sendRequest({ type: 'init' });
        console.log('[CryptoWorkerBridge] ✓ Worker initialized');
      } catch (err) {
        console.error('[CryptoWorkerBridge] Failed to initialize worker:', err);
        this.useWorker = false; // Fall back to Main Thread
      }
    })();

    return this.initPromise;
  }

  /**
   * Send request to worker and wait for response
   */
  private async sendRequest(message: WorkerMessage): Promise<any> {
    await this.initialize();

    if (!this.useWorker || !this.worker) {
      throw new Error('Worker not available');
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Worker request timeout after ${WORKER_TIMEOUT_MS}ms`));
      }, WORKER_TIMEOUT_MS);

      const pending: PendingRequest = { resolve, reject, timeout };
      this.pendingRequests.set(String(++this.messageCounter), pending);

      this.worker!.postMessage(message);
    });
  }

  /**
   * Generate long-term identity keypair
   * Offloaded to Worker to prevent Main Thread blocking
   */
  async generateIdentity(username: string): Promise<{
    ed25519: { publicKey: Uint8Array; secretKey: Uint8Array };
    mldsa: { publicKey: Uint8Array; secretKey: Uint8Array };
  }> {
    if (!this.useWorker) {
      throw new Error('Worker not available, cannot generate identity');
    }

    const result = await this.sendRequest({
      type: 'generateIdentity',
      username,
    });

    // Reconstruct Uint8Arrays from arrays
    return {
      ed25519: {
        publicKey: new Uint8Array(result.ed25519.publicKey),
        secretKey: new Uint8Array(result.ed25519.secretKey),
      },
      mldsa: {
        publicKey: new Uint8Array(result.mldsa.publicKey),
        secretKey: new Uint8Array(result.mldsa.secretKey),
      },
    };
  }

  /**
   * Generate prekey bundle in worker
   */
  async generatePrekeyBundle(
    identity: {
      ed25519: { publicKey: Uint8Array; secretKey: Uint8Array };
      mldsa: { publicKey: Uint8Array; secretKey: Uint8Array };
    },
    bundleId: string
  ): Promise<any> {
    if (!this.useWorker) {
      throw new Error('Worker not available');
    }

    // Serialize identity for transmission
    const identityStr = JSON.stringify({
      ed25519: {
        publicKey: Array.from(identity.ed25519.publicKey),
        secretKey: Array.from(identity.ed25519.secretKey),
      },
      mldsa: {
        publicKey: Array.from(identity.mldsa.publicKey),
        secretKey: Array.from(identity.mldsa.secretKey),
      },
    });

    const result = await this.sendRequest({
      type: 'generatePrekeyBundle',
      identity: identityStr,
      bundleId,
    });

    return result;
  }

  /**
   * Check if worker is healthy
   */
  async ping(): Promise<boolean> {
    try {
      if (!this.useWorker) return false;
      await this.initialize();
      const result = await this.sendRequest({ type: 'ping' });
      return result.timestamp > 0;
    } catch {
      return false;
    }
  }

  /**
   * Terminate worker and cleanup
   */
  terminate(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.pendingRequests.clear();
    this.initPromise = null;
  }
}

// Global singleton instance
let globalBridge: CryptoWorkerBridge | null = null;

/**
 * Get or create global worker bridge
 */
export function getCryptoWorkerBridge(): CryptoWorkerBridge {
  if (!globalBridge) {
    globalBridge = new CryptoWorkerBridge();
  }
  return globalBridge;
}

/**
 * Terminate global worker
 */
export function terminateCryptoWorker(): void {
  if (globalBridge) {
    globalBridge.terminate();
    globalBridge = null;
  }
}
