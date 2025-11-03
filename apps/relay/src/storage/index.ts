/**
 * Storage Factory
 * Creates the appropriate storage adapter based on configuration
 */

import type { IStorageAdapter } from './interfaces.js';
import { MemoryStorageAdapter } from './memory-adapter.js';
import { PostgresStorageAdapter } from './postgres-adapter.js';

export * from './interfaces.js';

export type StorageType = 'memory' | 'postgres';

export interface StorageConfig {
  type: StorageType;
  connectionString?: string; // For postgres
}

export async function createStorageAdapter(config: StorageConfig): Promise<IStorageAdapter> {
  let adapter: IStorageAdapter;

  switch (config.type) {
    case 'memory':
      console.log('[Storage] Using in-memory storage (NOT for production)');
      adapter = new MemoryStorageAdapter();
      break;

    case 'postgres':
      if (!config.connectionString) {
        throw new Error('PostgreSQL connection string required');
      }
      console.log('[Storage] Using PostgreSQL storage');
      adapter = new PostgresStorageAdapter(config.connectionString);
      break;

    default:
      throw new Error(`Unknown storage type: ${(config as any).type}`);
  }

  await adapter.init();
  return adapter;
}
