/**
 * Relay URL helper
 * Dynamically determines relay server URL based on environment
 *
 * DEPRECATED: Use getRelayBaseUrl() from './config' instead
 * This function is kept for backward compatibility
 */

import { getRelayBaseUrl } from './config';

export function getRelayUrl(): string {
  return getRelayBaseUrl();
}
