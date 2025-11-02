/**
 * Browser stub for @openforge-sh/liboqs
 *
 * This stub prevents webpack from trying to bundle the Node.js-specific
 * liboqs library for the browser. The actual PQ crypto will be loaded
 * dynamically on demand via dynamic imports.
 *
 * This allows the root page to compile without errors while keeping
 * the E2E encryption functionality intact.
 */

export function isSupported() {
  return false;
}

export async function init() {
  return false;
}

// Stub exports for common liboqs APIs
export const Kem = {};
export const Sig = {};

export default {
  isSupported,
  init,
  Kem,
  Sig,
};
