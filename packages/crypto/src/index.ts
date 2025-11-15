/**
 * Ilyazh-Web3E2E Protocol Implementation
 * Export public API
 */

export * from './constants.js';
export * from './primitives.js';
export * from './handshake.js';
export * from './ratchet.js';
export * from './wire.js';
export * from './skipped-keys.js';
export * from './group-chat.js';

// Version
export const PROTOCOL_VERSION_STRING = '0.9.0-beta';
export const PROTOCOL_NAME = 'Ilyazh-Web3E2E';
export const SUPPORTS_GROUP_CHAT = true;
