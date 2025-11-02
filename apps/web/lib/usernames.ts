/**
 * Username Normalization
 *
 * Handles canonicalization of usernames for relay lookups.
 * Ensures "Izahii", "izahii", "IZAHII", "Izahii (you)" all map to same identity.
 */

/**
 * Normalize username to canonical form
 *
 * Rules:
 * 1. Trim whitespace
 * 2. Convert to lowercase
 * 3. Strip display decorations (e.g., " (you)")
 *
 * @param raw - Raw username from UI or message
 * @returns Canonical username for relay lookups
 *
 * @example
 * normalizeUsername("Izahii") → "izahii"
 * normalizeUsername("Alice (you)") → "alice"
 * normalizeUsername("  Bob  ") → "bob"
 */
export function normalizeUsername(raw: string): string {
  if (!raw) return raw;

  // 1. Trim whitespace
  let normalized = raw.trim();

  // 2. Convert to lowercase (relay directory is case-insensitive)
  normalized = normalized.toLowerCase();

  // 3. Strip display decorations
  // Remove " (you)" suffix
  normalized = normalized.replace(/\s*\(you\)\s*$/i, '');

  // Remove other common decorations
  normalized = normalized.replace(/\s*\(.*?\)\s*$/g, '');

  return normalized;
}

/**
 * Check if two usernames are equivalent (after normalization)
 *
 * @param username1 - First username
 * @param username2 - Second username
 * @returns True if usernames are equivalent
 */
export function usernamesEqual(username1: string, username2: string): boolean {
  return normalizeUsername(username1) === normalizeUsername(username2);
}
