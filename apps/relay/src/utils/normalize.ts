/**
 * Username Normalization Utility (Relay Server)
 *
 * CRITICAL: ALL usernames MUST be normalized before:
 * - Storage (database, memory)
 * - Comparisons
 * - Responses
 *
 * Canonical form: lowercase + trimmed
 * "Alice" → "alice"
 * " Bob " → "bob"
 * "CHARLIE" → "charlie"
 *
 * MUST match client-side normalization exactly!
 */

/**
 * Normalize a username to canonical form
 *
 * @param username - Raw username (any case, may have whitespace)
 * @returns Canonical username (lowercase, trimmed)
 */
export function normalizeUsername(username: string | null | undefined): string {
  if (!username) {
    return '';
  }

  // Apply transformations in order:
  // 1. Convert to string (defensive)
  // 2. Trim whitespace
  // 3. Lowercase
  return String(username).trim().toLowerCase();
}

/**
 * Validate that a username is already in canonical form
 * Used for debugging/assertions
 */
export function isCanonical(username: string): boolean {
  return username === normalizeUsername(username);
}

/**
 * Batch normalize an array of usernames
 * Useful for participant lists
 */
export function normalizeUsernames(usernames: string[]): string[] {
  return usernames.map(normalizeUsername).filter(u => u.length > 0);
}

/**
 * Normalize chatId (deterministic from participants)
 * ChatIds are derived from sorted, normalized usernames
 */
export function normalizeChatId(participants: string[]): string {
  const normalized = normalizeUsernames(participants);
  return normalized.sort().join(':');
}
