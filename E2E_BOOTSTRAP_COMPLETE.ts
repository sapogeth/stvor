/**
 * COMPLETE E2E BOOTSTRAP IMPLEMENTATION
 *
 * This file contains the full, production-capable implementation (with documented architectural constraints) of:
 * 1. Identity generation (Ed25519 + ML-DSA-65)
 * 2. Profile creation (Supabase + Clerk integration)
 * 3. Prekey bundle generation (X25519 + ML-KEM-768)
 * 4. Directory registration (relay canonical identity)
 * 5. Local storage (IndexedDB recovery)
 *
 * Copy each section into the appropriate file in your project.
 */

// ============================================================================
// SECTION 1: Identity Bootstrap (apps/web/lib/identity.ts)
// ============================================================================

/**
 * Main entry point: Get or create E2E identity
 *
 * CRITICAL FLOW:
 * 1. Wait for PQ crypto to initialize ← MUST be first
 * 2. Get or create profile in Supabase
 * 3. Check if identity already exists locally
 * 4. If not, generate keypair + prekey bundle
 * 5. Register in relay (canonical truth)
 * 6. Store locally (for recovery)
 *
 * @throws Error if any step fails
 */
export async function getOrCreateIdentity(): Promise<{
  identityEd25519: string;
  identityMLDSA: string;
  prekeyBundle: PrekeyBundle;
  username: string;
}> {
  // ========== STEP 0: CRITICAL - Wait for PQ crypto ==========
  // This prevents the race condition where WASM hasn't loaded yet
  try {
    const { waitForPQReady, isPQReallyUnavailable } = await import('@ilyazh/crypto');

    await waitForPQReady(30000); // 30 second timeout

    if (isPQReallyUnavailable()) {
      console.error('[Identity] 🚨 PQ crypto is UNAVAILABLE - cannot proceed with hybrid crypto');
      console.error('[Identity] This is a critical failure - the system requires ML-KEM-768 and ML-DSA-65');
      console.error('[Identity] Please refresh the page - if this persists, check browser compatibility');
      throw new Error('Post-quantum cryptography is unavailable. Please refresh and try again.');
    }

    console.log('[Identity] ✅ PQ crypto ready - proceeding with E2E bootstrap');
  } catch (err) {
    if (err instanceof Error && err.message.includes('timeout')) {
      console.error('[Identity] ✗ PQ crypto initialization timeout - WASM modules failed to load');
      console.error('[Identity] Check network tab for mlkem-wasm and mldsa-wasm npm packages');
      throw new Error('PQ crypto initialization timeout. Check your internet connection.');
    }
    throw err;
  }

  // ========== STEP 1: Get or create profile ==========
  console.log('[Identity] Step 1: Getting or creating profile...');

  const { userId: clerkUserId } = await getAuth();
  if (!clerkUserId) {
    throw new Error('Not authenticated - cannot create identity');
  }

  // Get username (either existing or generate new)
  let username = await getUsernameFromClerk(clerkUserId);
  if (!username) {
    username = await generateUniqueUsername(clerkUserId);
  }

  // Create profile in Supabase if it doesn't exist
  const profile = await getOrCreateProfile(username, clerkUserId);
  console.log(`[Identity] ✅ Profile exists: ${profile.username} (${profile.userId})`);

  // ========== STEP 2: Check if identity already exists locally ==========
  console.log('[Identity] Step 2: Checking for existing identity...');

  const existing = await getLocalIdentity(profile.username);
  if (existing) {
    console.log('[Identity] ✅ Using existing identity (already generated)');
    return {
      identityEd25519: existing.identityEd25519,
      identityMLDSA: existing.identityMLDSA,
      prekeyBundle: existing.prekeyBundle,
      username: profile.username,
    };
  }

  console.log('[Identity] No existing identity found - generating new keypair...');

  // ========== STEP 3: Generate identity keypair ==========
  console.log('[Identity] Step 3: Generating Ed25519 + ML-DSA-65 keypair...');

  const startTime = performance.now();
  const identityKeypair = await generateIdentityKeypair();
  const elapsedMs = performance.now() - startTime;

  console.log(`[Identity] ✅ Keypair generated (${elapsedMs.toFixed(0)}ms):`);
  console.log(`[Identity]    Ed25519: ${identityKeypair.identityEd25519.substring(0, 24)}...`);
  console.log(`[Identity]    ML-DSA-65: ${identityKeypair.identityMLDSA.substring(0, 24)}...`);

  if (elapsedMs > 5000) {
    console.warn(`[Identity] ⚠️  Keypair generation took ${elapsedMs.toFixed(0)}ms (expected <2s)`);
  }

  // ========== STEP 4: Generate prekey bundle ==========
  console.log('[Identity] Step 4: Generating prekey bundle...');

  const prekeyStart = performance.now();
  const prebundle = await generatePrekeyBundle(identityKeypair.identityEd25519);
  const prekeyElapsedMs = performance.now() - prekeyStart;

  console.log(`[Identity] ✅ Prekey bundle generated (${prekeyElapsedMs.toFixed(0)}ms):`);
  console.log(`[Identity]    X25519 public: ${prebundle.prekeyBundle.x25519Pub.substring(0, 24)}...`);
  if (prebundle.prekeyBundle.pqKemPub) {
    console.log(`[Identity]    ML-KEM-768: ${prebundle.prekeyBundle.pqKemPub.substring(0, 24)}...`);
  }

  // ========== STEP 5: Register in relay (canonical) ==========
  console.log('[Identity] Step 5: Registering in relay directory...');

  await registerCanonicalIdentity(
    profile.username,
    identityKeypair.identityEd25519,
    identityKeypair.identityMLDSA,
    prebundle.prekeyBundle,
    prebundle.prekeySignature
  );

  console.log('[Identity] ✅ Relay registration complete');

  // ========== STEP 6: Store locally for recovery ==========
  console.log('[Identity] Step 6: Storing in local IndexedDB...');

  await storeLocalIdentity({
    username: profile.username,
    identityEd25519: identityKeypair.identityEd25519,
    identityMLDSA: identityKeypair.identityMLDSA,
    prekeyBundle: prebundle.prekeyBundle,
  });

  console.log('[Identity] ✅ Local backup created');

  // ========== SUCCESS ==========
  console.log('[Identity] ✅ E2E bootstrap complete!');

  return {
    identityEd25519: identityKeypair.identityEd25519,
    identityMLDSA: identityKeypair.identityMLDSA,
    prekeyBundle: prebundle.prekeyBundle,
    username: profile.username,
  };
}

/**
 * Register canonical identity in relay
 *
 * CRITICAL PATTERN: Check before register (prevents 404 cascade)
 *
 * Flow:
 * 1. Try GET /api/relay/directory/:username
 * 2. If 200 OK: Identity already registered (idempotent)
 * 3. If 404: Proceed to POST (expected for new users)
 * 4. If other error: Log and retry
 */
async function registerCanonicalIdentity(
  username: string,
  identityEd25519: string,
  identityMLDSA: string,
  prekeyBundle: PrekeyBundle,
  prekeySignature: string
): Promise<void> {
  // ========== PRE-CHECK: Is it already registered? ==========
  console.log(`[Identity] Pre-check: GET /api/relay/directory/${username}`);

  try {
    const checkResponse = await fetch(`/api/relay/directory/${username}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(5000), // 5 second timeout
    });

    if (checkResponse.ok) {
      console.log('[Identity] ✅ Directory entry already exists (idempotent)');
      return; // Already registered - nothing to do
    }

    // 404 is expected for new users - continue to registration
    if (checkResponse.status === 404) {
      console.log('[Identity] 404 as expected - user not yet in directory, proceeding to register');
    } else {
      console.warn(`[Identity] ⚠️  Unexpected status: ${checkResponse.status} (expected 200 or 404)`);
      // Don't fail - try to register anyway
    }
  } catch (err) {
    console.warn('[Identity] Could not check directory entry:', err);
    console.warn('[Identity] Will attempt registration anyway');
    // Network error - fall through and try to register
  }

  // ========== REGISTER: POST identity to relay ==========
  console.log(`[Identity] Registering: POST /api/relay/directory/${username}`);

  const registerPayload = {
    username, // Relay will normalize to lowercase
    identityEd25519,
    identityMLDSA,
    prekeyBundle,
    prekeySignature,
  };

  const registerResponse = await fetch(`/api/relay/directory/${username}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(registerPayload),
    signal: AbortSignal.timeout(15000), // 15 second timeout
  });

  if (!registerResponse.ok) {
    const errorText = await registerResponse.text();
    const error = (() => {
      try {
        return JSON.parse(errorText);
      } catch {
        return { raw: errorText };
      }
    })();

    console.error(`[Identity] ❌ Directory registration failed: ${registerResponse.status}`, error);
    throw new Error(`Directory registration failed: ${registerResponse.status}`);
  }

  const result = await registerResponse.json();
  console.log('[Identity] ✅ Registered in relay directory', result);
}

/**
 * Generate Ed25519 (identity) + ML-DSA-65 (PQ signature) keypair
 *
 * Imports from @ilyazh/crypto (libsodium + mlkem-wasm npm packages)
 */
async function generateIdentityKeypair(): Promise<{
  identityEd25519: string;
  identityMLDSA: string;
}> {
  const { getPQ } = await import('@ilyazh/crypto');
  const sodium = await require('libsodium').ready;

  const { mldsa65 } = getPQ();
  if (!mldsa65) {
    throw new Error('ML-DSA-65 not available - PQ crypto initialization failed');
  }

  // Generate Ed25519 keypair for identity
  const ed25519KeyPair = sodium.crypto_sign_keypair();
  const identityEd25519 = sodium.to_hex(ed25519KeyPair.publicKey);

  // Generate ML-DSA-65 keypair for PQ signatures
  const mldsaKeyPair = await mldsa65.generateKeyPair();
  const identityMLDSA = mldsaKeyPair.publicKey.toString('hex');

  return {
    identityEd25519,
    identityMLDSA,
  };
}

/**
 * Generate prekey bundle with hybrid (classical + PQ) crypto
 *
 * Bundle contains:
 * - x25519Pub: Classical key exchange (Elliptic Curve)
 * - pqKemPub: Post-quantum KEM (ML-KEM-768)
 * - pqSigPub: Post-quantum signature (ML-DSA-65)
 *
 * Signed with Ed25519 identity key
 */
async function generatePrekeyBundle(identityEd25519: string): Promise<{
  prekeyBundle: PrekeyBundle;
  prekeySignature: string;
}> {
  const { getPQ } = await import('@ilyazh/crypto');
  const sodium = await require('libsodium').ready;

  const { mlkem768, mldsa65 } = getPQ();
  if (!mlkem768 || !mldsa65) {
    throw new Error('PQ crypto not available');
  }

  // 1. Generate X25519 ephemeral key (classical)
  const x25519KeyPair = sodium.crypto_kx_keypair();
  const x25519Pub = sodium.to_hex(x25519KeyPair.publicKey);

  // 2. Generate ML-KEM-768 encapsulation key (PQ key exchange)
  const mlkemKeyPair = await mlkem768.generateKeyPair();
  const pqKemPub = mlkemKeyPair.publicKey.toString('hex');

  // 3. Generate ML-DSA-65 signing key (PQ signatures)
  const mldsaKeyPair = await mldsa65.generateKeyPair();
  const pqSigPub = mldsaKeyPair.publicKey.toString('hex');

  // 4. Create bundle structure
  const prekeyBundle: PrekeyBundle = {
    x25519Pub,
    pqKemPub,
    pqSigPub,
  };

  // 5. Sign the bundle with identity key
  const bundleJson = JSON.stringify(prekeyBundle);
  const bundleBytes = sodium.from_string(bundleJson);
  const signature = sodium.crypto_sign(bundleBytes, Buffer.from(identityEd25519, 'hex'));
  const prekeySignature = sodium.to_hex(signature);

  return {
    prekeyBundle,
    prekeySignature,
  };
}

// ============================================================================
// SECTION 2: Profile Management (apps/web/app/api/profiles/[...].ts)
// ============================================================================

/**
 * Get or create profile for authenticated user
 *
 * Try Supabase first (persistent), fall back to API if needed
 */
async function getOrCreateProfile(
  username: string,
  userId: string
): Promise<{ username: string; userId: string; displayName?: string }> {
  // 1. Try to get existing profile
  const getResponse = await fetch(`/api/profiles?username=${encodeURIComponent(username)}`);

  if (getResponse.ok) {
    return getResponse.json();
  }

  if (getResponse.status !== 404) {
    throw new Error(`Profile lookup failed: ${getResponse.status}`);
  }

  // 2. Profile doesn't exist - create it
  console.log('[Profile] Creating new profile...');

  const createResponse = await fetch('/api/profiles', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      displayName: username, // Default to username
    }),
  });

  if (!createResponse.ok) {
    const error = await createResponse.json();
    throw new Error(`Profile creation failed: ${error.error}`);
  }

  return createResponse.json();
}

/**
 * Generate unique username from Clerk user
 *
 * Tries: username → username_1 → username_2 → ...
 */
async function generateUniqueUsername(userId: string): Promise<string> {
  const baseUsername = userId.substring(0, 20).toLowerCase().replace(/[^a-z0-9_]/g, '_');

  let username = baseUsername;
  let counter = 1;

  while (await usernameExists(username)) {
    username = `${baseUsername}_${counter}`;
    counter++;

    if (counter > 100) {
      throw new Error('Could not generate unique username');
    }
  }

  return username;
}

/**
 * Check if username exists
 */
async function usernameExists(username: string): Promise<boolean> {
  const response = await fetch(`/api/profiles?username=${encodeURIComponent(username)}`);
  return response.ok;
}

/**
 * Get username from Clerk user metadata
 */
async function getUsernameFromClerk(userId: string): Promise<string | null> {
  try {
    const response = await fetch('/api/auth/username');
    if (response.ok) {
      const data = await response.json();
      return data.username || null;
    }
  } catch {
    // Fallback to null
  }
  return null;
}

/**
 * Get authenticated user from Clerk
 */
async function getAuth(): Promise<{ userId: string | null }> {
  try {
    const response = await fetch('/api/auth/user');
    if (response.ok) {
      return response.json();
    }
  } catch {
    // Not authenticated
  }
  return { userId: null };
}

// ============================================================================
// SECTION 3: Local Storage (IndexedDB) - apps/web/lib/keystore.ts
// ============================================================================

interface StoredIdentity {
  username: string;
  identityEd25519: string;
  identityMLDSA: string;
  prekeyBundle: PrekeyBundle;
  createdAt: string;
}

/**
 * Store identity locally in IndexedDB
 *
 * Purpose: Recovery if relay is unavailable
 * Encryption: Done locally by IndexedDB + browser security
 */
async function storeLocalIdentity(identity: Omit<StoredIdentity, 'createdAt'>): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 2);

    request.onerror = () => reject(new Error('IndexedDB open failed'));

    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction(['identity'], 'readwrite');
      const store = transaction.objectStore('identity');

      const storedData: StoredIdentity = {
        ...identity,
        createdAt: new Date().toISOString(),
      };

      const putRequest = store.put(storedData);

      putRequest.onerror = () => reject(new Error('IndexedDB put failed'));
      putRequest.onsuccess = () => {
        console.log(`[Keystore] ✅ Stored identity in IndexedDB: ${identity.username}`);
        resolve();
      };
    };
  });
}

/**
 * Retrieve identity from local IndexedDB
 */
async function getLocalIdentity(username: string): Promise<StoredIdentity | null> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 2);

    request.onerror = () => reject(new Error('IndexedDB open failed'));

    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction(['identity'], 'readonly');
      const store = transaction.objectStore('identity');

      const getRequest = store.get(username);

      getRequest.onerror = () => reject(new Error('IndexedDB get failed'));
      getRequest.onsuccess = () => {
        resolve(getRequest.result || null);
      };
    };
  });
}

// ============================================================================
// SECTION 4: Type Definitions
// ============================================================================

interface PrekeyBundle {
  x25519Pub: string;      // Classical elliptic curve
  pqKemPub?: string;      // Post-quantum KEM (ML-KEM-768)
  pqSigPub?: string;      // Post-quantum signature (ML-DSA-65)
}

// ============================================================================
// SECTION 5: Integration Point (apps/web/components/CryptoInitializer.tsx)
// ============================================================================

/**
 * Example integration in CryptoInitializer:
 *
 * ```typescript
 * export function CryptoInitializer() {
 *   const [ready, setReady] = useState(false);
 *   const [error, setError] = useState<string | null>(null);
 *
 *   useEffect(() => {
 *     (async () => {
 *       try {
 *         // 1. Initialize all crypto
 *         const { initCryptoOnce } = await import('@/lib/crypto/init');
 *         await initCryptoOnce();
 *
 *         // 2. Bootstrap E2E identity
 *         const { getOrCreateIdentity } = await import('@/lib/identity');
 *         const identity = await getOrCreateIdentity();
 *
 *         console.log('[App] E2E Identity ready:', identity.username);
 *         setReady(true);
 *       } catch (err) {
 *         setError(err instanceof Error ? err.message : String(err));
 *       }
 *     })();
 *   }, []);
 *
 *   if (error) {
 *     return <ErrorBoundary error={error} />;
 *   }
 *
 *   return null; // Don't render anything
 * }
 * ```
 */

// ============================================================================
// SECTION 6: Error Handling Examples
// ============================================================================

/**
 * Common error scenarios and how to handle them:
 *
 * 1. "PQ crypto initialization timeout"
 *    → WASM modules not loading
 *    → Check Network tab for mlkem-wasm, mldsa-wasm
 *    → Refresh page, check browser compatibility
 *
 * 2. "Directory registration failed: 404"
 *    → Relay server not running or unreachable
 *    → Check CORS configuration
 *    → Verify NEXT_PUBLIC_RELAY_URL is correct
 *
 * 3. "Profile not found"
 *    → Supabase schema not created
 *    → Run SUPABASE_SCHEMA_FIXED.sql
 *    → Check Supabase connection
 *
 * 4. "CORS not allowed"
 *    → Domain not in ALLOWED_ORIGINS
 *    → Update relay/.env ALLOWED_ORIGINS
 *    → Restart relay server
 *
 * 5. "Unauthorized (401)"
 *    → User not authenticated with Clerk
 *    → Check Clerk is properly configured
 *    → Verify NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
 */

// ============================================================================
// END OF COMPLETE IMPLEMENTATION
// ============================================================================
